#!/usr/bin/env python3

import sys
import time
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
import scapy.config

scapy.config.conf.verb = 0

from data import WiFiNet, ClientDevice


class WiFiScanner:
    def __init__(self, debug=False):
        self.networks = {}
        self.clients = defaultdict(list)

        self.scanning = False
        self.deep_scanning = False

        self.interface = ""
        self.lock = threading.Lock()

        self.channels_2ghz = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
        self.channels_5ghz = [36, 40, 44, 48, 149, 153, 157, 161]
        self.channels = self.channels_2ghz

        self.channel_idx = 0
        self.current_channel = 1
        self.debug = debug

        self.focus_bssid = None
        self.processed_packets = 0
        self.matched_packets = 0
        self.target_bssid: Optional[str] = None


    # ------------- LOG -------------

    def log(self, msg):
        if self.debug:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {msg}", file=sys.stderr)

    # ------------- INTERFEJS / TRYBY -------------

    def get_interfaces(self):
        out = []
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    parts = line.split()
                    iface = parts[-1]
                    out.append(iface)
        except Exception as e:
            self.log(f"get_interfaces error: {e}")
        return out

    def set_monitor_mode(self, iface: str) -> bool:
        """
        Przełącza wybrany interfejs w tryb monitor i odczepia go od NetworkManagera.
        Nie dotyka innych kart (np. wlp1s0 z internetem).
        """
        try:
            # Najpierw odpinam ten interfejs od NetworkManagera,
            # żeby nie próbował go konfigurować jako zwykłe Wi-Fi.
            subprocess.run(
                ["nmcli", "dev", "disconnect", iface],
                capture_output=True,
                text=True,
                timeout=3,
            )
            subprocess.run(
                ["nmcli", "dev", "set", iface, "managed", "no"],
                capture_output=True,
                text=True,
                timeout=3,
            )

            cmds = [
                ["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "monitor"],
                ["ip", "link", "set", iface, "up"],
            ]

            for cmd in cmds:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    self.log(
                        f"Command failed: {' '.join(cmd)} "
                        f"rc={result.returncode}, err={result.stderr.strip()}"
                    )
                    return False

            time.sleep(1)
            self.log(f"Monitor mode set on {iface}")
            self.interface = iface
            return True

        except Exception as e:
            self.log(f"set_monitor_mode error: {e}")
            return False


    def restore_managed_mode(self, iface: str):
        """
        Przywraca interfejs do normalnego trybu Wi-Fi i oddaje go z powrotem NetworkManagerowi.
        """
        try:
            cmds = [
                ["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "managed"],
                ["ip", "link", "set", iface, "up"],
            ]

            for cmd in cmds:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

            # z powrotem pozwalamy NetworkManagerowi zarządzać tym interfejsem
            subprocess.run(
                ["nmcli", "dev", "set", iface, "managed", "yes"],
                capture_output=True,
                text=True,
                timeout=3,
            )

            self.log(f"Managed mode restored on {iface}")

        except Exception as e:
            self.log(f"restore_managed_mode error: {e}")


    # ------------- KANAŁY -------------

    def set_channel(self, iface: str, channel: int) -> bool:
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                self.current_channel = channel
                return True
            else:
                self.log(f"set_channel({channel}) failed: {result.stderr.strip()}")
                return False
        except Exception as e:
            self.log(f"set_channel error: {e}")
            return False

    def channel_hopper(self, iface: str):
        """
        Hopowanie po kanałach w fazie skanowania.
        Robione wolniej i z limitem błędów, żeby nie zajechać sterownika.
        """
        self.log(f"Channel hopper started on {iface}")
        error_streak = 0

        while self.scanning:
            try:
                if not self.channels:
                    time.sleep(0.5)
                    continue

                ch = self.channels[self.channel_idx]
                ok = self.set_channel(iface, ch)
                if not ok:
                    error_streak += 1
                    if error_streak >= 5:
                        self.log("Too many channel set errors, stopping hopper")
                        break
                else:
                    error_streak = 0

                self.channel_idx = (self.channel_idx + 1) % len(self.channels)
                time.sleep(0.7)      # było 0.15, za szybko dla sterownika
            except Exception as e:
                self.log(f"channel_hopper error: {e}")
                break

        self.log("Channel hopper stopped")


    # ------------- POMOCNICZE WYCIĄGANIE INFO -------------

    def extract_ssid(self, pkt):
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0 and elt.info:
                        ssid = elt.info.decode("utf-8", errors="ignore").strip()
                        if ssid:
                            return ssid
                    elt = elt.payload.getlayer(Dot11Elt)
        except Exception as e:
            self.log(f"extract_ssid error: {e}")
        return "<Hidden>"

    def extract_channel(self, pkt):
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3 and elt.info:
                        ch = elt.info[0] if isinstance(elt.info, bytes) else elt.info
                        return int(ch)
                    elt = elt.payload.getlayer(Dot11Elt)
        except Exception as e:
            self.log(f"extract_channel error: {e}")
        return 1

    def extract_rssi(self, pkt):
        try:
            if pkt.haslayer(RadioTap):
                rt = pkt[RadioTap]
                if hasattr(rt, "dBm_AntSignal"):
                    return int(rt.dBm_AntSignal)
        except Exception as e:
            self.log(f"extract_rssi error: {e}")
        return -100

    # ------------- FILTR FOCUS_AP -------------

    def _belongs_to_focus(self, dot11):
        if self.focus_bssid is None:
            return True

        addrs = {dot11.addr1, dot11.addr2, dot11.addr3}
        return self.focus_bssid in addrs

    # ------------- AP (BEACON / PROBE RESP) -------------

    def parse_beacon(self, pkt):
        try:
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                return

            dot11 = pkt[Dot11]

            if pkt.haslayer(Dot11ProbeResp):
                bssid = dot11.addr3 or dot11.addr2
            else:
                bssid = dot11.addr2

            if not bssid or bssid.lower() == "ff:ff:ff:ff:ff:ff":
                return

            ssid = self.extract_ssid(pkt)
            channel = self.extract_channel(pkt)
            rssi = self.extract_rssi(pkt)

            if 1 <= channel <= 13:
                freq = 2412 + (channel - 1) * 5
            elif 36 <= channel <= 177:
                freq = 5000 + channel * 5
            else:
                freq = 0

            now = datetime.utcnow().isoformat() + "Z"

            with self.lock:
                if bssid not in self.networks:
                    net = WiFiNet(
                        index=len(self.networks) + 1,
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        frequency_mhz=freq,
                        signal_dbm=rssi,
                        beacon_interval_tu=100,
                        akm=["Unknown"],
                        cipher="Unknown",
                        rsn_pmf="unknown",
                        station_count=0,
                        capabilities=["ESS"],
                        first_seen=now,
                        last_seen=now,
                        vendor="Unknown",
                    )
                    self.networks[bssid] = net
                    self.log(f"AP found: {ssid} {bssid} CH{channel} RSSI={rssi}")
                else:
                    net = self.networks[bssid]
                    net.signal_dbm = rssi
                    net.last_seen = now

        except Exception as e:
            self.log(f"parse_beacon error: {e}")

    # ------------- KLIENCI Z DANYCH -------------

    def parse_data_frame(self, pkt):
        try:
            if not pkt.haslayer(Dot11):
                return

            dot11 = pkt[Dot11]

            if not self._belongs_to_focus(dot11):
                return

            if dot11.type != 2:
                return

            fc = dot11.FCfield
            to_ds = bool(fc & 0x01)
            from_ds = bool(fc & 0x02)

            addr1 = dot11.addr1
            addr2 = dot11.addr2

            rssi = self.extract_rssi(pkt)
            now = datetime.utcnow().isoformat() + "Z"

            # client -> AP
            if to_ds and not from_ds:
                ap = addr1
                client = addr2
                if ap in self.networks and client and client != "ff:ff:ff:ff:ff:ff":
                    self._add_client(client, ap, rssi, now)
                    self.matched_packets += 1

            # AP -> client
            elif not to_ds and from_ds:
                ap = addr2
                client = addr1
                if ap in self.networks and client and client != "ff:ff:ff:ff:ff:ff":
                    self._add_client(client, ap, rssi, now)
                    self.matched_packets += 1

        except Exception as e:
            self.log(f"parse_data_frame error: {e}")

    # ------------- KLIENCI Z MGMT -------------

    def parse_mgmt_frame(self, pkt):
        try:
            if not pkt.haslayer(Dot11):
                return

            dot11 = pkt[Dot11]

            if not self._belongs_to_focus(dot11):
                return

            if dot11.type != 0:
                return

            if dot11.subtype in [0, 2, 11]:
                client = dot11.addr2
                ap = dot11.addr1
                rssi = self.extract_rssi(pkt)
                now = datetime.utcnow().isoformat() + "Z"

                if ap in self.networks and client and client != "ff:ff:ff:ff:ff:ff":
                    self._add_client(client, ap, rssi, now)
                    self.matched_packets += 1

        except Exception as e:
            self.log(f"parse_mgmt_frame error: {e}")

    # ------------- DODAWANIE KLIENTA -------------

    def _add_client(self, client_mac, ap_bssid, rssi, timestamp):
        try:
            with self.lock:
                for client in self.clients[ap_bssid]:
                    if client.mac == client_mac:
                        client.signal_dbm = rssi
                        client.last_seen = timestamp
                        return

                new_client = ClientDevice(
                    mac=client_mac,
                    ap_bssid=ap_bssid,
                    signal_dbm=rssi,
                    last_seen=timestamp,
                    vendor="Unknown",
                )
                self.clients[ap_bssid].append(new_client)

                if ap_bssid in self.networks:
                    self.networks[ap_bssid].station_count = len(
                        self.clients[ap_bssid]
                    )

                self.log(f"Client found: {client_mac} -> {ap_bssid}")
        except Exception as e:
            self.log(f"_add_client error: {e}")

    # ------------- HANDLERY DO SNIFFA -------------

    def packet_handler_ap_discovery(self, pkt):
        try:
            if not pkt.haslayer(Dot11):
                return
            self.parse_beacon(pkt)
        except Exception as e:
            self.log(f"packet_handler_ap_discovery error: {e}")

    def packet_handler_deep_scan(self, pkt):
        try:
            if not pkt.haslayer(Dot11):
                return

            self.processed_packets += 1

            self.parse_beacon(pkt)
            self.parse_data_frame(pkt)
            self.parse_mgmt_frame(pkt)

            if self.debug and self.processed_packets % 200 == 0:
                self.log(
                    f"[DEEP] processed={self.processed_packets}, "
                    f"matched={self.matched_packets}, "
                    f"focus_bssid={self.focus_bssid}"
                )

        except Exception as e:
            self.log(f"packet_handler_deep_scan error: {e}")

    # ------------- START / STOP -------------

    def start_ap_discovery(self, iface: str):
        """
        Faza 1: skanowanie AP po wszystkich kanałach.
        Najpierw próbujemy ustawić pierwszy kanał.
        Jeśli to się nie uda, nie odpalamy hoppera ani sniffera.
        """
        self.interface = iface
        self.scanning = True
        self.deep_scanning = False
        self.focus_bssid = None
        self.target_bssid = None

        # szybki test: spróbuj ustawić pierwszy kanał z listy
        if self.channels:
            first_ch = self.channels[0]
            if not self.set_channel(iface, first_ch):
                self.log(f"Cannot set initial channel {first_ch} on {iface}, aborting AP discovery")
                self.scanning = False
                return

        hopper = threading.Thread(
            target=self.channel_hopper,
            args=(iface,),
            daemon=True,
        )
        hopper.start()
        self.log(f"AP Discovery started on {iface}")

        try:
            sniff(
                iface=iface,
                prn=self.packet_handler_ap_discovery,
                store=False,
                stop_filter=lambda x: not self.scanning,
            )
        except Exception as e:
            self.log(f"AP Discovery error: {e}")
        finally:
            self.log("AP Discovery sniff stopped")


    def lock_on_ap(self, iface, bssid, channel):
        self.interface = iface
        self.scanning = False
        self.deep_scanning = True
        self.focus_bssid = bssid

        self.processed_packets = 0
        self.matched_packets = 0

        self.set_channel(iface, channel)
        self.log(f"Deep scan locked on {bssid} CH{channel}")

        try:
            sniff(
                iface=iface,
                prn=self.packet_handler_deep_scan,
                store=False,
                stop_filter=lambda x: not self.deep_scanning,
            )
        except Exception as e:
            self.log(f"Deep scan error: {e}")
        finally:
            self.focus_bssid = None
            self.log("Deep scan finished")

    def stop_scan(self):
        self.scanning = False
        self.deep_scanning = False
        self.focus_bssid = None
        self.log("Scanning stopped")

    # ------------- DOSTĘP DO DANYCH -------------

    def get_network_list(self):
        with self.lock:
            return sorted(
                self.networks.values(),
                key=lambda n: n.signal_dbm,
                reverse=True,
            )

    def get_clients_for_ap(self, ap_bssid):
        with self.lock:
            return self.clients.get(ap_bssid, [])

    # ------------- EXPORT -------------

    def export_results(self, filename=None):
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_scan_{ts}.json"

        try:
            import json
            from dataclasses import asdict

            with self.lock:
                data = {
                    "networks": [asdict(n) for n in self.get_network_list()],
                    "clients": {
                        ap: [asdict(c) for c in cls]
                        for ap, cls in self.clients.items()
                    },
                    "summary": {
                        "timestamp": datetime.now().isoformat(),
                        "interface": self.interface,
                        "total_networks": len(self.networks),
                        "total_clients": sum(
                            len(cls) for cls in self.clients.values()
                        ),
                    },
                }

            with open(filename, "w") as f:
                json.dump(data, f, indent=2)

            return filename
        except Exception as e:
            self.log(f"export_results error: {e}")
            return None

