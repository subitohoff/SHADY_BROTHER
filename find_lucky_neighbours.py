#!/usr/bin/env python3

import sys
import time
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
from typing import Optional

# Scapy imports
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap
import scapy.config

# Suppress Scapy verbosity
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
        
        # Channel definitions
        self.channels_2ghz = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
        # Common 5GHz channels
        self.channels_5ghz = [36, 40, 44, 48, 149, 153, 157, 161]
        
        # Combine lists for full spectrum scan
        self.channels = self.channels_2ghz + self.channels_5ghz
        
        self.channel_idx = 0
        self.current_channel = 1
        self.debug = debug

        # Targeting
        self.focus_bssid = None
        self.processed_packets = 0
        self.matched_packets = 0

    def log(self, msg):
        if self.debug:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {msg}", file=sys.stderr)

    def get_interfaces(self):
        out = []
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    parts = line.split()
                    out.append(parts[-1])
        except Exception as e:
            self.log(f"Error fetching interfaces: {e}")
        return out

    def set_monitor_mode(self, iface: str) -> bool:
        try:
            # Kill conflicting processes
            subprocess.run(["nmcli", "dev", "disconnect", iface], capture_output=True, timeout=3)
            subprocess.run(["nmcli", "dev", "set", iface, "managed", "no"], capture_output=True, timeout=3)

            cmds = [
                ["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "monitor"],
                ["ip", "link", "set", iface, "up"],
            ]

            for cmd in cmds:
                if subprocess.run(cmd, capture_output=True).returncode != 0:
                    return False

            time.sleep(1)
            self.interface = iface
            return True
        except Exception:
            return False

    def restore_managed_mode(self, iface: str):
        try:
            cmds = [
                ["ip", "link", "set", iface, "down"],
                ["iw", "dev", iface, "set", "type", "managed"],
                ["ip", "link", "set", iface, "up"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=5)
            
            subprocess.run(["nmcli", "dev", "set", iface, "managed", "yes"], capture_output=True, timeout=3)
        except Exception:
            pass

    def set_channel(self, iface: str, channel: int) -> bool:
        try:
            # 'iw' is faster than 'iwconfig'
            cmd = ["iw", "dev", iface, "set", "channel", str(channel)]
            return subprocess.run(cmd, capture_output=True, timeout=1).returncode == 0
        except Exception:
            return False

    def channel_hopper(self, iface: str):
        # Rapidly cycles channels (2.4 & 5GHz)
        error_streak = 0
        while self.scanning:
            try:
                if not self.channels:
                    time.sleep(0.5)
                    continue

                ch = self.channels[self.channel_idx]
                
                # Attempt to set channel
                if not self.set_channel(iface, ch):
                    error_streak += 1
                else:
                    self.current_channel = ch
                    error_streak = 0

                # Next channel
                self.channel_idx = (self.channel_idx + 1) % len(self.channels)
                
                # Fast hop: 0.25s is enough for beacons
                time.sleep(0.25)
                
            except Exception:
                break

    def extract_ssid(self, pkt):
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0 and elt.info:
                        return elt.info.decode("utf-8", errors="ignore").strip()
                    elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return "<Hidden>"

    def analyze_security(self, pkt):
        # Detects Encryption and PMF (WPA3 Check)
        enc, pmf = "OPEN", "No"
        try:
            if pkt.haslayer(Dot11Elt):
                p = pkt[Dot11Elt]
                while isinstance(p, Dot11Elt):
                    if p.ID == 48: # RSN Information Element
                        enc = "WPA2"
                        if b'\x00\x0f\xac\x08' in p.info: # AKM Suite 08 = SAE (WPA3)
                            enc = "WPA3"
                            pmf = "Required"
                        elif b'\x00\x0f\xac\x06' in p.info: # AKM Suite 06 = PSK+SHA256
                            pmf = "Capable"
                        break
                    p = p.payload
        except Exception:
            pass
        return enc, pmf

    def extract_channel(self, pkt):
        try:
            if pkt.haslayer(Dot11Elt):
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3 and elt.info:
                        return int(elt.info[0] if isinstance(elt.info, bytes) else elt.info)
                    elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return self.current_channel 

    def extract_rssi(self, pkt):
        try:
            if pkt.haslayer(RadioTap):
                rt = pkt[RadioTap]
                if hasattr(rt, "dBm_AntSignal"):
                    return int(rt.dBm_AntSignal)
        except Exception:
            pass
        return -100

    def parse_beacon(self, pkt):
        try:
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                return

            dot11 = pkt[Dot11]
            bssid = dot11.addr3 if pkt.haslayer(Dot11ProbeResp) else dot11.addr2

            if not bssid or bssid == "ff:ff:ff:ff:ff:ff": return

            ssid = self.extract_ssid(pkt)
            channel = self.extract_channel(pkt)
            rssi = self.extract_rssi(pkt)
            enc, pmf = self.analyze_security(pkt)
            now = datetime.utcnow().isoformat() + "Z"

            with self.lock:
                if bssid not in self.networks:
                    # Create new Network object
                    net = WiFiNet(
                        index=len(self.networks) + 1,
                        ssid=ssid,
                        bssid=bssid,
                        channel=channel,
                        frequency_mhz=0, 
                        signal_dbm=rssi,
                        beacon_interval_tu=100,
                        station_count=0,
                        first_seen=now,
                        last_seen=now,
                        vendor="Unknown"
                    )
                    net.crypto = enc
                    net.pmf = pmf
                    self.networks[bssid] = net
                else:
                    # Update existing
                    self.networks[bssid].signal_dbm = rssi
                    self.networks[bssid].last_seen = now
                    self.networks[bssid].channel = channel 
                    self.networks[bssid].crypto = enc
                    self.networks[bssid].pmf = pmf

        except Exception:
            pass

    def parse_data_frame(self, pkt):
        try:
            if not pkt.haslayer(Dot11): return
            dot11 = pkt[Dot11]
            
            # Filter for target AP
            if self.focus_bssid and self.focus_bssid not in [dot11.addr1, dot11.addr2, dot11.addr3]:
                return
            
            if dot11.type != 2: return # Data frames only

            fc = dot11.FCfield
            to_ds = bool(fc & 0x01)
            from_ds = bool(fc & 0x02)
            
            ap, client = None, None

            if to_ds and not from_ds:
                ap, client = dot11.addr1, dot11.addr2
            elif not to_ds and from_ds:
                ap, client = dot11.addr2, dot11.addr1

            if ap and client and ap in self.networks and client != "ff:ff:ff:ff:ff:ff":
                self._add_client(client, ap, self.extract_rssi(pkt))
                self.matched_packets += 1
        except Exception:
            pass

    def _add_client(self, mac, bssid, rssi):
        now = datetime.utcnow().isoformat() + "Z"
        with self.lock:
            for c in self.clients[bssid]:
                if c.mac == mac:
                    c.signal_dbm = rssi
                    c.last_seen = now
                    return
            
            self.clients[bssid].append(ClientDevice(
                mac=mac, ap_bssid=bssid, signal_dbm=rssi, last_seen=now
            ))
            if bssid in self.networks:
                self.networks[bssid].station_count = len(self.clients[bssid])

    def packet_handler(self, pkt):
        if self.scanning:
            self.parse_beacon(pkt)
        elif self.deep_scanning:
            self.parse_beacon(pkt)
            self.parse_data_frame(pkt)

    def _sniff_worker(self, iface):
        # Helper to run sniff in a thread without blocking main
        try:
            sniff(iface=iface, prn=self.packet_handler, store=False, stop_filter=lambda x: not (self.scanning or self.deep_scanning))
        except Exception:
            pass

    def start_ap_discovery(self, iface: str):
        self.interface = iface
        self.scanning = True
        self.deep_scanning = False
        
        # Try setting first channel
        if self.channels:
            self.set_channel(iface, self.channels[0])

        # Start Channel Hopper (Thread 1)
        threading.Thread(target=self.channel_hopper, args=(iface,), daemon=True).start()
        
        # Start Sniffer (Thread 2) - FIX: No longer blocks main thread
        threading.Thread(target=self._sniff_worker, args=(iface,), daemon=True).start()

    def lock_on_ap(self, iface, bssid, channel):
        # Locks channel for Deep Scan (Stop hopping)
        self.interface = iface
        self.scanning = False
        self.deep_scanning = True
        self.focus_bssid = bssid
        self.set_channel(iface, channel)
        
        # Start Sniffer for Deep Scan (Thread)
        threading.Thread(target=self._sniff_worker, args=(iface,), daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        self.deep_scanning = False
