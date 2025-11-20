
 
#!/usr/bin/env python3

import os
import sys
import time
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import json

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Deauth, Dot11Disas
import scapy.config
import scapy.utils

# Ustawienia debugowania Scapy
scapy.config.conf.verb = 0  # Wyłącz verbose Scapy

from data import WiFiNet, ClientDevice


class WiFiScanner:
    def __init__(self):
        self.networks: Dict[str, WiFiNet] = {}
        self.clients: Dict[str, List[ClientDevice]] = defaultdict(list)
        self.scanning: bool = False
        self.interface: str = ""
        self.channels: List[int] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]  # Tylko 2.4GHz na początek
        self._ch_idx: int = 0
        self.packet_count = 0
        self.debug = False  # Włącz debugowanie

    def log(self, message):
        """Funkcja logowania do debugowania"""
        if self.debug:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")

    # ------------------ INTERFEJSY ------------------

    def get_interfaces(self) -> List[str]:
        """Zwraca listę interfejsów radiowych z `iw dev`."""
        out = []
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
            self.log(f"iw dev output: {result.stdout[:200]}...")
            
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    iface_name = line.split("Interface ", 1)[1].strip()
                    out.append(iface_name)
                    self.log(f"Found interface: {iface_name}")
        except FileNotFoundError:
            print("Error: brak 'iw' (zainstaluj wireless tools).")
        except subprocess.CalledProcessError as e:
            print(f"Error: 'iw dev' nie powiodło się: {e}")
        return out

    def set_monitor_mode(self, iface: str) -> bool:
        """Włącza monitor mode (ip+iw)."""
        try:
            self.log(f"Setting monitor mode for {iface}")
            
            # Sprawdź obecny tryb
            result = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
            self.log(f"Current interface info: {result.stdout}")
            
            # Zatrzymaj interfejs
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            self.log("Interface brought down")
            
            # Ustaw monitor mode
            subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True)
            self.log("Monitor mode set")
            
            # Włącz interfejs
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            self.log("Interface brought up")
            
            # Sprawdź nowy tryb
            result = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True)
            self.log(f"New interface info: {result.stdout}")
            
            print(f"[+] {iface}: monitor mode aktywny")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Nie udało się włączyć monitor mode: {e}")
            return False

    def restore_managed_mode(self, iface: str) -> None:
        """Przywraca normalny (managed) tryb Wi-Fi."""
        try:
            print("[*] Przywracam managed mode…")
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            print("[+] Managed mode przywrócony")
        except subprocess.CalledProcessError as e:
            print(f"[-] Błąd przywracania managed mode: {e}")

    # ------------------ KANAŁY ------------------

    def set_channel(self, iface: str, ch: int) -> bool:
        """Ustawia kanał; zwraca True/False (bez wyjątku)."""
        try:
            self.log(f"Setting channel {ch}")
            result = subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(ch)],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return True
            else:
                self.log(f"Channel set failed: {result.stderr}")
                return False
        except Exception as e:
            self.log(f"Channel set exception: {e}")
            return False

    def channel_hopper(self, iface: str) -> None:
        """Prosty hopping po kanałach."""
        self.log("Channel hopper started")
        while self.scanning and self.channels:
            ch = self.channels[self._ch_idx]
            if self.set_channel(iface, ch):
                self.log(f"Channel set to {ch}")
            else:
                self.log(f"Failed to set channel {ch}")
            
            self._ch_idx = (self._ch_idx + 1) % len(self.channels)
            time.sleep(1)  # 1 sekunda na kanale

    # ------------------ PARSOWANIE PAKIETÓW ------------------

    def parse_packet(self, pkt) -> None:
        """Główna funkcja parsująca pakiety"""
        self.packet_count += 1
        if self.packet_count % 50 == 0:
            self.log(f"Processed {self.packet_count} packets, found {len(self.networks)} networks")
        
        # Sprawdź czy to ramka 802.11
        if not pkt.haslayer(Dot11):
            return

        # Debug: pokaż podstawowe informacje o pakiecie
        if self.packet_count % 20 == 0:  # Co 20 pakietów
            self.log(f"Packet #{self.packet_count}: Type={pkt.type} Subtype={pkt.subtype}")

        # Parsuj ramki beacon/probe response (AP)
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._parse_ap_packet(pkt)
        
        # Parsuj ramki danych i zarządzania (klienci)
        self._detect_clients_from_packet(pkt)

    def _parse_ap_packet(self, pkt) -> None:
        """Parsuje ramki beacon/probe response dla AP"""
        try:
            # Pobierz BSSID
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
            elif pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr3
            else:
                return

            if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                return

            self.log(f"Found AP frame from BSSID: {bssid}")

            # Pobierz RSSI
            rssi = -100
            if pkt.haslayer(RadioTap):
                if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                    rssi = pkt[RadioTap].dBm_AntSignal
                elif hasattr(pkt[RadioTap], 'dBm_AntNoise'):
                    rssi = pkt[RadioTap].dBm_AntNoise

            # Pobierz SSID
            ssid = "<hidden>"
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0 and elt.info:  # SSID
                        try:
                            ssid_bytes = bytes(elt.info)
                            if ssid_bytes:
                                ssid = ssid_bytes.decode('utf-8', errors='ignore')
                                if not ssid.strip():
                                    ssid = "<hidden>"
                        except Exception as e:
                            self.log(f"SSID decode error: {e}")
                            ssid = "<hidden>"
                        break
                    elt = elt.payload.getlayer(Dot11Elt)

            # Pobierz kanał
            channel = 1
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 3:  # DS Parameter Set (kanał)
                        if elt.info:
                            channel = ord(elt.info)
                        break
                    elt = elt.payload.getlayer(Dot11Elt)

            now_iso = datetime.utcnow().isoformat() + "Z"

            # Aktualizuj lub dodaj sieć
            if bssid in self.networks:
                network = self.networks[bssid]
                network.signal_dbm = rssi
                network.channel = channel
                network.last_seen = now_iso
                self.log(f"Updated network: {ssid} (BSSID: {bssid})")
            else:
                network = WiFiNet(
                    index=len(self.networks) + 1,
                    ssid=ssid,
                    bssid=bssid,
                    channel=channel,
                    frequency_mhz=2412 + (channel - 1) * 5,  # 2.4GHz
                    signal_dbm=rssi,
                    beacon_interval_tu=100,
                    akm=["Unknown"],
                    cipher="Unknown",
                    rsn_pmf="unknown",
                    station_count=0,
                    capabilities=["ESS"],
                    first_seen=now_iso,
                    last_seen=now_iso,
                    vendor=self._get_vendor_from_mac(bssid)
                )
                self.networks[bssid] = network
                self.log(f"NEW NETWORK: {ssid} (BSSID: {bssid}, Channel: {channel}, RSSI: {rssi})")

        except Exception as e:
            self.log(f"Error parsing AP packet: {e}")

    def _detect_clients_from_packet(self, pkt) -> None:
        """Wykrywa klientów z różnych typów ramek"""
        try:
            if not pkt.haslayer(Dot11):
                return

            now_iso = datetime.utcnow().isoformat() + "Z"
            rssi = -100
            if pkt.haslayer(RadioTap):
                if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                    rssi = pkt[RadioTap].dBm_AntSignal

            # Ramki danych
            if pkt.haslayer(Dot11) and pkt.type == 2:  # Data frames
                addr1 = pkt.addr1  # Receiver
                addr2 = pkt.addr2  # Transmitter
                addr3 = pkt.addr3  # BSSID

                # Sprawdź różne kombinacje
                if (addr2 and addr2 not in self.networks and 
                    addr1 and addr1 in self.networks):
                    # Client -> AP
                    self._add_or_update_client(addr2, addr1, rssi, now_iso)
                
                elif (addr1 and addr1 not in self.networks and 
                      addr2 and addr2 in self.networks):
                    # AP -> Client
                    self._add_or_update_client(addr1, addr2, rssi, now_iso)

            # Ramki zarządzania
            elif pkt.haslayer(Dot11) and pkt.type == 0:  # Management frames
                if pkt.subtype in [11, 0]:  # Authentication, Association Request
                    # Client -> AP
                    client_mac = pkt.addr2
                    ap_mac = pkt.addr1
                    if (client_mac and ap_mac and ap_mac in self.networks and
                        client_mac not in self.networks):
                        self._add_or_update_client(client_mac, ap_mac, rssi, now_iso)

        except Exception as e:
            self.log(f"Error detecting clients: {e}")

    def _add_or_update_client(self, client_mac: str, ap_bssid: str, rssi: int, timestamp: str):
        """Dodaje lub aktualizuje klienta"""
        try:
            # Sprawdź czy klient już istnieje
            existing_client = None
            for client in self.clients[ap_bssid]:
                if client.mac == client_mac:
                    existing_client = client
                    break
            
            if existing_client:
                existing_client.signal_dbm = rssi
                existing_client.last_seen = timestamp
            else:
                client = ClientDevice(
                    mac=client_mac,
                    ap_bssid=ap_bssid,
                    signal_dbm=rssi,
                    last_seen=timestamp,
                    vendor=self._get_vendor_from_mac(client_mac)
                )
                self.clients[ap_bssid].append(client)
                self.log(f"NEW CLIENT: {client_mac} -> AP: {ap_bssid} (RSSI: {rssi})")
                
        except Exception as e:
            self.log(f"Error adding client: {e}")

    def _get_vendor_from_mac(self, mac: str) -> str:
        """Proste mapowanie OUI MAC na producenta"""
        if not mac or len(mac) < 8:
            return "Unknown"
        
        oui = mac.lower()[:8]
        vendors = {
            "00:50:f2": "Microsoft", "00:1b:63": "Apple", "00:1d:4f": "Apple",
            "00:23:12": "Apple", "00:25:00": "Apple", "00:26:08": "Apple",
            "00:26:4a": "Apple", "00:26:b0": "Apple", "00:30:65": "Apple",
            "00:56:cd": "Apple", "00:a0:40": "Apple", "00:0c:29": "VMware",
            "00:1a:11": "Google", "00:1e:65": "Google", "00:26:01": "Samsung",
            "08:00:27": "VirtualBox", "08:ee:8b": "Samsung", "10:30:47": "Samsung",
            "14:10:9f": "Apple", "18:af:61": "Apple", "1c:ab:a7": "Samsung",
            "20:aa:4b": "Apple", "24:a2:e1": "Apple", "28:37:37": "Apple",
            "28:cf:da": "Apple", "28:cf:e9": "Apple", "2c:33:61": "Apple",
            "2c:be:08": "Apple", "30:f7:0d": "Apple", "34:12:98": "Apple",
            "34:36:3b": "Apple", "38:48:4c": "Apple", "3c:07:54": "Apple",
            "3c:15:c2": "Apple", "3c:a0:67": "Raspberry Pi", "40:30:04": "Apple",
            "44:00:10": "Apple", "48:60:bc": "Apple", "4c:32:75": "Apple",
            "50:1a:c5": "Microsoft", "54:26:96": "Apple", "54:72:4f": "Apple",
            "54:e4:3a": "Apple", "5c:96:9d": "Apple", "60:33:4b": "Apple",
            "64:a3:cb": "Apple", "68:09:27": "Apple", "68:5b:35": "Apple",
            "68:96:7b": "Apple", "6c:70:9f": "Apple", "6c:94:f8": "Apple",
            "70:56:81": "Apple", "78:31:c1": "Apple", "78:7b:8a": "Apple",
            "78:ca:39": "Apple", "7c:6d:62": "Apple", "7c:c3:a1": "Apple",
            "80:00:6e": "Apple", "84:29:99": "Apple", "84:38:35": "Apple",
            "84:85:06": "Apple", "84:8e:0c": "Apple", "84:b1:53": "Apple",
            "88:53:95": "Apple", "8c:2d:aa": "Apple", "8c:7b:9d": "Apple",
            "90:60:f1": "Apple", "90:72:40": "Apple", "94:94:26": "Apple",
            "98:01:a7": "Apple", "98:b8:e3": "Apple", "98:d6:bb": "Apple",
            "98:fe:94": "Apple", "9c:04:eb": "Apple", "9c:20:7b": "Apple",
            "9c:35:eb": "Apple", "a0:99:9b": "Apple", "a4:31:35": "Apple",
            "a4:b1:97": "Apple", "a4:c3:61": "Apple", "a8:20:66": "Apple",
            "a8:86:dd": "Apple", "a8:88:08": "Apple", "a8:96:8a": "Apple",
            "ac:29:3a": "Raspberry Pi", "ac:3a:7a": "Raspberry Pi",
            "ac:bc:32": "Apple", "b0:34:95": "Apple", "b0:65:bd": "Apple",
            "b0:9f:ba": "Apple", "b4:18:d1": "Apple", "b4:f0:ab": "Apple",
            "b8:09:8a": "Apple", "b8:8d:12": "Apple", "b8:e8:56": "Apple",
            "b8:f6:b1": "Apple", "bc:3b:af": "Raspberry Pi", "bc:52:b7": "Samsung",
            "bc:67:78": "Apple", "bc:92:6b": "Apple", "c0:63:94": "Apple",
            "c0:84:7a": "Apple", "c0:ce:cd": "Apple", "c4:2c:03": "Apple",
            "c8:2a:14": "Apple", "c8:69:cd": "Apple", "c8:85:50": "Apple",
            "c8:b5:b7": "Apple", "cc:08:e0": "Apple", "cc:20:e8": "Apple",
            "cc:29:f5": "Apple", "d0:23:db": "Apple", "d0:81:7a": "Apple",
            "d8:30:62": "Apple", "d8:96:95": "Apple", "dc:2b:2a": "Apple",
            "dc:37:14": "Lenovo", "dc:41:5f": "Raspberry Pi", "dc:86:d8": "Apple",
            "e0:66:78": "TP-Link", "e0:ac:cb": "Apple", "e0:b9:ba": "Apple",
            "e0:c7:67": "Raspberry Pi", "e4:25:e7": "TP-Link", "e8:04:0b": "Apple",
            "e8:06:88": "Apple", "ec:35:86": "Raspberry Pi", "f0:18:98": "Apple",
            "f0:24:75": "Apple", "f0:99:bf": "Raspberry Pi", "f0:cb:a1": "Raspberry Pi",
            "f4:37:b7": "Apple", "f8:1e:df": "Intel",
        }
        return vendors.get(oui, "Unknown")

    # ------------------ START/STOP SNIFFA ------------------

    def start_scan(self, iface: str) -> None:
        """Uruchamia hoppera i sniffer."""
        self.interface = iface
        self.scanning = True

        # Uruchom channel hopper
        hopper_thread = threading.Thread(target=self.channel_hopper, args=(iface,), daemon=True)
        hopper_thread.start()
        self.log("Channel hopper thread started")

        print(f"[*] Start pasywnego skanu na {iface} (Ctrl+C aby przerwać)…")
        
        try:
            # Sniff z timeout i filtrem
            sniff(
                iface=iface,
                prn=self.parse_packet,
                store=0,
                stop_filter=lambda x: not self.scanning,
                timeout=300  # 5 minut timeout
            )
        except Exception as e:
            print(f"[-] Błąd sniffera: {e}")
            self.log(f"Sniffer error details: {e}")

    def stop_scan(self) -> None:
        self.scanning = False
        self.log("Scanning stopped")

    # ------------------ DOSTĘP / WYŚWIETLANIE ------------------

    def get_network_list(self) -> List[WiFiNet]:
        """Zwraca listę sieci posortowaną po sile sygnału (malejąco)."""
        return sorted(self.networks.values(), key=lambda n: n.signal_dbm, reverse=True)

    def get_clients_for_ap(self, ap_bssid: str) -> List[ClientDevice]:
        """Zwraca listę klientów dla danego AP."""
        return self.clients.get(ap_bssid, [])

    def display_network_details(self, net: WiFiNet) -> None:
        """Czytelny podgląd jednej sieci z klientami."""
        print("\n" + "=" * 60)
        print(f"DETAILS FOR: {net.ssid}")
        print("=" * 60)
        print(f"SSID:        {net.ssid}")
        print(f"BSSID:       {net.bssid}")
        print(f"Channel:     {net.channel}")
        print(f"Frequency:   {net.frequency_mhz} MHz")
        print(f"Signal:      {net.signal_dbm} dBm")
        print(f"Vendor:      {net.vendor}")
        print(f"First seen:  {net.first_seen}")
        print(f"Last seen:   {net.last_seen}")
        
        # Wyświetl klientów
        clients = self.get_clients_for_ap(net.bssid)
        print(f"\nConnected Clients: {len(clients)}")
        print("-" * 60)
        
        if clients:
            print(f"{'#':<2} {'MAC Address':<18} {'Signal':<8} {'Vendor':<15} {'Last Seen'}")
            print("-" * 60)
            for i, client in enumerate(clients, 1):
                time_str = client.last_seen[11:19] if len(client.last_seen) > 19 else client.last_seen
                print(f"{i:<2} {client.mac:<18} {client.signal_dbm:<8} {client.vendor:<15} {time_str}")
        else:
            print("No clients detected yet...")
            print("Keep scanning to discover connected devices")
        
        print("=" * 60)

    def display_attack_candidates(self, net: WiFiNet) -> None:
        """Pokazuje szczegółową ocenę podatności."""
        print("\n" + "=" * 60)
        print(f"SECURITY ASSESSMENT FOR: {net.ssid}")
        print("=" * 60)
        
        clients = self.get_clients_for_ap(net.bssid)
        
        print(f"Network: {net.ssid}")
        print(f"BSSID: {net.bssid}")
        print(f"Channel: {net.channel}")
        print(f"Signal: {net.signal_dbm} dBm")
        print(f"Vendor: {net.vendor}")
        
        print(f"\nConnected Clients: {len(clients)}")
        if clients:
            print("Available for testing:")
            for i, client in enumerate(clients, 1):
                print(f"  {i}. {client.mac} ({client.vendor}) - Signal: {client.signal_dbm} dBm")
        else:
            print("No clients detected - keep scanning")
        
        print("=" * 60)

    def export_results(self, filename: str = None) -> str:
        """Eksportuje wyniki do JSON."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_scan_results_{timestamp}.json"
        
        from dataclasses import asdict
        data = {
            "networks": [asdict(n) for n in self.get_network_list()],
            "clients": {
                ap_bssid: [asdict(c) for c in clients] 
                for ap_bssid, clients in self.clients.items()
            },
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "interface": self.interface,
                "total_networks": len(self.networks),
                "total_clients": sum(len(clients) for clients in self.clients.values()),
                "total_packets": self.packet_count
            }
        }
        
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        
        return filename
