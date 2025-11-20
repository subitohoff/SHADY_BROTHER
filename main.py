#!/usr/bin/env python3

import json
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime
import threading
from find_lucky_neighbours import WiFiScanner



def main():
    # root jest wymagany do monitor/sniff
    if os.geteuid() != 0:
        print("Error: uruchom jako root (monitor mode i sniff wymagają uprawnień).")
        sys.exit(1)

    scanner = WiFiScanner()

    print("=" * 60)
    print("       FIND LUCKY NEIGHBOURS - Passive Wi-Fi Scanner")
    print("           Educational/Research Tool Only")
    print("=" * 60)

    ifaces = scanner.get_interfaces()
    if not ifaces:
        print("[-] Nie wykryto interfejsów bezprzewodowych.")
        sys.exit(1)

    print("\nDostępne interfejsy:")
    for i, iface in enumerate(ifaces, 1):
        print(f"  [{i}] {iface}")
    try:
        sel = int(input(f"\nWybierz interfejs [1-{len(ifaces)}]: ")) - 1
    except ValueError:
        print("[-] Podaj liczbę."); sys.exit(1)
    if sel < 0 or sel >= len(ifaces):
        print("[-] Zły zakres."); sys.exit(1)

    iface = ifaces[sel]
    print(f"[*] Wybrano: {iface}")

    if not scanner.set_monitor_mode(iface):
        print("[-] Monitor mode nie działa na tym interfejsie.")
        sys.exit(1)

    t = threading.Thread(target=scanner.start_scan, args=(iface,), daemon=True)
    t.start()
    time.sleep(3)

    try:
        while True:
            os.system("clear")
            print("=" * 60)
            print("       FIND LUCKY NEIGHBOURS - Passive Wi-Fi Scanner")
            print("=" * 60)
            print(f"Interfejs: {iface}")
            print(f"Ilość sieci: {len(scanner.networks)}")
            print(f"Wykrytych klientów: {sum(len(clients) for clients in scanner.clients.values())}\n")
            print("Komendy: [numer] szczegóły, [A numer] ocena bezpieczeństwa, [R] odśwież, [Q] wyjście\n")

            nets = scanner.get_network_list()
            print(f"{'#':<3} {'SSID':<20} {'BSSID':<18} {'CH':<3} {'SIG':<5} {'PMF':<8} {'Clients':<8}")
            print("-" * 80)
            for n in nets:
                ssid_disp = n.ssid if len(n.ssid) <= 19 else n.ssid[:16] + "..."
                clients_count = len(scanner.get_clients_for_ap(n.bssid))
                print(f"{n.index:<3} {ssid_disp:<20} {n.bssid:<18} {n.channel:<3} {n.signal_dbm:<5} {n.rsn_pmf:<8} {clients_count:<8}")

            choice = input("\nWpisz: ").strip().upper()
            if choice == "Q":
                break
            if choice in ("R", ""):
                continue
            
            # Sprawdź czy to komenda oceny bezpieczeństwa
            if choice.startswith("A "):
                try:
                    idx = int(choice[2:])
                    sel_net = next((x for x in nets if x.index == idx), None)
                    if sel_net:
                        os.system("clear")
                        scanner.display_attack_candidates(sel_net)
                        input("\nEnter… aby wrócić")
                except ValueError:
                    continue
            else:
                try:
                    idx = int(choice)
                except ValueError:
                    continue

                sel_net = next((x for x in nets if x.index == idx), None)
                if sel_net:
                    os.system("clear")
                    scanner.display_network_details(sel_net)
                    input("\nEnter… aby wrócić")

    except KeyboardInterrupt:
        pass
    finally:
        scanner.stop_scan()
        scanner.restore_managed_mode(iface)

        if scanner.networks:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fn = f"wifi_scan_results_{ts}.json"
            from dataclasses import asdict
            import json
            with open(fn, "w") as f:
                # Zapisz zarówno sieci jak i klientów
                data = {
                    "networks": [asdict(n) for n in scanner.get_network_list()],
                    "clients": {
                        ap_bssid: [asdict(c) for c in clients] 
                        for ap_bssid, clients in scanner.clients.items()
                    },
                    "scan_info": {
                        "timestamp": ts,
                        "interface": iface,
                        "total_networks": len(scanner.networks),
                        "total_clients": sum(len(clients) for clients in scanner.clients.values())
                    }
                }
                json.dump(data, f, indent=2)
            print(f"[+] Zapisano: {fn}")


if __name__ == "__main__":
    main()
