#!/usr/bin/env python3

import subprocess
import time
from find_lucky_neighbours import WiFiScanner

def test_interface():
    """Testuje interfejs przed uruchomieniem skanera"""
    scanner = WiFiScanner()
    
    print("=== TEST DIAGNOSTYCZNY ===")
    
    # 1. Sprawdź interfejsy
    interfaces = scanner.get_interfaces()
    print(f"1. Dostępne interfejsy: {interfaces}")
    
    if not interfaces:
        print("❌ Brak interfejsów Wi-Fi!")
        return False
    
    # 2. Wybierz pierwszy interfejs
    iface = interfaces[0]
    print(f"2. Wybrano interfejs: {iface}")
    
    # 3. Sprawdź czy można ustawić monitor mode
    print(f"3. Próba ustawienia monitor mode...")
    if scanner.set_monitor_mode(iface):
        print("✅ Monitor mode ustawiony")
        
        # 4. Test kanałów
        print("4. Test zmiany kanałów...")
        for channel in [1, 6, 11]:
            if scanner.set_channel(iface, channel):
                print(f"   ✅ Kanał {channel} OK")
            else:
                print(f"   ❌ Kanał {channel} FAIL")
        
        # Przywróć managed mode
        scanner.restore_managed_mode(iface)
        return True
    else:
        print("❌ Nie udało się ustawić monitor mode")
        return False

if __name__ == "__main__":
    test_interface()
