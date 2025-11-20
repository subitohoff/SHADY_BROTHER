#!/usr/bin/env python3
from dataclasses import dataclass
from typing import List


@dataclass
class WiFiNet:
    index: int
    ssid: str
    bssid: str
    channel: int
    frequency_mhz: int
    signal_dbm: int
    beacon_interval_tu: int
    akm: List[str]
    cipher: str
    rsn_pmf: str
    station_count: int
    capabilities: List[str]
    first_seen: str
    last_seen: str
    vendor: str = ""
    country: str = ""
    wps: bool = False


@dataclass
class ClientDevice:
    """Reprezentuje klienta podłączonego do AP"""
    mac: str
    ap_bssid: str
    signal_dbm: int
    last_seen: str
    ip_address: str = ""
    vendor: str = ""
    connected: bool = True
