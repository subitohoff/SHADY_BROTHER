#!/usr/bin/env python3

from dataclasses import dataclass, field
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
    station_count: int
    first_seen: str
    last_seen: str
    vendor: str
    akm: List[str] = field(default_factory=lambda: ["Unknown"])
    cipher: str = "Unknown"
    rsn_pmf: str = "unknown"
    capabilities: List[str] = field(default_factory=lambda: ["ESS"])
    country: str = ""
    wps: bool = False
    

@dataclass
class ClientDevice:
    mac: str
    ap_bssid: str
    signal_dbm: int
    last_seen: str
    ip_address: str = ""
    vendor: str = ""
    connected: bool = True
