# SPDX-License-Identifier: GPL-3.0-or-later
"""Airodump CSV parsing tests (fixture data, no radio)."""
from __future__ import annotations

from netreaper.wireless.scan import parse_airodump_csv

FIXTURE = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:01, 2026-09-11 10:00:00, 2026-09-11 10:05:00, 6, 130, WPA2, CCMP, PSK, -42, 120, 3, 0.0.0.0, 9, HomeNet,
AA:BB:CC:DD:EE:02, 2026-09-11 10:00:00, 2026-09-11 10:05:00, 11, 130, WPA2, CCMP, PSK, -60, 80, 0, 0.0.0.0, 7, Office,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-09-11 10:01:00, 2026-09-11 10:05:00, -50, 40, AA:BB:CC:DD:EE:01, HomeNet
77:88:99:AA:BB:CC, 2026-09-11 10:02:00, 2026-09-11 10:05:00, -70, 12, (not associated), FreeWifi
"""


def test_parses_access_points():
    r = parse_airodump_csv(FIXTURE)
    assert len(r.access_points) == 2
    ap = r.access_points[0]
    assert ap.bssid == "AA:BB:CC:DD:EE:01"
    assert ap.essid == "HomeNet"
    assert ap.channel == 6
    assert ap.power == -42
    assert ap.privacy == "WPA2"
    assert ap.beacons == 120


def test_parses_clients():
    r = parse_airodump_csv(FIXTURE)
    assert len(r.clients) == 2
    c = r.clients[0]
    assert c.mac == "11:22:33:44:55:66"
    assert c.associated_bssid == "AA:BB:CC:DD:EE:01"
    assert c.probed_essids == ["HomeNet"]


def test_clients_for_and_find_ap_helpers():
    r = parse_airodump_csv(FIXTURE)
    assert len(r.clients_for("aa:bb:cc:dd:ee:01")) == 1   # case-insensitive
    assert r.find_ap("AA:BB:CC:DD:EE:02").essid == "Office"
    assert r.find_ap("de:ad:be:ef:00:00") is None


def test_empty_input_is_safe():
    r = parse_airodump_csv("")
    assert r.access_points == [] and r.clients == []
