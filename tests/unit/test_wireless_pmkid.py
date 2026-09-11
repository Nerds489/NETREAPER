# SPDX-License-Identifier: GPL-3.0-or-later
"""PMKID extraction, hashcat formatting, and capture orchestration (no radio)."""
from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.wireless.eapol import (
    LINKTYPE_IEEE802_11_RADIO,
    parse_pmkids,
    pmkids_for,
    read_pmkids,
)
from netreaper.wireless.pmkid import PmkidCapture, capture_pmkid, hashcat_22000_line

AP = "AA:BB:CC:DD:EE:01"
STA = "11:22:33:44:55:66"
AP2 = "AA:BB:CC:DD:EE:02"
PMKID = bytes(range(16))  # 000102...0f
PMKID_HEX = PMKID.hex()


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def m1_keyframe(key_data: bytes) -> bytes:
    """A message-1 EAPOL-Key body with the given Key Data appended."""
    return (
        b"\x02"                      # descriptor type
        + (0x0088).to_bytes(2, "big")  # key info: ACK + pairwise (M1)
        + b"\x00\x10"                # key length
        + b"\x00" * 8                # replay counter
        + b"\x11" * 32               # key nonce (ANonce)
        + b"\x00" * 16               # key IV
        + b"\x00" * 8                # key RSC
        + b"\x00" * 8                # key ID
        + b"\x00" * 16               # key MIC
        + len(key_data).to_bytes(2, "big")
        + key_data
    )


def pmkid_kde(pmkid: bytes) -> bytes:
    """An RSN PMKID KDE (00-0F-AC type 4)."""
    body = b"\x00\x0f\xac" + b"\x04" + pmkid
    return bytes([0xDD, len(body)]) + body


def dot11_m1(keyframe: bytes, ap: str = AP, sta: str = STA) -> bytes:
    fc = bytes([0x08, 0x02])  # Data, FromDS (AP -> STA)
    hdr = (
        fc + b"\x00\x00"
        + _mac_bytes(sta) + _mac_bytes(ap) + _mac_bytes(ap) + b"\x00\x00"
    )
    llc = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E])
    eapol = bytes([0x02, 0x03]) + len(keyframe).to_bytes(2, "big") + keyframe
    return hdr + llc + eapol


def make_pcap(*frames: bytes) -> bytes:
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_IEEE802_11_RADIO)
    rt = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
    out = gh
    for fr in frames:
        pkt = rt + fr
        out += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return out


# --- extraction ---


def test_extract_pmkid():
    cap = make_pcap(dot11_m1(m1_keyframe(pmkid_kde(PMKID))))
    found = parse_pmkids(cap)
    assert len(found) == 1
    assert found[0].pmkid == PMKID_HEX
    assert found[0].bssid == AP
    assert found[0].client == STA


def test_no_pmkid_when_key_data_empty():
    cap = make_pcap(dot11_m1(m1_keyframe(b"")))
    assert parse_pmkids(cap) == []


def test_all_zero_pmkid_is_ignored():
    cap = make_pcap(dot11_m1(m1_keyframe(pmkid_kde(b"\x00" * 16))))
    assert parse_pmkids(cap) == []


def test_pmkid_kde_after_other_kde():
    # a non-PMKID vendor KDE precedes the PMKID KDE; the walker must skip it
    other = bytes([0xDD, 0x06]) + b"\x00\x0f\xac" + b"\x01" + b"\x00\x00"
    cap = make_pcap(dot11_m1(m1_keyframe(other + pmkid_kde(PMKID))))
    found = parse_pmkids(cap)
    assert len(found) == 1 and found[0].pmkid == PMKID_HEX


def test_pmkids_for_filters_bssid_and_dedupes(tmp_path):
    cap = make_pcap(
        dot11_m1(m1_keyframe(pmkid_kde(PMKID)), ap=AP),
        dot11_m1(m1_keyframe(pmkid_kde(PMKID)), ap=AP),  # duplicate (AP, STA)
        dot11_m1(m1_keyframe(pmkid_kde(bytes(range(16, 32)))), ap=AP2),
    )
    path = tmp_path / "cap-01.cap"
    path.write_bytes(cap)
    assert len(read_pmkids(path)) == 2  # deduped per (bssid, client)
    assert len(pmkids_for(path, AP.lower())) == 1  # case-insensitive
    assert pmkids_for(path, "de:ad:be:ef:00:00") == []


# --- hashcat formatting ---


def test_hashcat_22000_line():
    line = hashcat_22000_line(PMKID_HEX, AP, STA, "HomeNet")
    assert line == f"WPA*01*{PMKID_HEX}*aabbccddee01*112233445566*486f6d654e6574***"


def test_hashcat_22000_empty_essid():
    line = hashcat_22000_line(PMKID_HEX, AP, STA, "")
    assert line == f"WPA*01*{PMKID_HEX}*aabbccddee01*112233445566****"


# --- capture orchestration ---


class FakeAirodump:
    def __init__(self, caps, raise_gate=False):
        self.caps = list(caps)
        self.calls: list[str] = []
        self.raise_gate = raise_gate

    async def capture_for_target(self, interface, bssid, channel, output, duration=60):
        self.calls.append(output)
        if self.raise_gate:
            raise TargetValidationError("BSSID not authorised by scope")
        idx = len(self.calls) - 1
        data = self.caps[idx] if idx < len(self.caps) else self.caps[-1]
        if data is not None:
            Path(f"{output}-01.cap").write_bytes(data)
        return {}


class FakeAireplay:
    def __init__(self):
        self.calls: list[tuple] = []

    async def deauth_attack(self, interface, bssid, client=None, count=10):
        self.calls.append((interface, bssid, client, count))
        return {"packets_sent": count}


EMPTY = make_pcap()


def _good_cap():
    return make_pcap(dot11_m1(m1_keyframe(pmkid_kde(PMKID))))


def _run(airodump, aireplay, out, **kw):
    hc = PmkidCapture(airodump=airodump, aireplay=aireplay)
    kw.setdefault("capture_seconds", 1)
    kw.setdefault("essid", "HomeNet")
    kw.setdefault("output", str(out / "pmkid"))
    return asyncio.run(hc.capture("wlan0mon", AP, 6, **kw))


def test_captures_pmkid_first_attempt(tmp_path):
    air, rep = FakeAirodump([_good_cap()]), FakeAireplay()
    res = _run(air, rep, tmp_path)
    assert res.captured is True
    assert res.pmkid == PMKID_HEX
    assert res.hashcat.startswith(f"WPA*01*{PMKID_HEX}*aabbccddee01*")
    assert res.attempts == 1
    assert rep.calls == []  # passive by default (deauth_count=0)


def test_deauth_used_when_requested(tmp_path):
    air, rep = FakeAirodump([_good_cap()]), FakeAireplay()
    res = _run(air, rep, tmp_path, deauth_count=5)
    assert res.captured is True
    assert len(rep.calls) == 1
    assert res.deauth_packets == 5


def test_no_pmkid_returns_uncaptured(tmp_path):
    air, rep = FakeAirodump([EMPTY]), FakeAireplay()
    res = _run(air, rep, tmp_path, max_attempts=2)
    assert res.captured is False
    assert res.attempts == 2
    assert len(air.calls) == 2


def test_scope_gate_denial_propagates(tmp_path):
    air, rep = FakeAirodump([_good_cap()], raise_gate=True), FakeAireplay()
    with pytest.raises(TargetValidationError):
        _run(air, rep, tmp_path)


def test_capture_pmkid_helper_smoke(tmp_path, monkeypatch):
    import netreaper.wireless.pmkid as pmkid_mod

    monkeypatch.setattr(pmkid_mod, "AirodumpTool", lambda: FakeAirodump([_good_cap()]))
    monkeypatch.setattr(pmkid_mod, "AireplayTool", lambda: FakeAireplay())
    res = asyncio.run(
        capture_pmkid("wlan0mon", AP, 6, essid="HomeNet", output=str(tmp_path / "p"),
                      capture_seconds=1)
    )
    assert res.captured is True and res.pmkid == PMKID_HEX
