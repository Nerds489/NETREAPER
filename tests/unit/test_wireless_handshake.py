# SPDX-License-Identifier: GPL-3.0-or-later
"""Handshake capture orchestration tests (mocked adapters, no radio)."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.wireless.eapol import LINKTYPE_IEEE802_11_RADIO
from netreaper.wireless.handshake import HandshakeCapture, capture_handshake

AP = "AA:BB:CC:DD:EE:01"
STA = "11:22:33:44:55:66"


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _eapol(key_info: int, *, from_ds: bool) -> bytes:
    fc = bytes([0x08, 0x02 if from_ds else 0x01])
    a1, a2 = (STA, AP) if from_ds else (AP, STA)
    hdr = fc + b"\x00\x00" + _mac_bytes(a1) + _mac_bytes(a2) + _mac_bytes(AP) + b"\x00\x00"
    llc = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E])
    keyframe = bytes([0x02]) + key_info.to_bytes(2, "big") + b"\x00" * 90
    return hdr + llc + bytes([0x02, 0x03]) + len(keyframe).to_bytes(2, "big") + keyframe


def _cap(*frames: bytes) -> bytes:
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_IEEE802_11_RADIO)
    rt = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
    out = gh
    for fr in frames:
        pkt = rt + fr
        out += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return out


COMPLETE = _cap(_eapol(0x0088, from_ds=True), _eapol(0x0108, from_ds=False))  # M1 + M2
EMPTY = _cap()  # valid pcap, no EAPOL frames


class FakeAirodump:
    """Writes a per-attempt .cap to the prefix the orchestrator hands it."""

    def __init__(self, caps: list[bytes | None]):
        self.caps = caps
        self.calls: list[str] = []

    async def capture_for_target(self, interface, bssid, channel, output, duration=60):
        idx = len(self.calls)
        self.calls.append(output)
        data = self.caps[idx] if idx < len(self.caps) else self.caps[-1]
        if data is not None:
            Path(f"{output}-01.cap").write_bytes(data)
        return {}


class FakeAireplay:
    def __init__(self, raise_gate: bool = False):
        self.raise_gate = raise_gate
        self.calls: list[tuple] = []

    async def deauth_attack(self, interface, bssid, client=None, count=10):
        self.calls.append((interface, bssid, client, count))
        if self.raise_gate:
            raise TargetValidationError("BSSID not authorised by scope")
        return {"packets_sent": count}


def _capture(airodump, aireplay, out, **kw):
    hc = HandshakeCapture(airodump=airodump, aireplay=aireplay)
    kw.setdefault("capture_seconds", 1)
    kw.setdefault("output", str(out / "hs"))
    import asyncio

    return asyncio.run(hc.capture("wlan0mon", AP, 6, **kw))


def test_captures_on_first_attempt(tmp_path):
    air, rep = FakeAirodump([COMPLETE]), FakeAireplay()
    res = _capture(air, rep, tmp_path)
    assert res.captured is True
    assert res.messages == [1, 2]
    assert res.client == STA
    assert res.cap_file.endswith("-01.cap")
    assert res.attempts == 1
    assert len(air.calls) == 1  # early exit, no wasted rounds
    assert len(rep.calls) == 1
    assert res.deauth_packets == 5


def test_retries_until_handshake(tmp_path):
    air, rep = FakeAirodump([EMPTY, COMPLETE]), FakeAireplay()
    res = _capture(air, rep, tmp_path, max_attempts=3)
    assert res.captured is True
    assert res.attempts == 2
    assert len(air.calls) == 2


def test_gives_up_after_max_attempts(tmp_path):
    air, rep = FakeAirodump([EMPTY]), FakeAireplay()
    res = _capture(air, rep, tmp_path, max_attempts=2)
    assert res.captured is False
    assert res.attempts == 2
    assert len(air.calls) == 2
    assert len(rep.calls) == 2


def test_scope_gate_denial_propagates(tmp_path):
    air, rep = FakeAirodump([COMPLETE]), FakeAireplay(raise_gate=True)
    with pytest.raises(TargetValidationError):
        _capture(air, rep, tmp_path)


def test_deauth_zero_disables_deauth(tmp_path):
    air, rep = FakeAirodump([COMPLETE]), FakeAireplay()
    res = _capture(air, rep, tmp_path, deauth_count=0)
    assert res.captured is True
    assert rep.calls == []  # passive: no frames transmitted
    assert res.deauth_packets == 0


def test_temp_dir_cleaned_up_when_no_output():
    air, rep = FakeAirodump([COMPLETE]), FakeAireplay()
    hc = HandshakeCapture(airodump=air, aireplay=rep)
    import asyncio

    res = asyncio.run(hc.capture("wlan0mon", AP, 6, capture_seconds=1))
    assert res.captured is True
    # airodump was handed a prefix inside a temp dir that is now removed
    assert not Path(air.calls[0]).parent.exists()


def test_capture_handshake_helper_smoke(tmp_path, monkeypatch):
    # capture_handshake() builds its own HandshakeCapture; patch the adapters.
    import netreaper.wireless.handshake as hs_mod

    monkeypatch.setattr(hs_mod, "AirodumpTool", lambda: FakeAirodump([COMPLETE]))
    monkeypatch.setattr(hs_mod, "AireplayTool", lambda: FakeAireplay())
    import asyncio

    res = asyncio.run(
        capture_handshake("wlan0mon", AP, 6, output=str(tmp_path / "hs"), capture_seconds=1)
    )
    assert res.captured is True
