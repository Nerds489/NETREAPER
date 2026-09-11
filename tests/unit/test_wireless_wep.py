# SPDX-License-Identifier: GPL-3.0-or-later
"""WEP key parsing, aircrack invocation, and attack orchestration (no radio)."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Tier
from netreaper.wireless.wep import WepAttack, crack_capture, parse_aircrack_key

AP = "AA:BB:CC:DD:EE:01"

KEY_FOUND_64 = "[00:00:00]  Tested 12345 keys\n\nKEY FOUND! [ AB:CD:EF:12:34 ]\n"
KEY_FOUND_ASCII = "KEY FOUND! [ 61:62:63:64:65 ] (ASCII: abcde )\n"
KEY_NOT_FOUND = "Failed. Next try with more IVs.\nKEY NOT FOUND\n"


# --- parser ---


def test_parse_wep64_key():
    assert parse_aircrack_key(KEY_FOUND_64) == "abcdef1234"


def test_parse_key_with_ascii_suffix():
    assert parse_aircrack_key(KEY_FOUND_ASCII) == "6162636465"


def test_parse_no_key():
    assert parse_aircrack_key(KEY_NOT_FOUND) is None
    assert parse_aircrack_key("") is None


# --- crack_capture (aircrack-ng invocation, fake runner) ---


class FakeRunner:
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[tuple] = []

    async def run(self, cmd, **kw):
        self.calls.append((cmd, kw))
        return SimpleNamespace(stdout=self.stdout, stderr=self.stderr, returncode=0)


def test_crack_capture_returns_key_and_runs_passive():
    runner = FakeRunner(stdout=KEY_FOUND_64)
    key = asyncio.run(crack_capture("cap-01.cap", AP, runner=runner))
    assert key == "abcdef1234"
    cmd, kw = runner.calls[0]
    assert cmd[0] == "aircrack-ng"
    assert "-b" in cmd and AP in cmd
    assert kw["tier"] == Tier.PASSIVE  # local compute, no network target


def test_crack_capture_no_key():
    runner = FakeRunner(stdout=KEY_NOT_FOUND)
    assert asyncio.run(crack_capture("cap-01.cap", AP, runner=runner)) is None


def test_crack_capture_omits_b_without_bssid():
    runner = FakeRunner(stdout=KEY_NOT_FOUND)
    asyncio.run(crack_capture("cap-01.cap", runner=runner))
    assert "-b" not in runner.calls[0][0]


# --- orchestration ---


class FakeAirodump:
    def __init__(self, raise_gate=False):
        self.calls: list[str] = []
        self.raise_gate = raise_gate

    async def capture_for_target(self, interface, bssid, channel, output, duration=60):
        self.calls.append(output)
        if self.raise_gate:
            raise TargetValidationError("BSSID not authorised by scope")
        await asyncio.sleep(0.05)  # let a backgrounded ARP-replay task run
        Path(f"{output}-01.cap").write_bytes(b"\x00")
        return {}


class FakeAireplay:
    def __init__(self, fakeauth_raises=False):
        self.fakeauth_calls: list[tuple] = []
        self.arpreplay_calls: list[tuple] = []
        self.fakeauth_raises = fakeauth_raises

    async def fakeauth_attack(self, interface, bssid, source_mac, essid, **kw):
        self.fakeauth_calls.append((interface, bssid, source_mac, essid))
        if self.fakeauth_raises:
            raise TargetValidationError("BSSID not authorised by scope")
        return {}

    async def arpreplay_attack(self, interface, bssid, source_mac, pps=10):
        self.arpreplay_calls.append((interface, bssid, source_mac))
        return {}


def _cracker(returns):
    seq = list(returns)

    async def cracker(cap_path, bssid=None):
        return seq.pop(0) if seq else None

    return cracker


def _attack(air, rep, cracker, **kw):
    a = WepAttack(airodump=air, aireplay=rep, cracker=cracker)
    kw.setdefault("capture_seconds", 1)
    return asyncio.run(a.run("wlan0mon", AP, 6, **kw))


def test_cracks_first_round_with_injection(tmp_path):
    air, rep = FakeAirodump(), FakeAireplay()
    res = _attack(air, rep, _cracker(["abcdef1234"]),
                  source_mac="00:11:22:33:44:55", essid="Net", output=str(tmp_path / "w"))
    assert res.cracked is True and res.key == "abcdef1234"
    assert res.rounds == 1
    assert len(rep.fakeauth_calls) == 1
    assert len(rep.arpreplay_calls) == 1  # ARP replay ran during capture


def test_no_key_tries_all_rounds(tmp_path):
    air, rep = FakeAirodump(), FakeAireplay()
    res = _attack(air, rep, _cracker([None, None, None]),
                  source_mac="00:11:22:33:44:55", output=str(tmp_path / "w"), max_rounds=3)
    assert res.cracked is False
    assert res.rounds == 3
    assert len(air.calls) == 3


def test_injection_skipped_without_source_mac(tmp_path):
    air, rep = FakeAirodump(), FakeAireplay()
    res = _attack(air, rep, _cracker(["ff00ff00ff"]), output=str(tmp_path / "w"))
    assert res.cracked is True
    assert rep.fakeauth_calls == []
    assert rep.arpreplay_calls == []


def test_capture_gate_denial_propagates(tmp_path):
    air, rep = FakeAirodump(raise_gate=True), FakeAireplay()
    with pytest.raises(TargetValidationError):
        _attack(air, rep, _cracker(["x"]), output=str(tmp_path / "w"))


def test_fakeauth_gate_denial_propagates(tmp_path):
    air, rep = FakeAirodump(), FakeAireplay(fakeauth_raises=True)
    with pytest.raises(TargetValidationError):
        _attack(air, rep, _cracker(["x"]),
                source_mac="00:11:22:33:44:55", output=str(tmp_path / "w"))
