# SPDX-License-Identifier: GPL-3.0-or-later
"""WPA handshake cracking (aircrack-ng, offline)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import TargetValidationError, ToolNotFoundError
from netreaper.core.process import ProcessResult
from netreaper.safety.scope import Tier
from netreaper.wireless.crack import crack_handshake, parse_wpa_key

# --- key parsing (pure) ---


def test_parse_wpa_key_extracts_passphrase():
    assert parse_wpa_key("...\nKEY FOUND! [ hunter2 ]\n...") == "hunter2"


def test_parse_wpa_key_allows_spaces_in_passphrase():
    assert parse_wpa_key("KEY FOUND! [ correct horse ]") == "correct horse"


def test_parse_wpa_key_none_when_absent():
    assert parse_wpa_key("Passphrase not in dictionary") is None


# --- orchestration ---


class FakeRunner:
    def __init__(self, *, stdout: str = "", raise_exc: Exception | None = None):
        self.calls: list[tuple[list[str], dict]] = []
        self._stdout = stdout
        self._raise = raise_exc

    async def run(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self._raise is not None:
            raise self._raise
        return ProcessResult(cmd=list(cmd), returncode=0, stdout=self._stdout)


def test_crack_success(tmp_path):
    wl = tmp_path / "rockyou.txt"
    wl.write_text("hunter2\n")
    cap = tmp_path / "hs.cap"
    cap.write_text("x")
    runner = FakeRunner(stdout="KEY FOUND! [ hunter2 ]")
    res = asyncio.run(
        crack_handshake(cap, "AA:BB:CC:DD:EE:FF", wl, runner=runner)
    )
    assert res.cracked and res.password == "hunter2"  # noqa: S105
    cmd, kw = runner.calls[0]
    assert cmd[:3] == ["aircrack-ng", "-a", "2"]
    assert "-b" in cmd and "AA:BB:CC:DD:EE:FF" in cmd and str(wl) in cmd
    assert kw["tier"] == Tier.PASSIVE
    assert kw.get("targets", ()) == ()  # offline: no network target


def test_crack_miss_when_not_in_wordlist(tmp_path):
    wl = tmp_path / "wl.txt"

    wl.write_text("nope\n")
    cap = tmp_path / "hs.cap"

    cap.write_text("x")
    res = asyncio.run(crack_handshake(
        cap, "AA:BB:CC:DD:EE:FF", wl, runner=FakeRunner(stdout="not found")))
    assert res.cracked is False and res.password is None


def test_crack_missing_wordlist(tmp_path):
    with pytest.raises(FileNotFoundError):
        asyncio.run(crack_handshake(
            tmp_path / "hs.cap", "AA:BB:CC:DD:EE:FF", tmp_path / "nope.txt",
            runner=FakeRunner()))


def test_crack_bad_bssid(tmp_path):
    wl = tmp_path / "wl.txt"

    wl.write_text("x\n")
    with pytest.raises(TargetValidationError):
        asyncio.run(crack_handshake(
            tmp_path / "hs.cap", "not-a-mac", wl, runner=FakeRunner()))


def test_crack_tool_missing_is_not_cracked(tmp_path):
    wl = tmp_path / "wl.txt"

    wl.write_text("x\n")
    cap = tmp_path / "hs.cap"

    cap.write_text("x")
    res = asyncio.run(crack_handshake(
        cap, "AA:BB:CC:DD:EE:FF", wl,
        runner=FakeRunner(raise_exc=ToolNotFoundError("aircrack-ng missing"))))
    assert res.cracked is False
