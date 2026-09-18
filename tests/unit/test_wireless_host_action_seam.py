# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #43: the wireless host actions go through the gated seam.

``wireless/mac.py`` and ``wireless/channels.py`` used to call
``asyncio.create_subprocess_exec`` directly for ``ip``/``iw``/``ethtool``.
``mac.py`` sits on a live attack path (``wireless.advanced`` calls
``change_mac``), so those spawns skipped the gate, the timeout, the
process-group teardown and the hash-chained audit trail.

``test_no_shell_spawn.py`` proves statically that no raw spawn remains. These
tests prove the behaviour: the commands are still the right ones, they are
routed through ``run_host`` with ``host_action=True``, and the mutating calls
are marked destructive so the audit line says so.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.process import ProcessResult
from netreaper.wireless import channels as channels_mod
from netreaper.wireless import mac as mac_mod


class FakeHostRunner:
    """Fake run_host callable recording (cmd, kwargs)."""

    def __init__(self, stdout: str = "", returncode: int = 0, result=...):
        self.calls: list[tuple[list[str], dict]] = []
        self._stdout = stdout
        self._returncode = returncode
        self._result = result

    async def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        if self._result is not ...:
            return self._result
        return ProcessResult(
            cmd=list(cmd), returncode=self._returncode, stdout=self._stdout
        )

    def cmd_strings(self) -> list[str]:
        return [" ".join(c) for c, _ in self.calls]


# ── mac.py ────────────────────────────────────────────────────────────────────


def test_change_mac_routes_every_ip_call_through_the_seam(monkeypatch, tmp_path):
    host = FakeHostRunner()
    monkeypatch.setattr(mac_mod, "run_host", host)
    # Force the ip fallback rather than sysfs, so the seam call is exercised.
    monkeypatch.setattr(mac_mod, "get_current_mac", _const("aa:bb:cc:dd:ee:ff"))

    new = asyncio.run(mac_mod.change_mac("wlan0", "02:11:22:33:44:55"))

    assert new == "02:11:22:33:44:55"
    assert host.cmd_strings() == [
        "ip link set wlan0 down",
        "ip link set wlan0 address 02:11:22:33:44:55",
        "ip link set wlan0 up",
    ]
    # Every one of them is a destructive host action, so the audit says so.
    for _, kw in host.calls:
        assert kw.get("destructive") is True


def test_get_current_mac_falls_back_to_the_seam(monkeypatch):
    host = FakeHostRunner(stdout="link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff")
    monkeypatch.setattr(mac_mod, "run_host", host)
    # No sysfs entry for this made-up interface, so it takes the ip path.
    got = asyncio.run(mac_mod.get_current_mac("nosuchiface0"))

    assert got == "aa:bb:cc:dd:ee:ff"
    assert host.cmd_strings() == ["ip link show nosuchiface0"]
    # A read, not a mutation: it must not be flagged destructive.
    assert host.calls[0][1].get("destructive") is not True


def test_get_permanent_mac_uses_the_seam(monkeypatch):
    host = FakeHostRunner(stdout="Permanent address: aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(mac_mod, "run_host", host)

    assert asyncio.run(mac_mod.get_permanent_mac("wlan0")) == "aa:bb:cc:dd:ee:ff"
    assert host.cmd_strings() == ["ethtool -P wlan0"]


def test_missing_tool_raises_so_change_mac_restores(monkeypatch):
    """run_host returns None for a missing tool; _run_ip_command must not pass silently."""
    host = FakeHostRunner(result=None)
    monkeypatch.setattr(mac_mod, "run_host", host)

    with pytest.raises(RuntimeError, match="did not run"):
        asyncio.run(mac_mod._run_ip_command(["link", "set", "wlan0", "up"]))


def test_nonzero_exit_raises(monkeypatch):
    host = FakeHostRunner(returncode=2)
    monkeypatch.setattr(mac_mod, "run_host", host)

    with pytest.raises(RuntimeError, match="ip command failed"):
        asyncio.run(mac_mod._run_ip_command(["link", "set", "wlan0", "up"]))


def test_change_mac_rejects_a_bad_address_before_spawning(monkeypatch):
    host = FakeHostRunner()
    monkeypatch.setattr(mac_mod, "run_host", host)

    with pytest.raises(ValueError):
        asyncio.run(mac_mod.change_mac("wlan0", "not-a-mac"))
    assert host.calls == []


# ── channels.py ───────────────────────────────────────────────────────────────


def test_set_channel_routes_through_the_seam(monkeypatch):
    host = FakeHostRunner()
    monkeypatch.setattr(channels_mod, "run_host", host)
    hopper = channels_mod.ChannelHopper("wlan0mon")

    assert asyncio.run(hopper.set_channel(6)) is True
    # Was pinned as "iw wlan0mon set channel 6", which is not valid iw syntax:
    # without the `dev` command group, iw parses the interface name as a
    # top-level command and errors, so the channel never changed. This test was
    # written to prove the call ROUTES through the seam and captured the argv
    # verbatim on the way, which pinned the bug rather than catching it.
    assert host.cmd_strings() == ["iw dev wlan0mon set channel 6"]
    assert host.calls[0][1].get("destructive") is True
    assert hopper._current_channel == 6


def test_set_channel_reports_failure_without_raising(monkeypatch):
    host = FakeHostRunner(returncode=1)
    monkeypatch.setattr(channels_mod, "run_host", host)
    hopper = channels_mod.ChannelHopper("wlan0mon")

    assert asyncio.run(hopper.set_channel(11)) is False
    assert hopper._current_channel != 11


def test_set_channel_handles_a_missing_tool(monkeypatch):
    """run_host returns None when iw is absent: report False, do not crash."""
    host = FakeHostRunner(result=None)
    monkeypatch.setattr(channels_mod, "run_host", host)
    hopper = channels_mod.ChannelHopper("wlan0mon")

    assert asyncio.run(hopper.set_channel(1)) is False


def _const(value):
    async def _inner(*_a, **_kw):
        return value

    return _inner
