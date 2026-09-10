# SPDX-License-Identifier: GPL-3.0-or-later
"""Monitor-mode controller tests (no radio; a scripted fake runner)."""
from __future__ import annotations

import pytest

from netreaper.wireless.monitor import MonitorController, MonitorState

MANAGED = "phy#0\n\tInterface wlan0\n\t\ttype managed\n"
RENAMED = "phy#0\n\tInterface wlan0mon\n\t\ttype monitor\n"
SAMENAME = "phy#0\n\tInterface wlan0\n\t\ttype monitor\n"
PHY_INFO = "\tSupported interface modes:\n\t\t * managed\n\t\t * monitor\n"


class _Res:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


class FakeRunner:
    """Returns queued `iw dev` outputs in order; records every command."""

    def __init__(self, iw_dev_seq):
        self._iw_dev = list(iw_dev_seq)
        self.calls: list[list[str]] = []

    async def run(self, cmd, **kwargs):
        self.calls.append(cmd)
        if cmd[:2] == ["iw", "dev"]:
            out = self._iw_dev.pop(0) if len(self._iw_dev) > 1 else self._iw_dev[0]
            return _Res(out)
        if cmd[:2] == ["iw", "phy"]:
            return _Res(PHY_INFO)
        return _Res("")


@pytest.mark.asyncio
async def test_enable_resolves_renamed_interface_by_diff():
    # from_name(iw dev)=MANAGED, before={wlan0}, after={wlan0mon}
    r = FakeRunner([MANAGED, MANAGED, RENAMED])
    c = MonitorController(runner=r)
    mon = await c.enable("wlan0")
    assert mon == "wlan0mon"
    assert c.state is MonitorState.MONITOR
    assert ["airmon-ng", "check", "kill"] in r.calls  # we stopped interferers


@pytest.mark.asyncio
async def test_enable_resolves_same_name_monitor():
    # mt76/rtl8812au keep the same name in monitor mode
    r = FakeRunner([MANAGED, MANAGED, SAMENAME])
    c = MonitorController(runner=r)
    mon = await c.enable("wlan0")
    assert mon == "wlan0"
    assert c.state is MonitorState.MONITOR


@pytest.mark.asyncio
async def test_already_monitor_is_noop_enable():
    r = FakeRunner([SAMENAME])
    c = MonitorController(runner=r)
    mon = await c.enable("wlan0")
    assert mon == "wlan0"
    assert ["airmon-ng", "start", "wlan0"] not in r.calls


@pytest.mark.asyncio
async def test_teardown_restores_and_is_idempotent():
    r = FakeRunner([MANAGED, MANAGED, RENAMED])
    c = MonitorController(runner=r)
    await c.enable("wlan0")
    await c.disable()
    assert c.state is MonitorState.MANAGED
    assert ["airmon-ng", "stop", "wlan0mon"] in r.calls
    assert ["systemctl", "restart", "NetworkManager"] in r.calls  # NM restored
    # second disable is a safe no-op
    before = len(r.calls)
    await c.disable()
    assert len(r.calls) == before
