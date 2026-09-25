# SPDX-License-Identifier: GPL-3.0-or-later
"""nmap's root need is per-invocation, not per-tool (#90).

The registries used to disagree: `automation/tool_requirements.py` said nmap
`needs_root=True`, `detection/tools.py` said False, and the disagreement was
pinned in test_registry_reconciliation rather than resolved. True blocked a
`standard` connect scan that needs no privilege; False let `stealth`/`udp`/`full`
reach nmap and fail there with a terse "requires root privileges".

Now root is computed from the scan the invocation will build
(`NmapTool.needs_root`) and enforced before the spawn (`NmapTool.execute`), and
both registries carry the honest base: a standard scan needs no root.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.tools.nmap import NmapTool

# ── the per-invocation decision ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "scan_type,expected",
    [
        ("standard", False),  # -sV connect scan
        ("quick", False),     # -F connect scan
        ("vuln", False),      # --script, no raw sockets
        ("stealth", True),    # -sS
        ("udp", True),        # -sU
        ("full", True),       # -A implies -O
    ],
)
def test_needs_root_is_keyed_on_scan_type(scan_type, expected):
    assert NmapTool().needs_root({"scan_type": scan_type}) is expected


def test_the_default_scan_needs_no_root():
    """No options at all is a standard scan, which must run unprivileged."""
    assert NmapTool().needs_root() is False
    assert NmapTool().needs_root({}) is False


def test_os_detection_forces_root_on_any_scan():
    assert NmapTool().needs_root({"scan_type": "standard", "os_detection": True}) is True


def test_a_privileged_flag_in_extra_args_forces_root():
    """A raw scan flag smuggled through extra_args still counts."""
    assert NmapTool().needs_root({"scan_type": "standard", "extra_args": ["-sS"]}) is True
    assert NmapTool().needs_root({"scan_type": "standard", "extra_args": "-O"}) is True


def test_the_root_flag_set_matches_the_scan_type_presets():
    """The known mapping, spelled out, so changing a preset's flags cannot
    silently change whether it needs root without this test noticing."""
    tool = NmapTool()
    for scan_type in ("stealth", "udp", "full"):
        assert tool.needs_root({"scan_type": scan_type}) is True, scan_type
    for scan_type in ("standard", "quick", "vuln"):
        assert tool.needs_root({"scan_type": scan_type}) is False, scan_type


# ── enforcement in execute() ──────────────────────────────────────────────────


def _run(tool, target, options):
    return asyncio.run(tool.execute(target, options))


def test_a_privileged_scan_is_refused_cleanly_when_unprivileged(monkeypatch):
    """Exit through a named failure, not nmap's terse runtime error, and never
    reach the process seam."""
    monkeypatch.setattr("netreaper.tools.nmap.os.geteuid", lambda: 1000)
    spawned = False

    async def _boom(*a, **k):
        nonlocal spawned
        spawned = True
        raise AssertionError("must not spawn a privileged scan without root")

    monkeypatch.setattr(
        "netreaper.tools.base.BaseToolWrapper.execute", _boom
    )
    result = _run(NmapTool(), "10.0.0.1", {"scan_type": "stealth"})
    assert result.success is False
    assert any("root" in e for e in result.errors)
    assert "stealth" in result.errors[0]
    assert spawned is False


def test_a_standard_scan_is_not_gated_when_unprivileged(monkeypatch):
    """The whole point: a connect scan reaches the runner without root."""
    monkeypatch.setattr("netreaper.tools.nmap.os.geteuid", lambda: 1000)
    reached = False

    async def _ok(self, target, options):
        nonlocal reached
        reached = True
        from netreaper.plugins.base import PluginResult

        return PluginResult(success=True, data={})

    monkeypatch.setattr("netreaper.tools.base.BaseToolWrapper.execute", _ok)
    result = _run(NmapTool(), "10.0.0.1", {"scan_type": "standard"})
    assert result.success is True
    assert reached is True


def test_root_runs_every_scan_type(monkeypatch):
    monkeypatch.setattr("netreaper.tools.nmap.os.geteuid", lambda: 0)
    reached = []

    async def _ok(self, target, options):
        reached.append(options.get("scan_type"))
        from netreaper.plugins.base import PluginResult

        return PluginResult(success=True, data={})

    monkeypatch.setattr("netreaper.tools.base.BaseToolWrapper.execute", _ok)
    for scan_type in ("standard", "stealth", "udp", "full"):
        _run(NmapTool(), "10.0.0.1", {"scan_type": scan_type})
    assert reached == ["standard", "stealth", "udp", "full"]


def test_a_dry_run_of_a_privileged_scan_is_not_gated(monkeypatch):
    """A dry run spawns nothing, so previewing a stealth plan without root is
    allowed; the gate is on the real run."""
    monkeypatch.setattr("netreaper.tools.nmap.os.geteuid", lambda: 1000)
    reached = False

    async def _ok(self, target, options):
        nonlocal reached
        reached = True
        from netreaper.plugins.base import PluginResult

        return PluginResult(success=True, data={})

    monkeypatch.setattr("netreaper.tools.base.BaseToolWrapper.execute", _ok)
    result = _run(NmapTool(), "10.0.0.1", {"scan_type": "stealth", "dry_run": True})
    assert result.success is True
    assert reached is True
