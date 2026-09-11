# SPDX-License-Identifier: GPL-3.0-or-later
"""Live wifi auto-chain: manifests + runners driven through the ChainExecutor."""
from __future__ import annotations

import asyncio

from netreaper.chaining.executor import ChainExecutor
from netreaper.chaining.manifest import resolve_chain
from netreaper.chaining.plan_exec import manifest_step_runner, plan_to_chain
from netreaper.wireless.autochain import AutoContext, build_wifi_registry
from netreaper.wireless.crack import CrackResult
from netreaper.wireless.handshake import HandshakeResult
from netreaper.wireless.scan import AccessPoint, ScanResult


def _fakes(calls: list[str], *, captured: bool = True):
    async def enable(iface):
        calls.append("enable")
        return "wlan0mon"

    async def scan(mon):
        calls.append("scan")
        return ScanResult(access_points=[AccessPoint(bssid="AA:BB:CC:DD:EE:FF", essid="Net")])

    async def capture(mon, bssid, ch):
        calls.append("capture")
        return HandshakeResult(bssid=bssid, channel=ch, captured=captured,
                               cap_file="hs.cap" if captured else None)

    async def crack(cap, bssid, wl):
        calls.append("crack")
        return CrackResult(bssid=bssid, cracked=True, password="hunter2")  # noqa: S106

    return {"enable": enable, "scan": scan, "capture": capture, "crack": crack}


def _run(ctx, fakes):
    reg = build_wifi_registry(ctx, **fakes)
    plan = resolve_chain("wifi.password", reg)
    ex = ChainExecutor(step_runner=manifest_step_runner(reg))
    return asyncio.run(ex.execute(plan_to_chain(plan))), reg


def test_auto_chain_runs_in_order_and_recovers_password():
    calls: list[str] = []
    ctx = AutoContext(interface="wlan0", target_bssid="AA:BB:CC:DD:EE:FF",
                      channel=6, wordlist="wl")
    result, _ = _run(ctx, _fakes(calls))
    assert result.success
    assert calls == ["enable", "scan", "capture", "crack"]
    assert ctx.password == "hunter2"  # noqa: S105


def test_capture_without_target_fails_the_chain():
    calls: list[str] = []
    ctx = AutoContext(interface="wlan0", wordlist="wl")  # no target/channel
    result, _ = _run(ctx, _fakes(calls))
    assert not result.success
    assert "crack" not in calls  # crack skipped after capture failed
    assert ctx.password is None


def test_no_handshake_captured_fails_before_crack():
    calls: list[str] = []
    ctx = AutoContext(interface="wlan0", target_bssid="AA:BB:CC:DD:EE:FF",
                      channel=6, wordlist="wl")
    result, _ = _run(ctx, _fakes(calls, captured=False))
    assert not result.success
    assert "crack" not in calls


def test_build_reuses_canonical_manifest_metadata():
    # runners attached, but provides/requires match the canonical WIFI_MANIFESTS
    from netreaper.wireless.manifests import WIFI_MANIFESTS
    reg = build_wifi_registry(AutoContext(interface="wlan0"))
    for m in WIFI_MANIFESTS:
        built = reg.get(m.name)
        assert built.provides == m.provides and built.requires == m.requires
        assert built.runner is not None
