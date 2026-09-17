# SPDX-License-Identifier: GPL-3.0-or-later
"""Live wifi auto-chain: manifests + runners driven through the ChainExecutor."""
from __future__ import annotations

import asyncio

from typer.testing import CliRunner

from netreaper.chaining.executor import ChainExecutor
from netreaper.chaining.manifest import resolve_chain
from netreaper.chaining.models import StepStatus
from netreaper.chaining.plan_exec import manifest_step_runner, plan_to_chain
from netreaper.cli import app
from netreaper.wireless.autochain import AutoContext, build_wifi_registry
from netreaper.wireless.crack import CrackResult
from netreaper.wireless.handshake import HandshakeResult
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.wireless.scan import AccessPoint, ScanResult

import pytest


@pytest.fixture(autouse=True)
def _authorised_engagement():
    """These chains run a manifest declared destructive + requires_confirmation.

    Before #46 item 2 the manifest's own words drove nothing but a "[confirm]"
    badge, so this whole suite ran a wifi deauth with NO engagement at all and
    passed. The step runner now enforces what the manifest declares, so the
    tests have to carry an authorisation, like the real thing does.
    """
    gate = get_scope_gate()
    gate.set_engagement(
        Engagement(
            operator="test",
            authorization_ref="SOW-TEST",
            scope=Scope(cidrs=["10.0.0.0/8"], bssids={"AA:BB:CC:DD:EE:FF"},
                        essids={"Net"}, hostnames={"wlan0", "wlan0mon"}),
            max_tier=Tier.BROADCAST,
            confirmed_tiers=frozenset({Tier.SINGLE_TARGET, Tier.BROADCAST}),
        )
    )
    yield
    gate.clear_engagement()



def _fakes(calls: list[str], *, captured: bool = True, cracked: bool = True):
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
        return CrackResult(bssid=bssid, cracked=cracked,
                           password="hunter2" if cracked else None)

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
    assert "crack" not in calls  # chain stops at the failed capture step
    assert ctx.password is None
    # on_error defaults to STOP: capture FAILED and the executor halts, so crack
    # is never reached or recorded.
    assert result.steps["capture_handshake"].status is StepStatus.FAILED
    assert "crack_handshake" not in result.steps


def test_no_handshake_captured_fails_before_crack():
    calls: list[str] = []
    ctx = AutoContext(interface="wlan0", target_bssid="AA:BB:CC:DD:EE:FF",
                      channel=6, wordlist="wl")
    result, _ = _run(ctx, _fakes(calls, captured=False))
    assert not result.success
    assert "crack" not in calls
    assert result.steps["capture_handshake"].status is StepStatus.FAILED
    assert "crack_handshake" not in result.steps


def test_passphrase_not_in_wordlist_fails_the_chain():
    # crack_handshake returns cracked=False without raising; the chain must not
    # report success on a missed passphrase.
    calls: list[str] = []
    ctx = AutoContext(interface="wlan0", target_bssid="AA:BB:CC:DD:EE:FF",
                      channel=6, wordlist="wl")
    result, _ = _run(ctx, _fakes(calls, cracked=False))
    assert not result.success
    assert calls == ["enable", "scan", "capture", "crack"]
    assert ctx.password is None
    assert result.steps["crack_handshake"].status is StepStatus.FAILED


def test_build_reuses_canonical_manifest_metadata():
    # runners attached, but provides/requires match the canonical WIFI_MANIFESTS
    from netreaper.wireless.manifests import WIFI_MANIFESTS
    reg = build_wifi_registry(AutoContext(interface="wlan0"))
    for m in WIFI_MANIFESTS:
        built = reg.get(m.name)
        assert built.provides == m.provides and built.requires == m.requires
        assert built.runner is not None


# --- CLI `wifi auto` -------------------------------------------------------

runner = CliRunner()


def test_cli_wifi_auto_dry_run_prints_plan_and_does_not_execute():
    result = runner.invoke(app, ["wifi", "auto", "-i", "wlan0"])
    assert result.exit_code == 0
    assert "crack_handshake" in result.stdout
    assert "Dry run" in result.stdout


def test_cli_wifi_auto_unresolvable_goal_exits_2():
    result = runner.invoke(app, ["wifi", "auto", "-i", "wlan0", "-g", "wifi.nonexistent"])
    assert result.exit_code == 2
