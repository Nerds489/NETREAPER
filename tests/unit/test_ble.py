# SPDX-License-Identifier: GPL-3.0-or-later
"""The BLE domain: manifests-first, with a gated GATT step (#33 slice 3, #92).

BLE follows automotive (a domain shipped as manifests the planner can resolve
before any adapter drives it) and web (a CLI verb over the chain). No live
adapter ships yet -- a correct BLE adapter needs on-hardware verification, and
bluetoothctl is an interactive REPL -- so the runners are planning-only. What is
proven here is that the chain resolves, that the CLI verb previews it, and that
`enumerate_gatt`'s requires_confirmation is enforced at the process seam, not
merely rendered as a badge.
"""
from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from netreaper.ble.autochain import build_ble_registry
from netreaper.ble.manifests import BLE_MANIFESTS, register_ble_manifests
from netreaper.chaining.manifest import ManifestRegistry, resolve_chain
from netreaper.chaining.models import ChainStep
from netreaper.chaining.plan_exec import manifest_step_runner
from netreaper.cli import app
from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate

runner = CliRunner()


# ── manifests and planning ────────────────────────────────────────────────────


def test_the_chain_resolves_scan_then_enumerate():
    plan = resolve_chain("ble.gatt_services", build_ble_registry())
    assert [m.name for m in plan.steps] == ["scan_le_devices", "enumerate_gatt"]


def test_a_scan_only_goal_is_one_step():
    plan = resolve_chain("ble.devices", build_ble_registry())
    assert [m.name for m in plan.steps] == ["scan_le_devices"]


def test_a_known_scan_short_circuits_to_enumerate():
    plan = resolve_chain(
        "ble.gatt_services", build_ble_registry(), available={"ble.devices"}
    )
    assert [m.name for m in plan.steps] == ["enumerate_gatt"]


def test_the_scan_is_passive_and_the_gatt_step_needs_confirmation():
    by_name = {m.name: m for m in BLE_MANIFESTS}
    assert by_name["scan_le_devices"].requires_confirmation is False
    assert by_name["enumerate_gatt"].requires_confirmation is True
    # Nothing here is destructive; BLE recon reads.
    assert not any(m.destructive for m in BLE_MANIFESTS)


def test_the_registrar_registers_the_manifests():
    reg = ManifestRegistry()
    register_ble_manifests(reg)
    assert reg.find_provider("ble.gatt_services") is not None


# ── the confirmation gate actually binds (acceptance: not just a badge) ───────


async def _fake_runner(state, target):
    return {"ble.gatt_services": "enumerated"}


def _gatt_registry():
    """enumerate_gatt with a runner attached, so the step reaches the gate."""
    import dataclasses

    gatt = next(m for m in BLE_MANIFESTS if m.name == "enumerate_gatt")
    reg = ManifestRegistry()
    reg.register(dataclasses.replace(gatt, requires=(), runner=_fake_runner))
    return reg


def _run_gatt(reg, target="AA:BB:CC:DD:EE:FF"):
    return asyncio.run(
        manifest_step_runner(reg)(ChainStep(id="s", tool="enumerate_gatt"), target, {})
    )


def _eng(**kw):
    return Engagement(
        operator="t",
        authorization_ref="SOW-1",
        scope=Scope(bssids={"AA:BB:CC:DD:EE:FF"}),
        max_tier=Tier.MITM,
        **kw,
    )


@pytest.fixture(autouse=True)
def _clear_engagement():
    yield
    get_scope_gate().clear_engagement()


def test_enumerate_gatt_is_refused_without_an_engagement():
    get_scope_gate().clear_engagement()
    with pytest.raises(TargetValidationError, match="no active engagement"):
        _run_gatt(_gatt_registry())


def test_enumerate_gatt_is_refused_without_the_confirmation_grant():
    get_scope_gate().set_engagement(_eng())
    with pytest.raises(TargetValidationError, match="requires confirmation"):
        _run_gatt(_gatt_registry())


def test_enumerate_gatt_runs_once_confirmed():
    get_scope_gate().set_engagement(
        _eng(confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))
    )
    assert _run_gatt(_gatt_registry()) == {"ble.gatt_services": "enumerated"}


def test_a_planning_only_step_refuses_to_spawn_rather_than_pretending():
    """With no runner wired, the step is refused with a clear reason, not silently
    treated as run."""
    from netreaper.core.exceptions import PluginError

    reg = build_ble_registry()  # planning-only, no runners
    with pytest.raises(PluginError, match="no runner"):
        asyncio.run(
            manifest_step_runner(reg)(
                ChainStep(id="s", tool="scan_le_devices"), "", {}
            )
        )


# ── the CLI verb ──────────────────────────────────────────────────────────────


def test_cli_ble_plan_previews_the_chain():
    result = runner.invoke(app, ["ble", "plan", "ble.gatt_services"])
    assert result.exit_code == 0
    assert "scan_le_devices" in result.stdout
    assert "enumerate_gatt" in result.stdout


def test_cli_ble_plan_defaults_to_the_full_goal():
    result = runner.invoke(app, ["ble", "plan"])
    assert result.exit_code == 0
    assert "enumerate_gatt" in result.stdout


def test_cli_ble_plan_unknown_goal_exits_2():
    result = runner.invoke(app, ["ble", "plan", "ble.nope"])
    assert result.exit_code == 2


def test_cli_ble_plan_have_skips_the_scan():
    result = runner.invoke(app, ["ble", "plan", "ble.gatt_services", "--have", "ble.devices"])
    assert result.exit_code == 0
    assert "scan_le_devices" not in result.stdout
    assert "enumerate_gatt" in result.stdout
