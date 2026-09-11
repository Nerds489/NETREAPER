# SPDX-License-Identifier: GPL-3.0-or-later
"""planner -> ChainExecutor bridge (plan_to_chain, manifest_step_runner)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.chaining.executor import ChainExecutor
from netreaper.chaining.manifest import ManifestRegistry, ToolManifest, resolve_chain
from netreaper.chaining.models import ChainStep
from netreaper.chaining.plan_exec import manifest_step_runner, plan_to_chain
from netreaper.core.exceptions import PluginError
from netreaper.wireless.manifests import register_wifi_manifests


def test_plan_to_chain_derives_dependency_edges():
    reg = ManifestRegistry()
    register_wifi_manifests(reg)
    chain = plan_to_chain(resolve_chain("wifi.password", reg))
    deps = {s.id: sorted(s.depends_on) for s in chain.steps}
    assert deps == {
        "enable_monitor_mode": [],
        "scan_networks": ["enable_monitor_mode"],
        "capture_handshake": ["enable_monitor_mode", "scan_networks"],
        "crack_handshake": ["capture_handshake"],
    }


def test_external_available_state_adds_no_edge():
    # with the handshake already available, only crack remains and it has no dep
    reg = ManifestRegistry()
    register_wifi_manifests(reg)
    chain = plan_to_chain(
        resolve_chain("wifi.password", reg, available={"wifi.handshake"})
    )
    assert [s.id for s in chain.steps] == ["crack_handshake"]
    assert chain.steps[0].depends_on == []


def test_execute_runs_in_dependency_order():
    calls: list[str] = []
    reg = ManifestRegistry()

    def mk(name: str):
        async def runner(state: dict, target: str) -> dict:
            calls.append(name)
            return {name: "done"}
        return runner

    reg.register(ToolManifest(
        "enable_monitor_mode", "wifi", provides=("wifi.monitor_interface",),
        runner=mk("enable_monitor_mode")))
    reg.register(ToolManifest(
        "scan_networks", "wifi", provides=("wifi.bssid_list",),
        requires=("wifi.monitor_interface",), runner=mk("scan_networks")))
    reg.register(ToolManifest(
        "capture_handshake", "wifi", provides=("wifi.handshake",),
        requires=("wifi.monitor_interface", "wifi.bssid_list"),
        runner=mk("capture_handshake")))
    reg.register(ToolManifest(
        "crack_handshake", "wifi", provides=("wifi.password",),
        requires=("wifi.handshake",), runner=mk("crack_handshake")))

    chain = plan_to_chain(resolve_chain("wifi.password", reg))
    result = asyncio.run(
        ChainExecutor(step_runner=manifest_step_runner(reg)).execute(chain)
    )
    assert result.success
    assert calls.index("enable_monitor_mode") < calls.index("scan_networks")
    assert calls.index("scan_networks") < calls.index("capture_handshake")
    assert calls.index("capture_handshake") < calls.index("crack_handshake")


def test_missing_runner_dispatch_raises():
    reg = ManifestRegistry()
    reg.register(ToolManifest("t", "wifi", provides=("wifi.x",)))  # runner=None
    runner = manifest_step_runner(reg)
    with pytest.raises(PluginError, match="no runner"):
        asyncio.run(runner(ChainStep(id="t", tool="t"), "", {}))
