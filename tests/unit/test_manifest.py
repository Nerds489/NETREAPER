# SPDX-License-Identifier: GPL-3.0-or-later
"""Backward-chaining planner: manifests, resolve_chain, guards (design doc)."""
from __future__ import annotations

import pytest

from netreaper.chaining.manifest import (
    ManifestRegistry,
    MissingCapabilityError,
    ToolManifest,
    resolve_chain,
)
from netreaper.core.exceptions import ConfigurationError, PluginError
from netreaper.wireless.manifests import WIFI_MANIFESTS, register_wifi_manifests


def _wifi_registry() -> ManifestRegistry:
    reg = ManifestRegistry()
    register_wifi_manifests(reg)
    return reg


# --- resolve_chain over the wifi DAG ---


def test_full_chain_to_password_is_ordered():
    plan = resolve_chain("wifi.password", _wifi_registry())
    assert [m.name for m in plan.steps] == [
        "enable_monitor_mode",
        "scan_networks",
        "capture_handshake",
        "crack_handshake",
    ]


def test_partial_goal_resolves_a_subchain():
    # asking only for the bssid list needs monitor mode then scan
    plan = resolve_chain("wifi.bssid_list", _wifi_registry())
    assert [m.name for m in plan.steps] == ["enable_monitor_mode", "scan_networks"]


def test_available_state_short_circuits():
    # a handshake already captured -> only cracking remains
    plan = resolve_chain("wifi.password", _wifi_registry(), available={"wifi.handshake"})
    assert [m.name for m in plan.steps] == ["crack_handshake"]


def test_goal_already_satisfied_is_empty():
    plan = resolve_chain("wifi.password", _wifi_registry(), available={"wifi.password"})
    assert plan.steps == ()
    assert "already satisfied" in plan.render()


def test_no_tool_re_planned_twice():
    # monitor_interface is required by both scan and capture; enable runs once
    plan = resolve_chain("wifi.password", _wifi_registry())
    names = [m.name for m in plan.steps]
    assert names.count("enable_monitor_mode") == 1


# --- guards ---


def test_missing_capability_names_it():
    with pytest.raises(MissingCapabilityError) as exc:
        resolve_chain("wifi.password", ManifestRegistry())  # empty registry
    assert exc.value.capability == "wifi.password"
    assert "wifi.password" in str(exc.value)


def test_cycle_is_detected():
    reg = ManifestRegistry()
    reg.register(ToolManifest("a", "d", provides=("d.x",), requires=("d.y",)))
    reg.register(ToolManifest("b", "d", provides=("d.y",), requires=("d.x",)))
    with pytest.raises(PluginError, match="cycle"):
        resolve_chain("d.x", reg)


def test_collision_two_providers_of_one_capability():
    reg = ManifestRegistry()
    reg.register(ToolManifest("first", "wifi", provides=("wifi.pw",)))
    with pytest.raises(ConfigurationError, match="already provided by"):
        reg.register(ToolManifest("second", "wifi", provides=("wifi.pw",)))


def test_provides_must_be_in_domain_namespace():
    with pytest.raises(ConfigurationError, match="domain namespace"):
        ToolManifest("t", "wifi", provides=("web.thing",))


def test_requires_must_be_namespaced():
    with pytest.raises(ConfigurationError, match="namespaced"):
        ToolManifest("t", "wifi", requires=("nodot",))


# --- registry + render + registration ---


def test_render_lists_steps_with_flags():
    out = resolve_chain("wifi.password", _wifi_registry()).render()
    assert "4 step(s)" in out
    assert "capture_handshake" in out and "[destructive]" in out and "[hw]" in out


def test_register_wifi_manifests_is_idempotent():
    reg = ManifestRegistry()
    register_wifi_manifests(reg)
    register_wifi_manifests(reg)  # replace=True by default -> no collision
    assert len(reg.all()) == len(WIFI_MANIFESTS)


def test_find_provider_and_replace():
    reg = ManifestRegistry()
    reg.register(ToolManifest("v1", "wifi", provides=("wifi.k",)))
    assert reg.find_provider("wifi.k").name == "v1"
    reg.register(ToolManifest("v1", "wifi", provides=("wifi.k2",)), replace=True)
    assert reg.find_provider("wifi.k") is None
    assert reg.find_provider("wifi.k2").name == "v1"
