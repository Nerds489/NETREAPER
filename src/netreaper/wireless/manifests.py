# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""WiFi capability manifests for the backward-chaining planner (design doc §WiFi).

The four wireless capabilities the planner chains toward ``wifi.password``:

    enable_monitor_mode -> scan_networks -> capture_handshake -> crack_handshake

Runners are not wired here (this is the planning slice): the planner uses these
manifests for ordering, prerequisite resolution and the dry-run preview. Live
execution (compiling the plan into a ChainDefinition and feeding step outputs
back as available state) is a later slice.
"""
from __future__ import annotations

from netreaper.chaining.manifest import (
    ManifestRegistry,
    ToolManifest,
    manifest_registry,
)

WIFI_MANIFESTS: tuple[ToolManifest, ...] = (
    ToolManifest(
        name="enable_monitor_mode",
        domain="wifi",
        provides=("wifi.monitor_interface",),
        requires=(),
        needs_hardware=True,
    ),
    ToolManifest(
        name="scan_networks",
        domain="wifi",
        provides=("wifi.ssid_list", "wifi.bssid_list"),
        requires=("wifi.monitor_interface",),
        needs_hardware=True,
    ),
    ToolManifest(
        name="capture_handshake",
        domain="wifi",
        provides=("wifi.handshake",),
        requires=("wifi.monitor_interface", "wifi.bssid_list"),
        needs_hardware=True,
        destructive=True,  # sends a targeted deauth
        requires_confirmation=True,
    ),
    ToolManifest(
        name="crack_handshake",
        domain="wifi",
        provides=("wifi.password",),
        requires=("wifi.handshake",),
    ),
)


def register_wifi_manifests(
    registry: ManifestRegistry = manifest_registry, *, replace: bool = True
) -> None:
    """Register the built-in wifi manifests. Idempotent when ``replace`` is True."""
    for m in WIFI_MANIFESTS:
        registry.register(m, replace=replace)


__all__ = ["WIFI_MANIFESTS", "register_wifi_manifests"]
