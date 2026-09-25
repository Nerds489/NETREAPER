# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""BLE capability manifests for the backward-chaining planner (#33, slice 3, #92).

A new domain shipped manifests-first, the way automotive CAN was: the planner can
resolve and preview the chain before any adapter drives it.

    scan_le_devices -> enumerate_gatt

WHY NO LIVE ADAPTERS YET. A correct BLE adapter needs a Bluetooth controller and
on-hardware verification: bluetoothctl is an interactive REPL, and whether a given
one-shot invocation emits parseable discovery output is BlueZ-version-sensitive.
Shipping a parser for output that cannot be verified here would be a guess, so the
runners are planning-only for now (build_ble_registry leaves them unset), exactly
as automotive's hardware steps are. Wiring real adapters is a follow-up that can
be tested against a controller.

POSTURE. A LE scan is passive: it listens for advertisements. Connecting to a
device and walking its GATT table is active and intrusive, so enumerate_gatt is
marked requires_confirmation -- and that flag is enforced at the process seam by
manifest_step_runner, not merely rendered as a badge (see the gate test).
"""
from __future__ import annotations

from netreaper.chaining.manifest import (
    ManifestRegistry,
    ToolManifest,
    manifest_registry,
)

BLE_MANIFESTS: tuple[ToolManifest, ...] = (
    ToolManifest(
        name="scan_le_devices",
        domain="ble",
        provides=("ble.devices",),
        requires=(),
        needs_hardware=True,  # a Bluetooth controller in LE scan mode
    ),
    ToolManifest(
        name="enumerate_gatt",
        domain="ble",
        provides=("ble.gatt_services",),
        requires=("ble.devices",),
        needs_hardware=True,
        # Connecting to a device and reading its GATT table is active, not a
        # passive listen. It must clear the confirmation gate like a wifi deauth.
        requires_confirmation=True,
    ),
)


def register_ble_manifests(
    registry: ManifestRegistry = manifest_registry, *, replace: bool = True
) -> None:
    """Register the built-in BLE manifests. Idempotent when ``replace`` is True."""
    for m in BLE_MANIFESTS:
        registry.register(m, replace=replace)


__all__ = ["BLE_MANIFESTS", "register_ble_manifests"]
