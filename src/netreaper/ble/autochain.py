# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Build a BLE manifest registry, with runners when they exist (#92).

Mirrors build_automotive_registry: the manifests resolve for planning with no
runners attached, and a runner_map can bind them when real, hardware-verified
adapters are added. Nothing supplies runners today (see ble/manifests.py for
why), so this returns a planning-only registry, which `ble plan` uses.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from netreaper.ble.manifests import BLE_MANIFESTS
from netreaper.chaining.manifest import ManifestRegistry


@dataclass
class BLEContext:
    """State a BLE chain would thread through its runners once they exist."""

    target: str | None = None  # a device address for the GATT step
    devices: Any = None
    gatt_services: Any = None


def build_ble_registry(
    runner_map: dict[str, Callable] | None = None,
) -> ManifestRegistry:
    """Register the BLE manifests, binding runners where supplied.

    Planning-only by default: a manifest with no runner resolves for the preview
    and `manifest_step_runner` refuses to spawn it (saying so plainly), rather
    than a registry that silently holds nothing.
    """
    runner_map = runner_map or {}
    reg = ManifestRegistry()
    for m in BLE_MANIFESTS:
        runner = runner_map.get(m.name)
        reg.register(dataclasses.replace(m, runner=runner) if runner else m)
    return reg


__all__ = ["BLEContext", "build_ble_registry"]
