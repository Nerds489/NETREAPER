# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Automotive capability manifests for the backward-chaining planner (#33).

The chain the planner can resolve toward a readable bus capture:

    list_can_interfaces -> capture_can_frames -> decode_can_frames

Every step is read-only. No manifest declares a capability that transmits, and
none is marked destructive, because nothing here writes to a bus.
"""
from __future__ import annotations

import dataclasses

from netreaper.chaining.manifest import ManifestRegistry, ToolManifest

AUTOMOTIVE_MANIFESTS: tuple[ToolManifest, ...] = (
    ToolManifest(
        name="list_can_interfaces",
        domain="automotive",
        provides=("automotive.can_interface",),
        requires=(),
        needs_hardware=True,
    ),
    ToolManifest(
        name="capture_can_frames",
        domain="automotive",
        provides=("automotive.can_capture",),
        requires=("automotive.can_interface",),
        needs_hardware=True,
    ),
    ToolManifest(
        name="decode_can_frames",
        domain="automotive",
        provides=("automotive.decoded_signals",),
        requires=("automotive.can_capture", "automotive.can_id_database"),
        needs_hardware=False,
    ),
)


def build_automotive_registry(runner_map: dict | None = None) -> ManifestRegistry:
    """Register the automotive manifests, with runners when supplied.

    AUTOMOTIVE_MANIFESTS was declared and never registered anywhere, which is
    exactly the defect this codebase keeps producing: a declaration with no path
    to it. wireless/autochain.py does this for WIFI_MANIFESTS; this is the
    automotive equivalent.

    Runners are optional because two of the three steps need real hardware. A
    manifest with no runner is planning-only and the step runner says so
    plainly, which is better than a registry that silently holds nothing.
    """
    runner_map = runner_map or {}
    reg = ManifestRegistry()
    for m in AUTOMOTIVE_MANIFESTS:
        runner = runner_map.get(m.name)
        reg.register(dataclasses.replace(m, runner=runner) if runner else m)
    return reg


__all__ = ["AUTOMOTIVE_MANIFESTS", "build_automotive_registry"]
