# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Automotive capability manifests for the backward-chaining planner (#33).

The chain the planner can resolve toward a readable bus capture:

    list_can_interfaces -> capture_can_frames -> decode_can_frames

Every step is read-only. No manifest declares a capability that transmits, and
none is marked destructive, because nothing here writes to a bus.
"""
from __future__ import annotations

from netreaper.chaining.manifest import ToolManifest

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
