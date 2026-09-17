# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Automotive domain: read and decode a vehicle bus (#33).

The domain is analysis only. Reading a CAN bus and naming its signals is
information security; writing frames to a live vehicle is a physical-safety
action that a scope gate cannot make safe, so it is not implemented. The
reasoning is in :mod:`netreaper.tools.canutils`, and the boundary is enforced by
a test rather than trusted to a comment.
"""
from __future__ import annotations

from netreaper.automotive.decode import CanIdDatabase, decode_capture
from netreaper.automotive.manifests import (
    AUTOMOTIVE_MANIFESTS,
    build_automotive_registry,
)

__all__ = [
    "AUTOMOTIVE_MANIFESTS",
    "CanIdDatabase",
    "build_automotive_registry",
    "decode_capture",
]
