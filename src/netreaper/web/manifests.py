# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Web recon capability manifests for the backward-chaining planner (#33, slice 2).

The first non-wireless domain the planner drives with tools that already ship
adapters. The chain toward a web assessment:

    fingerprint_web -> enumerate_paths
                    -> scan_web

FINGERPRINT FIRST IS A METHODOLOGY CHOICE, NOT A TECHNICAL ONE. gobuster and
nikto each only need the URL to run, so they could require nothing. They are
modelled as requiring `web.fingerprint` because identifying the stack before
probing it is ordinary recon practice, and it gives the planner a real chain to
resolve rather than three unrelated one-step goals. To let them run without a
prior fingerprint, drop `web.fingerprint` from their `requires` here; nothing
else changes.

Runners are wired in web/autochain.py, the same split wireless uses: this file
is the ordering and prerequisite declaration, autochain.py binds the adapters.
"""
from __future__ import annotations

from netreaper.chaining.manifest import (
    ManifestRegistry,
    ToolManifest,
    manifest_registry,
)

WEB_MANIFESTS: tuple[ToolManifest, ...] = (
    ToolManifest(
        name="fingerprint_web",
        domain="web",
        provides=("web.fingerprint",),
        requires=(),
    ),
    ToolManifest(
        name="enumerate_paths",
        domain="web",
        provides=("web.paths",),
        requires=("web.fingerprint",),
    ),
    ToolManifest(
        name="scan_web",
        domain="web",
        provides=("web.findings",),
        requires=("web.fingerprint",),
    ),
    # ffuf and nuclei each provide a DISTINCT capability, not web.paths /
    # web.findings: the planner allows one provider per capability, and these are
    # genuinely different techniques from gobuster (wordlist path brute) and nikto
    # (built-in checks). See #93.
    ToolManifest(
        name="fuzz_web",
        domain="web",
        provides=("web.fuzz",),
        requires=("web.fingerprint",),
    ),
    ToolManifest(
        name="scan_templates",
        domain="web",
        provides=("web.templated_findings",),
        requires=("web.fingerprint",),
    ),
)


def register_web_manifests(
    registry: ManifestRegistry = manifest_registry, *, replace: bool = True
) -> None:
    """Register the built-in web manifests. Idempotent when ``replace`` is True."""
    for m in WEB_MANIFESTS:
        registry.register(m, replace=replace)


__all__ = ["WEB_MANIFESTS", "register_web_manifests"]
