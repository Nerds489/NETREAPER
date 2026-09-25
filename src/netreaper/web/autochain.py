# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Wire the web recon manifests to their tool adapters (#33, slice 2).

The wireless equivalent is wireless/autochain.py: manifests declare the ordering,
this binds each one to a runner that drives the real adapter. Every adapter's
own execute() goes through the gated ProcessRunner, so each step is scope-gated
and audited exactly like a hand-typed `web dirs` / `web fingerprint`.

A runner returns ``{capability: value}`` keyed by the capability it provides, the
same convention the wireless runners use, so a later slice could feed those back
as available state. Web results are not durable (a site changes), so unlike wifi
they are not persisted to the state cache; the chain just threads them through.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

from netreaper.chaining.manifest import ManifestRegistry
from netreaper.core.exceptions import PluginError
from netreaper.web.manifests import WEB_MANIFESTS


def _why(res: Any) -> str:
    """A short failure reason from a tool result, for the raised error."""
    return "; ".join(res.errors) or "no output"


@dataclass
class WebContext:
    """The mutable state a web recon chain threads through its runners."""

    target: str  # the URL under assessment
    wordlist: str | None = None
    fingerprint: Any = None
    paths: Any = field(default=None)
    findings: Any = field(default=None)


def build_web_registry(ctx: WebContext | None = None) -> ManifestRegistry:
    """Register the web manifests with runners bound to the real adapters.

    ``ctx`` may be None for a planning-only registry (dry run / `web plan`),
    matching build_wifi_registry(None): the manifests still resolve, the runners
    just are not attached.
    """
    reg = ManifestRegistry()
    if ctx is None:
        for m in WEB_MANIFESTS:
            reg.register(m)
        return reg

    async def r_fingerprint(_state: dict, _target: str) -> dict[str, Any]:
        from netreaper.tools.whatweb import WhatWebTool

        res = await WhatWebTool().execute(ctx.target, {})
        if not res.success:
            raise PluginError(f"fingerprint failed: {_why(res)}")
        ctx.fingerprint = res.data
        return {"web.fingerprint": ctx.fingerprint}

    async def r_paths(_state: dict, _target: str) -> dict[str, Any]:
        from netreaper.tools.gobuster import GobusterTool

        opts = {"wordlist": ctx.wordlist} if ctx.wordlist else {}
        res = await GobusterTool().execute(ctx.target, opts)
        if not res.success:
            raise PluginError(f"path enumeration failed: {_why(res)}")
        ctx.paths = res.data
        return {"web.paths": ctx.paths}

    async def r_findings(_state: dict, _target: str) -> dict[str, Any]:
        from netreaper.tools.nikto import NiktoTool

        res = await NiktoTool().execute(ctx.target, {})
        if not res.success:
            raise PluginError(f"web scan failed: {_why(res)}")
        ctx.findings = res.data
        return {"web.findings": ctx.findings}

    runners = {
        "fingerprint_web": r_fingerprint,
        "enumerate_paths": r_paths,
        "scan_web": r_findings,
    }
    for m in WEB_MANIFESTS:
        reg.register(dataclasses.replace(m, runner=runners[m.name]))
    return reg


__all__ = ["WebContext", "build_web_registry"]
