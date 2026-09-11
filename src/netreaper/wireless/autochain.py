# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Live runners for the wifi capability chain, behind ``wifi auto``.

:func:`build_wifi_registry` returns a
:class:`~netreaper.chaining.manifest.ManifestRegistry` whose four wifi manifests
carry runners that adapt the real wireless functions (``enable_monitor_mode`` ->
``scan_networks`` -> ``capture_handshake`` -> ``crack_handshake``), threading
data through a shared :class:`AutoContext`. It reuses the canonical
``WIFI_MANIFESTS`` metadata (attaching runners via ``dataclasses.replace``) so
the planning and execution views cannot drift. The wireless functions are
injectable, so the orchestration is testable without a radio; the live path is
the already-gated wireless calls.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from netreaper.chaining.manifest import ManifestRegistry
from netreaper.core.exceptions import PluginError
from netreaper.wireless.crack import crack_handshake as _crack
from netreaper.wireless.handshake import capture_handshake as _capture
from netreaper.wireless.manifests import WIFI_MANIFESTS
from netreaper.wireless.monitor import enable_monitor_mode as _enable
from netreaper.wireless.scan import scan_networks as _scan

Fn = Callable[..., Awaitable[Any]]


@dataclass
class AutoContext:
    """Per-invocation parameters + the state threaded between chain steps."""

    interface: str
    target_bssid: str | None = None
    channel: int | None = None
    wordlist: str | None = None
    # filled in as the chain runs:
    monitor_interface: str | None = None
    cap_file: str | None = None
    password: str | None = None


def build_wifi_registry(
    ctx: AutoContext,
    *,
    enable: Fn = _enable,
    scan: Fn = _scan,
    capture: Fn = _capture,
    crack: Fn = _crack,
) -> ManifestRegistry:
    """Register the wifi manifests with live runners bound to ``ctx``."""

    async def r_monitor(state: dict[str, object], target: str) -> dict[str, object]:
        ctx.monitor_interface = await enable(ctx.interface)
        return {"wifi.monitor_interface": ctx.monitor_interface}

    async def r_scan(state: dict[str, object], target: str) -> dict[str, object]:
        if not ctx.monitor_interface:
            raise PluginError("monitor interface not established")
        res = await scan(ctx.monitor_interface)
        return {
            "wifi.bssid_list": [ap.bssid for ap in res.access_points],
            "wifi.ssid_list": [ap.essid for ap in res.access_points],
        }

    async def r_capture(state: dict[str, object], target: str) -> dict[str, object]:
        # Targets the operator-supplied BSSID/channel. The scan step's
        # wifi.bssid_list requirement only forces ordering; selecting the target
        # from the scan is a future enhancement (see #31).
        if not ctx.target_bssid or ctx.channel is None:
            raise PluginError("capture_handshake needs a target BSSID and channel")
        hs = await capture(ctx.monitor_interface, ctx.target_bssid, ctx.channel)
        if not hs.captured:
            raise PluginError(f"no handshake captured for {ctx.target_bssid}")
        ctx.cap_file = hs.cap_file
        return {"wifi.handshake": hs.cap_file}

    async def r_crack(state: dict[str, object], target: str) -> dict[str, object]:
        if not ctx.wordlist:
            raise PluginError("crack_handshake needs a wordlist")
        res = await crack(ctx.cap_file, ctx.target_bssid, ctx.wordlist)
        # crack_handshake returns cracked=False (not raises) when the passphrase
        # is not in the wordlist. Fail the step so the goal path is truthful:
        # result.success stays False and the CLI exits non-zero.
        if not res.cracked:
            raise PluginError(f"passphrase for {ctx.target_bssid} not in wordlist")
        ctx.password = res.password
        return {"wifi.password": res.password}

    runners: dict[str, Fn] = {
        "enable_monitor_mode": r_monitor,
        "scan_networks": r_scan,
        "capture_handshake": r_capture,
        "crack_handshake": r_crack,
    }
    reg = ManifestRegistry()
    for m in WIFI_MANIFESTS:
        reg.register(dataclasses.replace(m, runner=runners[m.name]))
    return reg


__all__ = ["AutoContext", "build_wifi_registry"]
