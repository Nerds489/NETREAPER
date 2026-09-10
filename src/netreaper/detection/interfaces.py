# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Wireless interface detection and capability probing.

All shell-outs go through the ProcessRunner seam (target-less, passive), so even
detection is uniform with the rest of the framework. Parsing is defensive: a
missing tool or odd output yields a best-effort interface rather than a crash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from netreaper.core.exceptions import TargetValidationError
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.safety.scope import Tier

# Drivers known to support monitor mode + injection (best-effort scoring).
_INJECTION_DRIVERS = {
    "ath9k_htc", "ath9k", "rt2800usb", "rtl8187", "carl9170",
    "rtl8812au", "rtl8814au", "rtl8821au", "mt76x2u", "mt7601u", "mt76",
}


@dataclass
class NetworkInterface:
    name: str
    is_wireless: bool = False
    current_mode: str = "unknown"      # managed | monitor | ...
    driver: str = ""
    mac: str = ""
    phy: str = ""
    supports_monitor: bool = False
    supports_injection: bool = False

    @classmethod
    async def from_name(cls, name: str, runner: ProcessRunner | None = None) -> NetworkInterface:
        runner = runner or get_process_runner()
        iface = cls(name=name)
        iface.driver = _read_driver(name)
        iface.mac = _read_mac(name)
        iface.is_wireless = _is_wireless(name)

        # mode + phy from `iw dev`
        dev = await _run(runner, ["iw", "dev"])
        iface.current_mode, iface.phy = _parse_iw_dev_for(dev, name)
        if iface.phy:
            info = await _run(runner, ["iw", "phy", iface.phy, "info"])
            iface.supports_monitor = "* monitor" in info or "monitor" in _supported_modes(info)
        iface.supports_injection = iface.supports_monitor and iface.driver in _INJECTION_DRIVERS
        return iface


async def _run(runner: ProcessRunner, cmd: list[str]) -> str:
    try:
        res = await runner.run(cmd, tier=Tier.PASSIVE)
        return res.stdout
    except Exception:
        return ""


def _read_driver(name: str) -> str:
    link = Path(f"/sys/class/net/{name}/device/driver")
    try:
        return link.resolve().name if link.exists() else ""
    except OSError:
        return ""


def _read_mac(name: str) -> str:
    try:
        return Path(f"/sys/class/net/{name}/address").read_text().strip()
    except OSError:
        return ""


def _is_wireless(name: str) -> bool:
    return Path(f"/sys/class/net/{name}/wireless").exists() or Path(f"/sys/class/net/{name}/phy80211").exists()


def _parse_iw_dev_for(iw_dev_output: str, name: str) -> tuple[str, str]:
    """Return (mode, phy) for `name` from `iw dev` output."""
    mode, phy = "unknown", ""
    current_phy = ""
    in_iface = False
    for line in iw_dev_output.splitlines():
        s = line.strip()
        m = re.match(r"phy#(\d+)", s)
        if m:
            current_phy = f"phy{m.group(1)}"
            continue
        if s.startswith("Interface "):
            in_iface = s.split(None, 1)[1] == name
            if in_iface:
                phy = current_phy
            continue
        if in_iface and s.startswith("type "):
            mode = s.split(None, 1)[1]
    return mode, phy


def _supported_modes(iw_phy_info: str) -> set[str]:
    modes: set[str] = set()
    capture = False
    for line in iw_phy_info.splitlines():
        s = line.strip()
        if s.startswith("Supported interface modes"):
            capture = True
            continue
        if capture:
            if s.startswith("*"):
                modes.add(s.lstrip("* ").strip())
            elif s and not s.startswith("*"):
                break
    return modes


async def list_wireless_interfaces(runner: ProcessRunner | None = None) -> list[NetworkInterface]:
    runner = runner or get_process_runner()
    dev = await _run(runner, ["iw", "dev"])
    names = re.findall(r"^\s*Interface\s+(\S+)", dev, re.MULTILINE)
    result = []
    for n in names:
        iface = await NetworkInterface.from_name(n, runner=runner)
        if iface.is_wireless or iface.phy:
            result.append(iface)
    return result


async def validate_wireless_interface(name: str, runner: ProcessRunner | None = None) -> NetworkInterface:
    iface = await NetworkInterface.from_name(name, runner=runner)
    if not (iface.is_wireless or iface.phy):
        raise TargetValidationError(f"{name} is not a wireless interface")
    return iface


__all__ = [
    "NetworkInterface",
    "list_wireless_interfaces",
    "validate_wireless_interface",
]
