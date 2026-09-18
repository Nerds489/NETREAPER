# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Attached-device enumeration for iOS and Android (#33)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.safety.scope import Tier

logger = get_logger(__name__)

# Reads only. Everything that writes to a device is refused by name.
IOS_READ_BINARIES = frozenset({"idevice_id", "ideviceinfo", "idevicediagnostics"})
ANDROID_READ_BINARIES = frozenset({"adb"})

REFUSED_DEVICE_WRITERS = frozenset(
    {"idevicerestore", "idevicebackup2", "fastboot", "heimdall", "odin"}
)


@dataclass
class MobileDevice:
    udid: str
    platform: str
    name: str = ""
    properties: dict[str, str] = field(default_factory=dict)


def _guard(binary: str, permitted: frozenset[str]) -> None:
    if binary in REFUSED_DEVICE_WRITERS:
        raise ValueError(
            f"{binary} writes to or re-images a device and is deliberately not "
            f"available: bricking hardware is not an outcome an authorisation "
            f"tier makes acceptable. Enumeration and property reads only."
        )
    if binary not in permitted:
        raise ValueError(
            f"{binary} is not a permitted binary here; "
            f"allowed: {', '.join(sorted(permitted))}"
        )


class IosTool:
    """libimobiledevice reads. host_action: a USB device is not a network target."""

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or get_process_runner()

    async def list_devices(self) -> list[MobileDevice]:
        _guard("idevice_id", IOS_READ_BINARIES)
        res = await self._runner.run(
            ["idevice_id", "-l"], host_action=True, tier=Tier.PASSIVE, timeout=30
        )
        return [
            MobileDevice(udid=line.strip(), platform="ios")
            for line in res.stdout.splitlines()
            if line.strip()
        ]

    async def info(self, udid: str) -> MobileDevice:
        _guard("ideviceinfo", IOS_READ_BINARIES)
        res = await self._runner.run(
            ["ideviceinfo", "-u", udid],
            host_action=True,
            tier=Tier.PASSIVE,
            timeout=30,
        )
        props = dict(
            re.findall(r"^([A-Za-z0-9_]+):\s*(.*)$", res.stdout, re.MULTILINE)
        )
        return MobileDevice(
            udid=udid,
            platform="ios",
            name=props.get("DeviceName", ""),
            properties=props,
        )


class AndroidTool:
    """adb reads. The Android counterpart asked for alongside libimobiledevice."""

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or get_process_runner()

    async def list_devices(self) -> list[MobileDevice]:
        _guard("adb", ANDROID_READ_BINARIES)
        res = await self._runner.run(
            ["adb", "devices", "-l"], host_action=True, tier=Tier.PASSIVE, timeout=30
        )
        out: list[MobileDevice] = []
        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                model = re.search(r"model:(\S+)", line)
                out.append(
                    MobileDevice(
                        udid=parts[0],
                        platform="android",
                        name=model.group(1) if model else "",
                    )
                )
        return out

    async def properties(self, serial: str) -> MobileDevice:
        _guard("adb", ANDROID_READ_BINARIES)
        res = await self._runner.run(
            ["adb", "-s", serial, "shell", "getprop"],
            host_action=True,
            tier=Tier.PASSIVE,
            timeout=45,
        )
        props = dict(
            re.findall(r"^\[([^\]]+)\]:\s*\[([^\]]*)\]$", res.stdout, re.MULTILINE)
        )
        return MobileDevice(
            udid=serial,
            platform="android",
            name=props.get("ro.product.model", ""),
            properties=props,
        )


async def list_all_devices() -> list[MobileDevice]:
    """Every attached device across both platforms; a missing toolchain is not
    an error, it just contributes nothing."""
    from netreaper.core.exceptions import SubprocessError, ToolNotFoundError

    found: list[MobileDevice] = []
    for tool in (IosTool(), AndroidTool()):
        try:
            found.extend(await tool.list_devices())
        except (SubprocessError, ToolNotFoundError) as e:
            logger.debug("%s unavailable: %s", type(tool).__name__, e)
    return found
