# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Monitor-mode lifecycle as a small state machine.

Fixes the classic wireless-tool bugs: the real monitor interface is resolved by
diffing ``iw dev`` before/after (works for the ``wlan0``->``wlan0mon`` rename AND
for mt76/rtl8812au drivers that keep the same name), and teardown is idempotent
and runs on exit, restoring managed mode and NetworkManager if we stopped it.
All shell-outs go through the ProcessRunner seam.
"""
from __future__ import annotations

import asyncio
import atexit
import re
from enum import Enum

from netreaper.core.exceptions import NetreaperError
from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.detection.interfaces import NetworkInterface, validate_wireless_interface
from netreaper.safety.scope import Tier

logger = get_logger(__name__)


class MonitorModeError(NetreaperError):
    """Monitor-mode operation failed."""


class MonitorState(str, Enum):
    UNKNOWN = "unknown"
    MANAGED = "managed"
    MONITOR = "monitor"


class MonitorController:
    """Owns the monitor-mode lifecycle for one adapter, with safe teardown."""

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or get_process_runner()
        self.state = MonitorState.UNKNOWN
        self.managed_iface: str | None = None
        self.monitor_iface: str | None = None
        self._killed_network_manager = False

    async def _iface_names(self) -> set[str]:
        res = await self._runner.run(["iw", "dev"], tier=Tier.PASSIVE)
        return set(re.findall(r"^\s*Interface\s+(\S+)", res.stdout, re.MULTILINE))

    async def enable(self, interface: str, *, kill_processes: bool = True) -> str:
        iface = await validate_wireless_interface(interface, runner=self._runner)
        if iface.current_mode == "monitor":
            self.state = MonitorState.MONITOR
            self.monitor_iface = interface
            self.managed_iface = interface
            return interface

        before = await self._iface_names()
        if kill_processes:
            await self._runner.run(["airmon-ng", "check", "kill"], tier=Tier.PASSIVE)
            self._killed_network_manager = True
        await self._runner.run(["airmon-ng", "start", interface], tier=Tier.PASSIVE)
        after = await self._iface_names()

        # Resolve the real monitor interface by diff (not by name-guessing).
        new = after - before
        if len(new) == 1:
            self.monitor_iface = next(iter(new))
        elif interface in after:
            self.monitor_iface = interface  # same-name monitor (mt76/rtl8812au)
        else:
            raise MonitorModeError(
                f"could not resolve the monitor interface after enabling on {interface} "
                f"(before={sorted(before)} after={sorted(after)})"
            )
        self.managed_iface = interface
        self.state = MonitorState.MONITOR
        logger.info("monitor mode enabled: %s -> %s", interface, self.monitor_iface)
        return self.monitor_iface

    async def disable(self) -> None:
        """Idempotent: safe to call when not in monitor mode."""
        if self.state is not MonitorState.MONITOR or not self.monitor_iface:
            return
        try:
            await self._runner.run(["airmon-ng", "stop", self.monitor_iface], tier=Tier.PASSIVE)
        finally:
            if self._killed_network_manager:
                # best-effort: bring NetworkManager back
                try:
                    await self._runner.run(
                        ["systemctl", "restart", "NetworkManager"], tier=Tier.PASSIVE
                    )
                except Exception:
                    logger.warning("could not restart NetworkManager during teardown")
                self._killed_network_manager = False
            self.state = MonitorState.MANAGED
            self.monitor_iface = None

    async def teardown(self) -> None:
        await self.disable()


_controller = MonitorController()


def _atexit_teardown() -> None:
    if _controller.state is MonitorState.MONITOR:
        try:
            asyncio.run(_controller.teardown())
        except Exception:
            pass


atexit.register(_atexit_teardown)


async def enable_monitor_mode(interface: str, kill_processes: bool = True) -> str:
    return await _controller.enable(interface, kill_processes=kill_processes)


async def disable_monitor_mode(interface: str | None = None) -> None:
    await _controller.disable()


async def get_monitor_status(interface: str) -> dict:
    iface = await NetworkInterface.from_name(interface)
    return {
        "interface": interface,
        "is_wireless": iface.is_wireless,
        "current_mode": iface.current_mode,
        "is_monitor": iface.current_mode == "monitor",
        "driver": iface.driver,
        "supports_monitor": iface.supports_monitor,
        "supports_injection": iface.supports_injection,
    }


__all__ = [
    "MonitorController",
    "MonitorModeError",
    "MonitorState",
    "disable_monitor_mode",
    "enable_monitor_mode",
    "get_monitor_status",
]
