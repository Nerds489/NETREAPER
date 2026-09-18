# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""AUTO-MON handler for monitor mode management."""

import asyncio
import shutil
from pathlib import Path

from netreaper.automation.handlers._host import run_host
from netreaper.automation.labels import AUTO_REGISTRY
from netreaper.core.validation import require_interface


class AutoMonHandler:
    """Handles AUTO-MON for enabling monitor mode."""

    def __init__(self, interface: str = "") -> None:
        self.interface = interface
        self.monitor_interface: str | None = None

    async def can_fix(self) -> bool:
        """Check if we can enable monitor mode."""
        # Need airmon-ng or iw
        has_airmon = shutil.which("airmon-ng") is not None
        has_iw = shutil.which("iw") is not None

        if not (has_airmon or has_iw):
            return False

        # Need an interface
        if not self.interface:
            interfaces = await self._get_wireless_interfaces()
            return len(interfaces) > 0

        return True

    async def fix(self) -> bool:
        """Enable monitor mode on the interface."""
        if not self.interface:
            interfaces = await self._get_wireless_interfaces()
            if not interfaces:
                return False
            self.interface = interfaces[0]

        # Try airmon-ng first
        if shutil.which("airmon-ng"):
            return await self._enable_with_airmon()
        elif shutil.which("iw"):
            return await self._enable_with_iw()

        return False

    async def get_ui_prompt(self) -> str:
        """Get the UI prompt for this fix."""
        if self.interface:
            return f"Enable monitor mode on {self.interface}?"
        return "Enable monitor mode on wireless interface?"

    @staticmethod
    async def _get_wireless_interfaces() -> list[str]:
        """Get list of wireless interfaces."""
        interfaces = []
        wireless_path = Path("/sys/class/net")

        if wireless_path.exists():
            for iface_path in wireless_path.iterdir():
                wireless_dir = iface_path / "wireless"
                if wireless_dir.exists():
                    interfaces.append(iface_path.name)

        return interfaces

    async def _enable_with_airmon(self) -> bool:
        """Enable monitor mode using airmon-ng."""
        iface = require_interface(self.interface)
        # Kill interfering processes, then enable monitor mode.
        await run_host(["airmon-ng", "check", "kill"], destructive=True)
        await run_host(["airmon-ng", "start", iface], destructive=True)

        # Find the new monitor interface
        await asyncio.sleep(1)
        self.monitor_interface = await self._find_monitor_interface()

        return self.monitor_interface is not None

    async def _enable_with_iw(self) -> bool:
        """Enable monitor mode using iw."""
        iface = require_interface(self.interface)
        await run_host(["ip", "link", "set", iface, "down"], destructive=True)
        result = await run_host(
            ["iw", "dev", iface, "set", "type", "monitor"], destructive=True
        )
        await run_host(["ip", "link", "set", iface, "up"], destructive=True)

        if result is not None and result.ok:
            self.monitor_interface = iface
            return True

        return False

    async def _find_monitor_interface(self) -> str | None:
        """Find the monitor mode interface."""
        # Check for common naming patterns
        patterns = [
            f"{self.interface}mon",
            f"mon{self.interface[-1]}",
            "wlan0mon",
            "wlan1mon",
        ]

        for pattern in patterns:
            iface_path = Path(f"/sys/class/net/{pattern}")
            if iface_path.exists():
                return pattern

        # Fall back to original interface
        return self.interface

    async def disable_monitor_mode(self) -> bool:
        """Disable monitor mode and restore managed mode."""
        if not self.monitor_interface:
            return False

        iface = require_interface(self.monitor_interface)

        if shutil.which("airmon-ng"):
            result = await run_host(["airmon-ng", "stop", iface], destructive=True)
            # Restart network manager
            await run_host(["systemctl", "start", "NetworkManager"], destructive=True)
            return result is not None and result.ok

        elif shutil.which("iw"):
            await run_host(["ip", "link", "set", iface, "down"], destructive=True)
            result = await run_host(
                ["iw", "dev", iface, "set", "type", "managed"], destructive=True
            )
            await run_host(["ip", "link", "set", iface, "up"], destructive=True)
            return result is not None and result.ok

        return False


# Register the handler
AUTO_REGISTRY.register("AUTO-MON", AutoMonHandler)
