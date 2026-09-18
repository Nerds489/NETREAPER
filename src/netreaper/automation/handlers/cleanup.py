# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""AUTO-CLEANUP handler for restoring system state."""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from netreaper.automation.handlers._host import run_host
from netreaper.automation.labels import AUTO_REGISTRY
from netreaper.core.exceptions import TargetValidationError
from netreaper.core.logging import get_logger
from netreaper.core.validation import require_interface

logger = get_logger(__name__)


@dataclass
class CleanupAction:
    """A cleanup action to be performed."""

    name: str
    action: Callable[[], Any]
    priority: int = 0  # Higher = execute first


class AutoCleanupHandler:
    """Handles AUTO-CLEANUP for restoring system state after operations."""

    # Class-level cleanup stack shared across instances
    _cleanup_stack: list[CleanupAction] = []

    def __init__(self) -> None:
        pass

    async def can_fix(self) -> bool:
        """Check if there are cleanup actions to perform."""
        return len(self._cleanup_stack) > 0

    async def fix(self) -> bool:
        """Perform all cleanup actions."""
        return await self.cleanup_all()

    async def get_ui_prompt(self) -> str:
        """Get the UI prompt for cleanup."""
        count = len(self._cleanup_stack)
        if count == 0:
            return "No cleanup actions pending."
        return f"Perform {count} cleanup action(s)?"

    @classmethod
    def register_cleanup(
        cls,
        name: str,
        action: Callable[[], Any],
        priority: int = 0,
    ) -> None:
        """Register a cleanup action to be performed later."""
        cls._cleanup_stack.append(
            CleanupAction(name=name, action=action, priority=priority)
        )

    @classmethod
    async def cleanup_all(cls) -> bool:
        """Perform all cleanup actions in order."""
        # Sort by priority (higher first)
        actions = sorted(cls._cleanup_stack, key=lambda x: x.priority, reverse=True)
        cls._cleanup_stack.clear()

        success = True
        for action in actions:
            try:
                result = action.action()
                if asyncio.iscoroutine(result):
                    await result
                logger.debug('Cleanup action completed: %s', action.name)
            except TargetValidationError:
                raise  # a scope-gate denial is never swallowed
            except Exception as e:
                logger.warning('Cleanup action failed: %s: %s', action.name, e)
                success = False

        return success

    @classmethod
    def get_pending_actions(cls) -> list[str]:
        """Get list of pending cleanup action names."""
        return [action.name for action in cls._cleanup_stack]

    @classmethod
    def clear_cleanup_stack(cls) -> None:
        """Clear all pending cleanup actions without executing them."""
        cls._cleanup_stack.clear()

    # Common cleanup actions
    @classmethod
    async def restore_network_manager(cls) -> bool:
        """Restore NetworkManager service."""
        result = await run_host(
            ["systemctl", "start", "NetworkManager"], destructive=True
        )
        return result is not None and result.ok

    @classmethod
    async def restore_managed_mode(cls, interface: str) -> bool:
        """Restore interface to managed mode."""
        iface = require_interface(interface)
        commands = [
            ["ip", "link", "set", iface, "down"],
            ["iw", "dev", iface, "set", "type", "managed"],
            ["ip", "link", "set", iface, "up"],
        ]
        for cmd in commands:
            await run_host(cmd, destructive=True)
        return True

    @classmethod
    async def disable_ip_forwarding(cls) -> bool:
        """Disable IP forwarding."""
        result = await run_host(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"], destructive=True
        )
        return result is not None and result.ok

    @classmethod
    async def flush_iptables(cls) -> bool:
        """Flush iptables rules."""
        commands = [
            ["iptables", "-F"],
            ["iptables", "-t", "nat", "-F"],
            ["iptables", "-t", "mangle", "-F"],
        ]
        for cmd in commands:
            await run_host(cmd, destructive=True)
        return True

    # NOTE: killall-based stop_hostapd/stop_dnsmasq were removed. A global killall
    # takes down unrelated daemons (e.g. libvirt's dnsmasq); daemon teardown is
    # ownership-tracked via pidfile in EvilTwin._kill_by_pidfile instead.


# Register the handler
AUTO_REGISTRY.register("AUTO-CLEANUP", AutoCleanupHandler)
