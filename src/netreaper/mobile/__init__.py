# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Mobile domain: enumerate and read attached devices (#33).

iOS through libimobiledevice, Android through platform-tools, both driven via
the one gated spawn seam like any other external binary.

Read-only, and for the same reason the automotive domain is. `idevicerestore`
puts a device into a restore state and `fastboot flash` writes partitions; both
can brick hardware that is not ours to brick, and neither failure mode is
something a scope tier improves. Enumeration and property reads are wired.
Restore, flash and unlock are refused by name, and a test enforces it.
"""
from __future__ import annotations

from netreaper.mobile.devices import (
    AndroidTool,
    IosTool,
    MobileDevice,
    list_all_devices,
)

__all__ = ["AndroidTool", "IosTool", "MobileDevice", "list_all_devices"]
