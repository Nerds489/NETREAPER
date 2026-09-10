# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Built-in wireless chains. Definitions land as the wireless capabilities are
migrated; this registers none yet so the chaining system loads cleanly."""
from __future__ import annotations


def register_wireless_chains() -> None:
    """Register built-in wireless chains (none yet)."""
    return None


__all__ = ["register_wireless_chains"]
