# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Built-in credential chains. Definitions land as credential capabilities are
migrated; this registers none yet so the chaining system loads cleanly."""
from __future__ import annotations


def register_credential_chains() -> None:
    """Register built-in credential chains (none yet)."""
    return None


__all__ = ["register_credential_chains"]
