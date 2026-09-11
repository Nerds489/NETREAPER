# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Validation for values interpolated into host commands.

Interface names reach subprocess argument lists from discovery, configuration
and UI state. Even though commands now run through exec argument arrays (never a
shell string), a strict grammar keeps a malformed or hostile name from ever
reaching a command in the first place.
"""
from __future__ import annotations

import re

from netreaper.core.exceptions import TargetValidationError

# Linux IFNAMSIZ is 16, so an interface name is at most 15 characters. Restrict
# to the kernel's real name grammar; anything else is refused before it runs.
# fullmatch (not match + $) is deliberate: $ would accept a trailing newline.
_IFACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")


def valid_interface_name(name: str) -> bool:
    """True when ``name`` is a syntactically valid network-interface name."""
    return bool(name) and name not in (".", "..") and _IFACE_RE.fullmatch(name) is not None


def require_interface(name: str) -> str:
    """Return ``name`` if valid, else raise :class:`TargetValidationError`."""
    if not valid_interface_name(name):
        raise TargetValidationError(f"invalid interface name: {name!r}")
    return name


# Six hex pairs (colon/hyphen separated) or twelve bare hex digits.
_BSSID_RE = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}")


def valid_bssid(bssid: str) -> bool:
    """True when ``bssid`` is a syntactically valid 48-bit MAC/BSSID."""
    return bool(bssid) and _BSSID_RE.fullmatch(bssid) is not None


def require_bssid(bssid: str) -> str:
    """Return ``bssid`` if valid, else raise :class:`TargetValidationError`."""
    if not valid_bssid(bssid):
        raise TargetValidationError(f"invalid BSSID: {bssid!r}")
    return bssid
