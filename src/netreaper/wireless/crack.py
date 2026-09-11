# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""WPA/WPA2 handshake cracking: offline dictionary attack with aircrack-ng.

A captured 4-way handshake is cracked offline by testing each candidate
passphrase in a wordlist against the handshake's MIC. This reads a local ``.cap``
and a local wordlist and makes no network contact, so it runs at PASSIVE tier
with no target (a scope-gate denial still propagates). The BSSID is validated and
used only as aircrack's ``-b`` filter to pick the handshake, not as a network
target. hashcat (mode 22000, for PMKID ``.22000`` files) is a future path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from netreaper.core.exceptions import SubprocessError, ToolNotFoundError
from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.core.validation import require_bssid
from netreaper.orchestration.events import Events, event_bus
from netreaper.safety.scope import Tier

logger = get_logger(__name__)

# WPA passphrases are arbitrary text (not hex): capture everything between the
# brackets of aircrack-ng's "KEY FOUND! [ <passphrase> ]" line.
_WPA_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")


def parse_wpa_key(output: str) -> str | None:
    """Return the WPA passphrase from aircrack-ng output, or None."""
    m = _WPA_KEY_RE.search(output)
    if not m:
        return None
    return m.group(1) or None


@dataclass
class CrackResult:
    bssid: str
    cracked: bool = False
    password: str | None = None
    cap_file: str | None = None


async def crack_handshake(
    cap_path: str | Path,
    bssid: str,
    wordlist: str | Path,
    *,
    runner: ProcessRunner | None = None,
    timeout: float = 1800.0,
) -> CrackResult:
    """Crack a captured WPA handshake against a wordlist with aircrack-ng.

    Offline (PASSIVE, no target). Returns a :class:`CrackResult`; a missing tool
    or a timeout yields ``cracked=False`` rather than raising. A missing wordlist
    raises :class:`FileNotFoundError`; a malformed BSSID raises
    :class:`~netreaper.core.exceptions.TargetValidationError`.
    """
    target = require_bssid(bssid)
    wl = Path(wordlist)
    if not wl.is_file():
        raise FileNotFoundError(f"wordlist not found: {wl}")
    runner = runner or get_process_runner()
    result = CrackResult(bssid=target, cap_file=str(cap_path))
    cmd = ["aircrack-ng", "-a", "2", "-b", target, "-w", str(wl), str(cap_path)]
    try:
        proc = await runner.run(cmd, tier=Tier.PASSIVE, timeout=timeout)
    except (SubprocessError, ToolNotFoundError):
        return result
    key = parse_wpa_key(proc.stdout + (proc.stderr or ""))
    if key:
        result.cracked = True
        result.password = key
        event_bus.emit(
            Events.CREDENTIAL_CRACKED,
            {"type": "wpa", "bssid": target, "password": key},
        )
        logger.info("WPA handshake cracked for %s", target)
    else:
        logger.info("WPA handshake for %s not in the wordlist", target)
    return result


__all__ = ["CrackResult", "crack_handshake", "parse_wpa_key"]
