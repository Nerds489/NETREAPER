# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Wireless discovery: enumerate access points and clients via airodump-ng.

The pure parser (:func:`parse_airodump_csv`) is fully unit-tested; the live
:func:`scan_networks` orchestration runs airodump through the gated ProcessRunner
and needs a monitor-mode adapter (opt-in, not exercised in CI).
"""
from __future__ import annotations

import csv
import re
import time
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path

from netreaper.core.exceptions import SubprocessError
from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.safety.scope import Tier

logger = get_logger(__name__)


@dataclass
class AccessPoint:
    bssid: str
    essid: str = ""
    channel: int | None = None
    power: int | None = None
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    beacons: int = 0
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class Client:
    mac: str
    associated_bssid: str = ""
    power: int | None = None
    packets: int = 0
    probed_essids: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    access_points: list[AccessPoint] = field(default_factory=list)
    clients: list[Client] = field(default_factory=list)

    def clients_for(self, bssid: str) -> list[Client]:
        b = bssid.upper()
        return [c for c in self.clients if c.associated_bssid.upper() == b]

    def find_ap(self, bssid: str) -> AccessPoint | None:
        b = bssid.upper()
        return next((a for a in self.access_points if a.bssid.upper() == b), None)


def _int(v: str) -> int | None:
    try:
        return int(v.strip())
    except (ValueError, AttributeError):
        return None


def essid_from_airodump_row(row: list[str]) -> str:
    """Extract the ESSID from an airodump AP row.

    ESSID starts at column 13 and airodump does not quote embedded commas, so it
    can span several columns. The trailing "Key" column (empty, or a hex WEP key)
    is dropped only when it is actually present, so a truncated row missing the
    Key column does not lose the ESSID's last segment.
    """
    tail = [f.strip() for f in row[13:]]
    if len(tail) > 1 and re.fullmatch(r"[0-9A-Fa-f]*", tail[-1] or ""):
        tail = tail[:-1]
    return ",".join(tail).strip()


def _rows_after_header(block: str):
    """The CSV rows of one airodump section, its header line dropped."""
    lines = block.strip().split("\n")
    return csv.reader(StringIO("\n".join(lines[1:])))


def _access_points_from(block: str) -> list[AccessPoint]:
    """The AP section. A row with fewer than 14 fields is a partial write, not
    an AP: airodump rewrites this file every second while it runs."""
    found = []
    for row in _rows_after_header(block):
        if len(row) < 14 or not row[0].strip():
            continue
        found.append(
            AccessPoint(
                bssid=row[0].strip(),
                first_seen=row[1].strip(),
                last_seen=row[2].strip(),
                channel=_int(row[3]),
                privacy=row[5].strip(),
                cipher=row[6].strip(),
                auth=row[7].strip(),
                power=_int(row[8]),
                beacons=_int(row[9]) or 0,
                essid=essid_from_airodump_row(row),
            )
        )
    return found


def _clients_from(block: str) -> list[Client]:
    """The station section. Probed ESSIDs are every field from 6 on, because a
    station can probe for any number of networks and airodump just keeps going."""
    found = []
    for row in _rows_after_header(block):
        if len(row) < 6 or not row[0].strip():
            continue
        probes = [p.strip() for p in row[6:] if p.strip()] if len(row) > 6 else []
        found.append(
            Client(
                mac=row[0].strip(),
                power=_int(row[3]),
                packets=_int(row[4]) or 0,
                associated_bssid=row[5].strip(),
                probed_essids=probes,
            )
        )
    return found


def parse_airodump_csv(text: str) -> ScanResult:
    """Parse an airodump-ng CSV dump (AP section, blank line, client section)."""
    # Normalise newlines and split the two sections on the blank line between them.
    blocks = [b for b in text.replace("\r\n", "\n").split("\n\n") if b.strip()]
    result = ScanResult()
    if not blocks:
        return result

    result.access_points.extend(_access_points_from(blocks[0]))
    if len(blocks) > 1:
        result.clients.extend(_clients_from(blocks[1]))
    return result


async def scan_networks(
    monitor_interface: str,
    *,
    duration: int = 15,
    runner: ProcessRunner | None = None,
    out_dir: Path | None = None,
) -> ScanResult:
    """Run airodump-ng on a monitor interface for ``duration`` seconds and parse
    the result. Discovery is target-less (you scan to find targets), so it passes
    the gate without an engagement."""
    runner = runner or get_process_runner()
    out_dir = out_dir or Path.home() / ".netreaper" / "scans"
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = out_dir / f"scan_{int(time.time())}"

    cmd = [
        "airodump-ng", "--output-format", "csv",
        "--write", str(prefix), "--write-interval", "1", monitor_interface,
    ]
    try:
        # airodump runs until stopped; the timeout is the intended scan window.
        await runner.run(cmd, tier=Tier.PASSIVE, timeout=duration)
    except SubprocessError:
        pass  # timeout == scan window elapsed; read what was captured

    csv_path = Path(f"{prefix}-01.csv")
    if not csv_path.exists():
        logger.warning("no scan CSV produced at %s (airodump may not have started)", csv_path)
        return ScanResult()
    return parse_airodump_csv(csv_path.read_text(errors="replace"))


__all__ = ["AccessPoint", "Client", "ScanResult", "essid_from_airodump_row", "parse_airodump_csv", "scan_networks"]
