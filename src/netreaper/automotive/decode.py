# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Turn raw arbitration IDs into named signals (#33).

A candump capture is a wall of hex. What makes it analysable is a per-make
identifier database, which is what awesome-automotive-can-id collects. That data
is FETCHED on demand and never vendored: it is someone else's curated work, its
licence is recorded in :mod:`netreaper.resources.registry`, and a database that
ships inside the package is a database nobody updates.

The loader is deliberately forgiving about format. Community CAN ID data arrives
as CSV, TSV and JSON with inconsistent column names, so a strict parser would
reject most of what is actually out there and a silent one would mislabel
signals. Rows it cannot understand are counted and reported, not dropped
quietly.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

from netreaper.core.logging import get_logger

logger = get_logger(__name__)

# Column names the community data actually uses, in rough order of preference.
_ID_COLUMNS = ("can_id", "id", "arbitration_id", "canid", "pgn", "frame_id")
_NAME_COLUMNS = ("name", "signal", "description", "label", "signal_name", "desc")


@dataclass
class CanIdEntry:
    can_id: str
    name: str
    make: str = ""
    source: str = ""


@dataclass
class CanIdDatabase:
    """Arbitration ID to human name, loaded from fetched community data."""

    entries: dict[str, CanIdEntry] = field(default_factory=dict)
    unparsed_rows: int = 0
    files_loaded: int = 0

    def __len__(self) -> int:
        return len(self.entries)

    @staticmethod
    def _normalise_id(raw: str) -> str:
        """0x1A0, 1a0 and 01A0 are the same identifier in different clothes."""
        s = str(raw).strip().upper().removeprefix("0X").lstrip("0")
        return s or "0"

    def lookup(self, can_id: str) -> CanIdEntry | None:
        return self.entries.get(self._normalise_id(can_id))

    def add(self, entry: CanIdEntry) -> None:
        self.entries[self._normalise_id(entry.can_id)] = entry

    @classmethod
    def load(cls, path: Path, *, make: str = "") -> CanIdDatabase:
        """Load one file or every supported file in a directory."""
        db = cls()
        paths = (
            sorted(
                p
                for p in path.rglob("*")
                if p.suffix.lower() in {".csv", ".tsv", ".json"}
            )
            if path.is_dir()
            else [path]
        )
        for p in paths:
            try:
                before = len(db.entries)
                if p.suffix.lower() == ".json":
                    db._load_json(p, make)
                else:
                    db._load_delimited(p, make)
                db.files_loaded += 1
                logger.debug("loaded %d ids from %s", len(db.entries) - before, p.name)
            # UnicodeDecodeError is a subclass of ValueError, so listing both
            # catches nothing extra and misleads the reader into thinking a
            # decode error is handled separately from a parse error.
            except (OSError, ValueError) as e:
                # One malformed file must not lose the whole database.
                logger.warning("skipping CAN id file %s: %s", p, e)
        if db.unparsed_rows:
            logger.info(
                "%d row(s) had no recognisable id/name column and were skipped",
                db.unparsed_rows,
            )
        return db

    def _load_delimited(self, p: Path, make: str) -> None:
        text = p.read_text(encoding="utf-8", errors="replace")
        delim = "\t" if p.suffix.lower() == ".tsv" else ","
        for row in csv.DictReader(text.splitlines(), delimiter=delim):
            self._ingest(
                {(k or "").strip().lower(): v for k, v in row.items()}, p, make
            )

    def _load_json(self, p: Path, make: str) -> None:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, list):
            rows = data
        else:
            # A bare {"1A0": "Steering angle", ...} mapping is the common shape,
            # and looking for an "ids"/"signals" wrapper first dropped it
            # entirely: the fallback [] meant the whole file contributed nothing,
            # silently. Fall back to the object itself, not to empty.
            rows = data.get("ids", data.get("signals", data))
        if isinstance(rows, dict):  # {"1A0": "Steering angle", ...}
            for k, v in rows.items():
                self.add(
                    CanIdEntry(
                        can_id=str(k), name=str(v), make=make, source=p.name
                    )
                )
            return
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                self._ingest({str(k).lower(): v for k, v in row.items()}, p, make)
            else:
                self.unparsed_rows += 1

    def _ingest(self, row: dict, p: Path, make: str) -> None:
        cid = next((row[c] for c in _ID_COLUMNS if row.get(c)), None)
        name = next((row[c] for c in _NAME_COLUMNS if row.get(c)), None)
        if not cid or not name:
            self.unparsed_rows += 1
            return
        self.add(
            CanIdEntry(
                can_id=str(cid),
                name=str(name).strip(),
                make=make or str(row.get("make", "") or ""),
                source=p.name,
            )
        )


@dataclass
class DecodedFrame:
    can_id: str
    name: str
    data: str
    known: bool


def decode_capture(capture, db: CanIdDatabase) -> list[DecodedFrame]:
    """Name what we can and say plainly what we cannot.

    An unknown id is reported as unknown rather than guessed at: a mislabelled
    signal on a vehicle bus is worse than an unlabelled one.
    """
    out: list[DecodedFrame] = []
    for frame in getattr(capture, "frames", []):
        hit = db.lookup(frame.can_id)
        out.append(
            DecodedFrame(
                can_id=frame.can_id,
                name=hit.name if hit else "unknown",
                data=frame.data,
                known=hit is not None,
            )
        )
    return out
