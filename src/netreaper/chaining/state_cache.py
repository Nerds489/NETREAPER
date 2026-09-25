# SPDX-License-Identifier: GPL-3.0-or-later
"""Durable per-target capability state for the backward-chaining planner (#31).

`resolve_chain` already accepts an `available` set and skips any capability in
it, and `plan_to_chain` already drops the dependency edge a cached capability
would have satisfied. Both were fed by hand: `wifi plan --have wifi.handshake`.
`wifi auto` passed nothing, so every run re-derived everything. This is the
persistence that closes that gap: record what a run obtained, hand it back to
the next run's planner.

TWO THINGS MAKE A NAIVE CACHE WRONG HERE, and both are handled by only caching
*durable* capabilities and re-checking them on read:

  the artefact is deleted. `wifi auto`'s capture step passes no output path, so
  HandshakeCapture writes to a temp dir and `shutil.rmtree`s it in `finally`
  (handshake.py). The `wifi.handshake` "provided" by that step is a path to a
  file that no longer exists. Recording it blindly would tell the next run to
  skip capture and hand a deleted .cap to the cracker. So a handshake is
  recorded only if its file is present, and re-validated the same way on read.

  the fact is ephemeral. `wifi.monitor_interface` is a live interface on THIS
  machine right now, and `wifi.ssid_list` is what was in the air during one
  scan. Neither is a durable property of the target, so neither is cached at
  all: a fresh run must re-enable monitor mode and re-scan.

Only `wifi.password` (a network, once cracked, stays cracked) and a `wifi.handshake`
whose file survived are durable. Everything else is deliberately not persisted.

The store keeps a capability MARKER, never the value behind it. A recovered key
is a secret and belongs in the encrypted loot store; this table records only
that `wifi.password` was obtained for a BSSID, which is all the planner needs.

Keyed by (session_id, target_type, target, capability). There is no runtime
session plumbing yet (nothing supplies a session id to the CLI), so the CLI
path writes the sentinel session `NO_SESSION`; the column is here so per-session
scoping can layer on without a schema change.

Every operation degrades to "no cached state" on any database error rather than
raising: the cache is an optimisation, and a broken cache must never stop
`wifi auto` from running the full chain.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from netreaper.core.logging import get_logger
from netreaper.db.engine import get_db

logger = get_logger(__name__)

# Sentinel for "no session scope". A real, non-null value so the UNIQUE
# constraint and the ON CONFLICT upsert behave (SQLite considers NULLs distinct).
NO_SESSION = "-"


def _password_is_durable(_metadata: Mapping[str, Any]) -> bool:
    """A cracked network stays cracked; the marker never goes stale."""
    return True


def _handshake_file_present(metadata: Mapping[str, Any]) -> bool:
    """A handshake is only usable while its capture file exists on disk."""
    path = metadata.get("cap_file")
    return bool(path) and Path(str(path)).is_file()


# The capabilities worth persisting, each with the predicate that decides
# whether a recorded entry is still usable when it is read back. A capability
# absent from this map is ephemeral and is never cached — see the module
# docstring for why monitor-interface and scan lists are excluded.
_DURABLE: dict[str, Callable[[Mapping[str, Any]], bool]] = {
    "wifi.password": _password_is_durable,
    "wifi.handshake": _handshake_file_present,
}


def is_durable(capability: str) -> bool:
    """True if this capability is one the cache persists at all."""
    return capability in _DURABLE


async def available_for(
    target_type: str, target: str, *, session_id: str = NO_SESSION
) -> set[str]:
    """Return the durable, still-valid capabilities known for a target.

    This is what the planner is fed as ``available``. Each stored capability is
    re-checked against its freshness predicate, so a handshake whose file has
    since been deleted is silently dropped rather than offered.
    """
    try:
        db = await get_db()
        rows = await db.fetch_all(
            """
            SELECT capability, metadata FROM available_state
            WHERE session_id = ? AND target_type = ? AND target = ?
            """,
            (session_id, target_type, target),
        )
    except Exception as exc:
        logger.warning("available_state: read failed for %s: %s", target, exc)
        return set()

    out: set[str] = set()
    for row in rows:
        capability = row["capability"]
        fresh = _DURABLE.get(capability)
        if fresh is None:
            continue
        try:
            metadata = json.loads(row["metadata"]) if row["metadata"] else {}
        except (ValueError, TypeError):
            metadata = {}
        if fresh(metadata):
            out.add(capability)
    return out


async def record_capability(
    target_type: str,
    target: str,
    capability: str,
    value: Any,
    *,
    session_id: str = NO_SESSION,
) -> bool:
    """Persist one obtained capability, if it is durable and real.

    Returns True when a row was written. Refuses (returns False) for an
    ephemeral capability, an empty/falsey value, or a handshake whose file is
    already gone — the exact case the auto path produces.
    """
    fresh = _DURABLE.get(capability)
    if fresh is None:
        return False  # ephemeral: not a durable property of the target
    if not value:
        return False  # the step ran but produced nothing to remember

    metadata: dict[str, Any] = {}
    if capability == "wifi.handshake":
        if not Path(str(value)).is_file():
            return False  # do not cache a path to a deleted capture
        metadata["cap_file"] = str(value)
    # wifi.password intentionally stores no value: the marker is the fact, the
    # secret is not this table's to hold.

    try:
        db = await get_db()
        await db.execute(
            """
            INSERT INTO available_state
                (session_id, target_type, target, capability, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(session_id, target_type, target, capability) DO UPDATE SET
                metadata = excluded.metadata,
                recorded_at = CURRENT_TIMESTAMP
            """,
            (session_id, target_type, target, capability, json.dumps(metadata)),
        )
        return True
    except Exception as exc:
        logger.warning(
            "available_state: record failed for %s/%s: %s", target, capability, exc
        )
        return False


async def record_plan_outputs(
    target_type: str,
    target: str,
    step_outputs: Mapping[str, Any] | None,
    *,
    session_id: str = NO_SESSION,
) -> list[str]:
    """Record the durable capabilities from an executed chain's outputs.

    ``step_outputs`` is ``ChainResult.final_output``: ``{step_id: {capability:
    value}}``. Runners key their return dicts by capability name, so this walks
    those inner dicts and records each durable capability. Non-durable and
    invalid ones are dropped by ``record_capability``.
    """
    recorded: list[str] = []
    for data in (step_outputs or {}).values():
        if not isinstance(data, Mapping):
            continue
        for capability, value in data.items():
            if await record_capability(
                target_type, target, capability, value, session_id=session_id
            ):
                recorded.append(capability)
    return recorded


async def forget(
    target_type: str, target: str, *, session_id: str = NO_SESSION
) -> None:
    """Drop all cached state for a target (the ``--refresh`` escape hatch).

    Needed because a durable fact can still become false out of band: change an
    AP's password and the cached ``wifi.password`` marker would otherwise make
    ``wifi auto`` report the goal already met forever.
    """
    try:
        db = await get_db()
        await db.execute(
            """
            DELETE FROM available_state
            WHERE session_id = ? AND target_type = ? AND target = ?
            """,
            (session_id, target_type, target),
        )
    except Exception as exc:
        logger.warning("available_state: clear failed for %s: %s", target, exc)
