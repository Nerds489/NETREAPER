# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Persist an :class:`~netreaper.safety.scope.Engagement` across CLI processes.

The scope gate is a per-process singleton, so an engagement set in one
``netreaper`` invocation would not survive to the next. This stores the
authorising fields in a consent file (default ``$NETREAPER_HOME/config/
engagement.json``, mode 0600) so ``netreaper engage start`` arms the gate for
every later command until ``engage end`` or expiry.

The stored ``consent_hash`` is re-derived on load and compared: if the file's
authorising fields were edited without recomputing the hash, the load is
rejected. This is the same unkeyed tamper-evidence the in-memory
:meth:`Engagement.verify_consent` provides, extended to the durable artefact.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from netreaper.core.constants import NETREAPER_CONFIG_DIR
from netreaper.core.logging import get_logger
from netreaper.safety.scope import Engagement, Scope, Tier

logger = get_logger(__name__)


def engagement_file_path() -> Path:
    """The consent file location."""
    return NETREAPER_CONFIG_DIR / "engagement.json"


def _to_dict(eng: Engagement) -> dict[str, object]:
    return {
        "operator": eng.operator,
        "authorization_ref": eng.authorization_ref,
        "scope": {
            "cidrs": list(eng.scope.cidrs),
            "hostnames": sorted(eng.scope.hostnames),
            "bssids": sorted(eng.scope.bssids),
            "essids": sorted(eng.scope.essids),
            "deny": list(eng.scope.deny),
        },
        "started_at": eng.started_at.isoformat(),
        "expires_at": eng.expires_at.isoformat(),
        "max_tier": int(eng.max_tier),
        "consent_hash": eng.consent_hash,
    }


def _from_dict(data: dict[str, Any]) -> Engagement:
    s = data["scope"]
    scope = Scope(
        cidrs=list(s.get("cidrs", [])),
        hostnames=set(s.get("hostnames", [])),
        bssids=set(s.get("bssids", [])),
        essids=set(s.get("essids", [])),
        deny=list(s.get("deny", [])),
    )
    return Engagement(
        operator=data["operator"],
        authorization_ref=data["authorization_ref"],
        scope=scope,
        started_at=datetime.fromisoformat(data["started_at"]),
        expires_at=datetime.fromisoformat(data["expires_at"]),
        max_tier=Tier(int(data["max_tier"])),
    )


def save_engagement(eng: Engagement, *, path: Path | None = None) -> Path:
    """Write the engagement to the consent file (mode 0600). Returns the path."""
    p = path or engagement_file_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_to_dict(eng), indent=2, sort_keys=True))
    p.chmod(0o600)
    return p


def load_engagement(*, path: Path | None = None) -> Engagement | None:
    """Load the persisted engagement, or None if absent/unreadable/tampered.

    The re-derived consent hash must match the stored one; a mismatch means the
    file's authorising fields were altered without updating the hash, so the
    record is rejected rather than trusted.
    """
    p = path or engagement_file_path()
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text())
        eng = _from_dict(data)
    except (OSError, ValueError, KeyError) as exc:
        logger.warning("ignoring unreadable engagement file %s: %s", p, exc)
        return None
    stored = data.get("consent_hash", "")
    if eng.consent_hash != stored:
        logger.warning(
            "engagement file %s failed its consent-hash check; ignoring it", p
        )
        return None
    return eng


def clear_engagement_file(*, path: Path | None = None) -> bool:
    """Delete the consent file. Returns True if a file was removed."""
    p = path or engagement_file_path()
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False


__all__ = [
    "clear_engagement_file",
    "engagement_file_path",
    "load_engagement",
    "save_engagement",
]
