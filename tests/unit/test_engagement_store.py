# SPDX-License-Identifier: GPL-3.0-or-later
"""Engagement consent-file persistence: round-trip, tamper-evidence, clearing."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from netreaper.safety.engagement_store import (
    clear_engagement_file,
    load_engagement,
    save_engagement,
)
from netreaper.safety.scope import Engagement, Scope, Tier


def _eng() -> Engagement:
    now = datetime.now(UTC)
    return Engagement(
        operator="op",
        authorization_ref="ROE-42",
        scope=Scope(cidrs=["10.0.0.0/24"], bssids={"AA:BB:CC:DD:EE:FF"},
                    essids={"CorpWifi"}),
        started_at=now,
        expires_at=now + timedelta(hours=2),
        max_tier=Tier.MITM,
    )


def test_round_trip_preserves_fields_and_consent(tmp_path):
    p = tmp_path / "engagement.json"
    save_engagement(_eng(), path=p)
    loaded = load_engagement(path=p)
    assert loaded is not None
    assert loaded.operator == "op"
    assert loaded.authorization_ref == "ROE-42"
    assert loaded.scope.cidrs == ["10.0.0.0/24"]
    assert loaded.scope.essids == {"CorpWifi"}
    assert loaded.max_tier is Tier.MITM
    assert loaded.verify_consent()  # re-derived hash matches


def test_load_absent_returns_none(tmp_path):
    assert load_engagement(path=tmp_path / "nope.json") is None


def test_file_is_owner_only(tmp_path):
    p = tmp_path / "engagement.json"
    save_engagement(_eng(), path=p)
    assert (p.stat().st_mode & 0o777) == 0o600


def test_tamper_without_rehash_is_rejected(tmp_path):
    p = tmp_path / "engagement.json"
    save_engagement(_eng(), path=p)
    data = json.loads(p.read_text())
    data["scope"]["essids"] = ["EvilNet"]  # widen scope, leave consent_hash stale
    p.write_text(json.dumps(data))
    assert load_engagement(path=p) is None


def test_clear_removes_file(tmp_path):
    p = tmp_path / "engagement.json"
    save_engagement(_eng(), path=p)
    assert clear_engagement_file(path=p) is True
    assert not p.exists()
    assert clear_engagement_file(path=p) is False
