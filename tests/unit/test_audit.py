# SPDX-License-Identifier: GPL-3.0-or-later
"""Hash-chained audit trail (§5.5) and engagement consent hash (§5.2)."""
from __future__ import annotations

import dataclasses

import pytest

from netreaper.core.audit import GENESIS, AuditTrail
from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate


@pytest.fixture(autouse=True)
def _clean_gate():
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


def _trail() -> AuditTrail:
    return AuditTrail(path=None)  # in-memory only


# --- the hash chain ---


def test_chain_links_and_verifies():
    t = _trail()
    assert t.head == GENESIS
    a = t.record(outcome="authorised", tool="nmap", targets=["10.0.0.1"], tier="ACTIVE_SCAN")
    b = t.record(outcome="executed", tool="nmap", detail="rc=0")
    assert a.prev_hash == GENESIS
    assert b.prev_hash == a.entry_hash          # linked
    assert t.head == b.entry_hash
    assert [e.seq for e in t.entries] == [0, 1]
    assert t.verify() is True


def test_verify_detects_a_tampered_entry():
    t = _trail()
    t.record(outcome="executed", tool="aireplay-ng", detail="rc=0")
    t.record(outcome="executed", tool="airodump-ng", detail="rc=0")
    # Alter a past entry's body while keeping its stored hash -> chain breaks.
    t._entries[0] = dataclasses.replace(t._entries[0], detail="rc=1 (forged)")
    assert t.verify() is False


def test_verify_detects_a_dropped_entry():
    t = _trail()
    for _ in range(3):
        t.record(outcome="executed", tool="iw", host_action=True)
    del t._entries[1]
    assert t.verify() is False


def test_outcomes_and_fields_are_recorded():
    t = _trail()
    d = t.record(outcome="denied", operator="op1", tool="aireplay-ng",
                 targets=["AA:BB:CC:DD:EE:FF"], tier="BROADCAST",
                 destructive=True, detail="out of scope")
    assert d.outcome == "denied" and d.operator == "op1"
    assert d.destructive is True and d.targets == ["AA:BB:CC:DD:EE:FF"]


# --- consent hash ---


def _eng(**kw) -> Engagement:
    kw.setdefault("operator", "tester")
    kw.setdefault("authorization_ref", "ROE-1")
    kw.setdefault("scope", Scope(cidrs=["10.0.0.0/24"]))
    return Engagement(**kw)


def test_consent_hash_is_set_and_verifies():
    e = _eng()
    assert e.consent_hash and len(e.consent_hash) == 64
    assert e.verify_consent() is True


def test_consent_hash_is_deterministic_for_equal_records():
    from datetime import UTC, datetime, timedelta
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    t1 = t0 + timedelta(hours=12)
    a = Engagement("op", "R", Scope(cidrs=["10.0.0.0/24"]), started_at=t0, expires_at=t1)
    b = Engagement("op", "R", Scope(cidrs=["10.0.0.0/24"]), started_at=t0, expires_at=t1)
    assert a.consent_hash == b.consent_hash


def test_consent_detects_scope_tamper():
    e = _eng()
    e.scope.cidrs.append("192.168.0.0/16")   # widen scope after consent was granted
    assert e.verify_consent() is False


def test_gate_denies_a_tampered_engagement():
    gate = get_scope_gate()
    e = _eng(scope=Scope(cidrs=["10.0.0.0/24"]), max_tier=Tier.ACTIVE_SCAN)
    gate.set_engagement(e)
    # in-scope target authorises cleanly...
    gate.authorize(["10.0.0.5"], tier=Tier.ACTIVE_SCAN)
    # ...but if the record is mutated after the fact, the gate refuses.
    e.scope.cidrs.append("0.0.0.0/0")
    with pytest.raises(TargetValidationError, match="consent hash"):
        gate.authorize(["10.0.0.5"], tier=Tier.ACTIVE_SCAN)
