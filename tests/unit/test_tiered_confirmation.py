# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #46 item 1: the tiered confirmation rules are enforced, not declared.

``ScopeGate.authorize()`` accepted ``requires_confirmation`` and never read it.
``core/process.py`` forwarded it, ``chaining/manifest.py`` used it only to print
a ``[confirm]`` badge. So SEC-001 §3 was documented and enforced nowhere: a
ceiling (``max_tier``) said what an engagement MAY reach, and nothing ever said
that this particular action was intended.

The rule now: a confirmation cannot be obtained at a prompt mid-run, so anything
needing one must be granted in the authorisation record before the run starts,
and the grant is inside the consent digest so it cannot be added afterwards.
"""
from __future__ import annotations

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.engagement_store import load_engagement, save_engagement
from netreaper.safety.scope import (
    DANGEROUS_OPS_PHRASE,
    Engagement,
    Scope,
    ScopeGate,
    Tier,
)

TARGET = "10.0.0.5"


def _eng(max_tier=Tier.MITM, confirmed=frozenset(), phrase=""):
    return Engagement(
        operator="tester",
        authorization_ref="SOW-1",
        scope=Scope(cidrs=["10.0.0.0/24"]),
        max_tier=max_tier,
        confirmed_tiers=confirmed,
        dangerous_ops_phrase=phrase,
    )


def _gate(**kw):
    g = ScopeGate()
    g.set_engagement(_eng(**kw))
    return g


# ── T4 (MITM): grant AND the distinct phrase ──────────────────────────────────


def test_mitm_refused_without_preconfirmation():
    with pytest.raises(TargetValidationError, match="pre-confirmation"):
        _gate().authorize([TARGET], tier=Tier.MITM, destructive=True)


def test_mitm_refused_when_the_phrase_is_missing():
    g = _gate(confirmed=frozenset({Tier.MITM}))
    with pytest.raises(TargetValidationError, match="dangerous-ops phrase"):
        g.authorize([TARGET], tier=Tier.MITM, destructive=True)


def test_mitm_refused_when_the_phrase_is_wrong():
    g = _gate(confirmed=frozenset({Tier.MITM}), phrase="yes go on")
    with pytest.raises(TargetValidationError, match="dangerous-ops phrase"):
        g.authorize([TARGET], tier=Tier.MITM, destructive=True)


def test_mitm_allowed_with_the_grant_and_the_exact_phrase():
    g = _gate(confirmed=frozenset({Tier.MITM}), phrase=DANGEROUS_OPS_PHRASE)
    g.authorize([TARGET], tier=Tier.MITM, destructive=True)   # must not raise


# ── T3 (BROADCAST): structural, no prompt fallback ────────────────────────────


def test_broadcast_refused_without_a_grant_and_says_why():
    g = _gate(max_tier=Tier.BROADCAST)
    with pytest.raises(TargetValidationError, match="cannot be confirmed mid-run"):
        g.authorize([TARGET], tier=Tier.BROADCAST, destructive=True)


def test_broadcast_cannot_be_rescued_by_an_interactive_terminal(monkeypatch):
    """A mass action must never be answerable by whatever is on stdin."""
    monkeypatch.setattr("netreaper.safety.scope.is_non_interactive", lambda: False)
    g = _gate(max_tier=Tier.BROADCAST)
    with pytest.raises(TargetValidationError, match="cannot be confirmed mid-run"):
        g.authorize([TARGET], tier=Tier.BROADCAST, destructive=True)


def test_broadcast_allowed_when_granted_up_front():
    g = _gate(max_tier=Tier.BROADCAST, confirmed=frozenset({Tier.BROADCAST}))
    g.authorize([TARGET], tier=Tier.BROADCAST, destructive=True)


# ── T2 and the flag that used to do nothing ───────────────────────────────────


def test_single_target_refused_without_a_grant_whatever_is_on_stdin(monkeypatch):
    """Revise pass: the first cut let an attached TTY through.

    It reasoned that an operator "could have been asked". Nobody was asked
    anything, which is precisely the auto-confirm SEC-001 §3 forbids. Nothing in
    the gate prompts, so a missing grant is a refusal either way.
    """
    for interactive in (True, False):
        monkeypatch.setattr(
            "netreaper.safety.scope.is_non_interactive", lambda: not interactive
        )
        g = _gate(max_tier=Tier.SINGLE_TARGET)
        with pytest.raises(TargetValidationError, match="requires confirmation"):
            g.authorize([TARGET], tier=Tier.SINGLE_TARGET)


def test_single_target_allowed_with_a_grant():
    g = _gate(max_tier=Tier.SINGLE_TARGET, confirmed=frozenset({Tier.SINGLE_TARGET}))
    g.authorize([TARGET], tier=Tier.SINGLE_TARGET)


def test_requires_confirmation_now_actually_blocks():
    """The whole point of #46: this flag was accepted and ignored everywhere."""
    g = _gate(max_tier=Tier.MITM)
    # match= matters: a bare raises() passed even when the check broke for an
    # unrelated reason, so it proved only "something threw".
    with pytest.raises(TargetValidationError, match="requires confirmation"):
        g.authorize([TARGET], tier=Tier.ACTIVE_SCAN, requires_confirmation=True)


def test_requires_confirmation_satisfied_by_a_grant_for_that_tier():
    g = _gate(max_tier=Tier.MITM, confirmed=frozenset({Tier.ACTIVE_SCAN}))
    g.authorize([TARGET], tier=Tier.ACTIVE_SCAN, requires_confirmation=True)


# ── nothing below T2 changed ──────────────────────────────────────────────────


def test_passive_and_active_scan_are_untouched():
    g = _gate(max_tier=Tier.MITM)
    g.authorize([TARGET], tier=Tier.PASSIVE)
    g.authorize([TARGET], tier=Tier.ACTIVE_SCAN)


def test_host_actions_are_still_allowed():
    g = _gate(max_tier=Tier.MITM)
    g.authorize([], host_action=True, destructive=True)


def test_the_ceiling_still_applies_before_confirmation_is_considered():
    g = _gate(max_tier=Tier.ACTIVE_SCAN, confirmed=frozenset({Tier.MITM}),
              phrase=DANGEROUS_OPS_PHRASE)
    with pytest.raises(TargetValidationError, match="exceeds this engagement"):
        g.authorize([TARGET], tier=Tier.MITM)


# ── the grant is tamper-evident and survives persistence ──────────────────────


def test_a_grant_added_after_the_fact_breaks_the_consent_hash():
    eng = _eng(confirmed=frozenset(), phrase="")
    assert eng.verify_consent()
    object.__setattr__(eng, "confirmed_tiers", frozenset({Tier.MITM}))
    assert not eng.verify_consent(), (
        "a confirmation bolted on after authorisation must not verify"
    )


def test_the_store_round_trips_the_grant_and_the_hash_still_verifies(tmp_path):
    eng = _eng(confirmed=frozenset({Tier.BROADCAST, Tier.MITM}),
               phrase=DANGEROUS_OPS_PHRASE)
    p = tmp_path / "engagement.json"
    save_engagement(eng, path=p)
    loaded = load_engagement(path=p)

    assert loaded.confirmed_tiers == eng.confirmed_tiers
    assert loaded.dangerous_ops_phrase == DANGEROUS_OPS_PHRASE
    assert loaded.consent_hash == eng.consent_hash
    assert loaded.verify_consent()

    g = ScopeGate()
    g.set_engagement(loaded)
    g.authorize([TARGET], tier=Tier.MITM, destructive=True)
