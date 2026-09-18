# SPDX-License-Identifier: GPL-3.0-or-later
"""Can an operator actually authorise each tier from the command line?

This is the test whose absence shipped a dead tool. PR #54 taught the gate to
require a tier in ``confirmed_tiers`` before a T2+ action could run, and
``engage start`` had no flag that could put one there. Every SINGLE_TARGET,
BROADCAST and MITM action on main refused, which is to say the entire offensive
surface of the tool, and 384 tests stayed green because every one of them builds
an ``Engagement`` by hand:

    Engagement(..., confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))

A test that constructs the grant it needs can never discover that no operator
can construct it. It asserts the lock works while saying nothing about whether
a key exists. So these tests reach the gate only the way a user does, through
``runner.invoke(app, ["engage", "start", ...])``, and they walk the whole
``Tier`` enum rather than a hand-written list of the tiers that mattered in
September, so a tier added later with no CLI path fails here instead of in
somebody's engagement.

The negative controls matter as much as the positives. A test that only proves
"authorised work runs" passes just as happily against a gate that authorises
everything, and that is the other way this file could rot into a vacuous pass.
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from netreaper.cli import app
from netreaper.core.exceptions import TargetValidationError
from netreaper.safety import engagement_store
from netreaper.safety.scope import (
    DANGEROUS_OPS_PHRASE,
    Tier,
    get_scope_gate,
)

runner = CliRunner()

IN_SCOPE_BSSID = "AA:BB:CC:DD:EE:FF"
IN_SCOPE_ESSID = "CorpWifi"
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

# What each tier actually names as its target in ``src``, checked rather than
# assumed: T3 comes from aireplay's broadcast deauth, which still names the AP's
# BSSID, and T4 comes from eviltwin/enterprise/downgrade, which name an ESSID.
# The first cut of this file guessed FF:FF:FF:FF:FF:FF for T3+ and went red,
# which is how the stale comment in _check_target got found.
TARGET_FOR_TIER = {
    Tier.PASSIVE: IN_SCOPE_BSSID,
    Tier.ACTIVE_SCAN: IN_SCOPE_BSSID,
    Tier.SINGLE_TARGET: IN_SCOPE_BSSID,
    Tier.BROADCAST: IN_SCOPE_BSSID,
    Tier.MITM: IN_SCOPE_ESSID,
}


def target_for(tier: Tier) -> str:
    """Fails loudly for a tier added without deciding what it targets."""
    assert tier in TARGET_FOR_TIER, (
        f"{tier.name} is a new tier with no declared target shape; add it to "
        f"TARGET_FOR_TIER after checking what its call sites in src actually pass"
    )
    return TARGET_FOR_TIER[tier]


@pytest.fixture(autouse=True)
def _redirect_store(tmp_path, monkeypatch):
    """Keep the consent file in a temp dir and the gate clean either side."""
    path = tmp_path / "engagement.json"
    monkeypatch.setattr(engagement_store, "engagement_file_path", lambda: path)
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


def engage_argv(tier: Tier, *, target: str = IN_SCOPE_BSSID) -> list[str]:
    """The argv an operator types to authorise work at ``tier``.

    Built from the tier rather than hardcoded per command, so the question this
    file asks stays "is there a way in for every tier" and not "is there a way
    in for the five tiers that existed when I wrote this".
    """
    argv = [
        "engage", "start",
        "--operator", "tester",
        "--ref", "ROE-LADDER",
        "--bssid", target,
        "--essid", IN_SCOPE_ESSID,
        "--max-tier", tier.name.lower(),
    ]
    if tier >= Tier.SINGLE_TARGET:
        argv += ["--confirm-tier", tier.name.lower()]
    if tier >= Tier.MITM:
        argv += ["--accept-interception"]
    return argv


# ── the ladder is climbable ──────────────────────────────────────────────────


@pytest.mark.parametrize("tier", list(Tier), ids=lambda t: t.name)
def test_an_operator_can_authorise_every_tier_from_the_cli(tier):
    """For each tier: a real `engage start`, then a real gate check.

    No Engagement is constructed here. If the gate grows a requirement that no
    flag can satisfy, this goes red for that tier, which is exactly what did
    not happen in September.
    """
    result = runner.invoke(app, engage_argv(tier))
    assert result.exit_code == 0, f"{tier.name}: engage start failed\n{result.stdout}"

    target = target_for(tier)
    # Raises TargetValidationError if the tier cannot be reached. Deliberately
    # not wrapped in pytest.raises(None) or a try: the traceback is the report.
    get_scope_gate().authorize([target], tier=tier)


@pytest.mark.parametrize("tier", list(Tier), ids=lambda t: t.name)
def test_a_manifest_flagged_action_is_runnable_at_every_tier(tier):
    """``requires_confirmation`` forces a grant even at PASSIVE.

    ``needs = requires_confirmation or tier >= SINGLE_TARGET``, so a manifest
    that flags a T0 action needs PASSIVE in confirmed_tiers. If no flag could
    grant that, every such manifest would be unrunnable: the same defect one
    tier down.
    """
    argv = engage_argv(tier)
    if tier < Tier.SINGLE_TARGET:  # not added by engage_argv for low tiers
        argv += ["--confirm-tier", tier.name.lower()]
    assert runner.invoke(app, argv).exit_code == 0

    target = target_for(tier)
    get_scope_gate().authorize([target], tier=tier, requires_confirmation=True)


def test_every_tier_name_is_accepted_by_confirm_tier():
    """The flag's vocabulary and the enum's cannot drift apart."""
    for tier in Tier:
        r = runner.invoke(app, engage_argv(tier))
        assert r.exit_code == 0, f"--confirm-tier {tier.name.lower()} rejected"


def test_the_mitm_grant_carries_the_dangerous_ops_phrase():
    """--accept-interception must actually write the phrase, not just parse."""
    assert runner.invoke(app, engage_argv(Tier.MITM)).exit_code == 0
    eng = get_scope_gate().engagement
    assert eng is not None
    assert eng.dangerous_ops_phrase == DANGEROUS_OPS_PHRASE
    assert Tier.MITM in eng.confirmed_tiers


# ── the negative controls: the gate is real, not permissive ──────────────────


@pytest.mark.parametrize(
    "tier", [t for t in Tier if t >= Tier.SINGLE_TARGET], ids=lambda t: t.name
)
def test_without_confirm_tier_the_gate_still_refuses(tier):
    """A ceiling alone authorises nothing at T2+.

    Without this, every test above would pass against a gate that waved
    everything through, and the file would prove nothing.
    """
    argv = [
        "engage", "start",
        "--operator", "tester",
        "--ref", "ROE-NOCONFIRM",
        "--bssid", IN_SCOPE_BSSID,
        "--max-tier", tier.name.lower(),
    ]
    assert runner.invoke(app, argv).exit_code == 0

    target = target_for(tier)
    with pytest.raises(TargetValidationError, match=r"confirm|pre-confirm|granted"):
        get_scope_gate().authorize([target], tier=tier)


def test_mitm_without_accepting_interception_is_refused_at_the_cli():
    """The awkward phrase is a required sentence, not a documented one."""
    argv = [
        "engage", "start",
        "--operator", "tester",
        "--ref", "ROE-NOPHRASE",
        "--bssid", IN_SCOPE_BSSID,
        "--max-tier", "mitm",
        "--confirm-tier", "mitm",
    ]
    r = runner.invoke(app, argv)
    assert r.exit_code == 2
    assert "accept-interception" in r.stdout


def test_confirming_above_the_ceiling_is_refused():
    """A grant the ceiling forbids is a contradiction, caught at entry."""
    r = runner.invoke(app, [
        "engage", "start",
        "--operator", "tester",
        "--ref", "ROE-OVER",
        "--bssid", IN_SCOPE_BSSID,
        "--max-tier", "active_scan",
        "--confirm-tier", "broadcast",
    ])
    assert r.exit_code == 2
    assert "exceeds" in r.stdout


def test_an_out_of_scope_target_is_refused_at_every_authorised_tier():
    """The confirmation grant is not a scope bypass."""
    assert runner.invoke(app, engage_argv(Tier.SINGLE_TARGET)).exit_code == 0
    with pytest.raises(TargetValidationError):
        get_scope_gate().authorize(["11:22:33:44:55:66"], tier=Tier.SINGLE_TARGET)


def test_a_broadcast_target_is_refused_below_broadcast_tier():
    """FF:FF:FF:FF:FF:FF at T2 is a mass action wearing a single-target hat."""
    assert runner.invoke(app, engage_argv(Tier.SINGLE_TARGET)).exit_code == 0
    with pytest.raises(TargetValidationError):
        get_scope_gate().authorize([BROADCAST_MAC], tier=Tier.SINGLE_TARGET)


def test_no_engagement_at_all_refuses_everything_gated():
    """Deny-by-default, asserted through the same path as the positives."""
    for tier in Tier:
        if tier <= Tier.PASSIVE:
            continue
        with pytest.raises(TargetValidationError, match="deny-by-default"):
            get_scope_gate().authorize([IN_SCOPE_BSSID], tier=tier)


# ── the target grammar does not loosen as the tier rises ─────────────────────


@pytest.mark.parametrize("tier", list(Tier), ids=lambda t: t.name)
@pytest.mark.parametrize("mass", [BROADCAST_MAC, "0.0.0.0/0", "::/0"])
def test_a_mass_target_is_refused_at_every_tier_including_mitm(tier, mass):
    """Authorising T4 does not buy the right to stop naming a target.

    _check_target's comment used to claim these were allowed "at BROADCAST+
    tier", which the code has never done. The comment is now corrected, and
    this pins the behaviour so the next reader cannot close the gap the other
    way round by making the code match the old prose.
    """
    argv = engage_argv(tier)
    if tier < Tier.SINGLE_TARGET:
        argv += ["--confirm-tier", tier.name.lower()]
    assert runner.invoke(app, argv).exit_code == 0

    with pytest.raises(TargetValidationError, match=r"broadcast|everything|scope"):
        get_scope_gate().authorize([mass], tier=tier, requires_confirmation=True)
