# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixes for the four-reviewer pass over today's audit and confirmation work.

Every defect below was found by attacking shipped, merged, "verified" code. The
pattern the correctness reviewer named: the original tests exercised each fix's
headline scenario EXACTLY ONCE and never pushed a second step further, which is
where every one of them broke. So these go one iteration past the obvious case:
two writes after a crash rather than one, a secret AFTER the flag-shaped value,
a path-qualified tool name as well as a bare one.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netreaper.core.audit import REDACTED, AuditTrail, redact_argv, redact_text
from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import (
    DANGEROUS_OPS_PHRASE,
    Engagement,
    Scope,
    ScopeGate,
    Tier,
)

PHRASE = DANGEROUS_OPS_PHRASE


def _scope():
    return Scope(cidrs=["10.0.0.0/24"])


def _eng(**kw):
    kw.setdefault("max_tier", Tier.MITM)
    return Engagement(operator="t", authorization_ref="SOW-1", scope=_scope(), **kw)


# ── the gate had no way to issue a grant, which bricked every T2+ action ──────


def test_engage_start_can_actually_issue_a_grant(tmp_path, monkeypatch):
    """Before this, `engage start` could not set confirmed_tiers at all.

    The gate refused every SINGLE_TARGET/BROADCAST/MITM action and told the
    operator to add a tier to confirmed_tiers, which no command could do. The
    tool's primary function was dead and the whole suite passed, because tests
    build Engagement directly and grant themselves what the CLI could not.
    """
    from typer.testing import CliRunner

    from netreaper.cli import app
    from netreaper.safety.scope import get_scope_gate

    monkeypatch.setenv("HOME", str(tmp_path))
    res = CliRunner().invoke(
        app,
        ["engage", "start", "--operator", "op", "--ref", "SOW-9",
         "--cidr", "10.0.0.0/24", "--max-tier", "broadcast",
         "--confirm-tier", "single_target", "--confirm-tier", "broadcast"],
    )
    assert res.exit_code == 0, res.output
    gate = get_scope_gate()
    gate.authorize(["10.0.0.5"], tier=Tier.SINGLE_TARGET)
    gate.authorize(["10.0.0.5"], tier=Tier.BROADCAST)


def test_mitm_needs_the_interception_acknowledgement(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from netreaper.cli import app

    monkeypatch.setenv("HOME", str(tmp_path))
    res = CliRunner().invoke(
        app,
        ["engage", "start", "--operator", "op", "--ref", "R", "--cidr", "10.0.0.0/24",
         "--max-tier", "mitm", "--confirm-tier", "mitm"],
    )
    assert res.exit_code == 2
    assert "accept-interception" in res.output


def test_a_grant_cannot_exceed_its_own_ceiling(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from netreaper.cli import app

    monkeypatch.setenv("HOME", str(tmp_path))
    res = CliRunner().invoke(
        app,
        ["engage", "start", "--operator", "op", "--ref", "R", "--cidr", "10.0.0.0/24",
         "--max-tier", "single_target", "--confirm-tier", "mitm"],
    )
    assert res.exit_code == 2
    assert "exceeds --max-tier" in res.output


# ── credentials that are not behind a known flag ─────────────────────────────


def test_targets_are_redacted_they_were_stored_raw():
    t = AuditTrail()
    e = t.record(outcome="denied", tool="hydra", argv=["hydra"],
                 targets=["root:hunter2@10.0.0.5"])
    assert "hunter2" not in str(e.targets)
    assert e.targets == [f"root:{REDACTED}@10.0.0.5"]


@pytest.mark.parametrize(
    "arg",
    [
        "http://admin:SuperSecret@10.0.0.5/login.php",
        "https://proxyuser:proxypass@127.0.0.1:8080",
        "root:hunter2@10.0.0.5",
    ],
)
def test_credentials_embedded_in_a_url_are_stripped(arg):
    """sqlmap takes -u/--proxy/--cookie/--data; none of them are flag names."""
    out = redact_argv(["sqlmap", "-u", arg])
    assert REDACTED in out[-1]
    for secret in ("SuperSecret", "proxypass", "hunter2"):
        assert secret not in out[-1]


def test_a_url_without_credentials_is_left_alone():
    argv = ["sqlmap", "-u", "http://10.0.0.5/login.php?id=1"]
    assert redact_argv(argv) == argv


# ── the lookup was exact and case-sensitive ──────────────────────────────────


@pytest.mark.parametrize("tool", ["hydra", "Hydra", "HYDRA", "hydra.exe", "/usr/bin/hydra"])
def test_the_tool_key_is_normalised(tool):
    out = redact_argv([tool, "-l", "admin", "-p", "hunter2"])
    assert out[-1] == REDACTED, f"{tool} failed open"


def test_argv_and_detail_agree_on_which_tool_this_is():
    """One entry had argv masked and detail in the clear, because the two
    redactors derived the tool key differently."""
    t = AuditTrail()
    e = t.record(
        outcome="denied", tool="/usr/bin/hydra",
        argv=["/usr/bin/hydra", "-p", "hunter2"],
        detail="refused running: /usr/bin/hydra -p hunter2 10.0.0.5",
    )
    assert "hunter2" not in " ".join(e.argv)
    assert "hunter2" not in e.detail


# ── the state machine could be blinded by a crafted value ────────────────────


@pytest.mark.parametrize("filler", ["-p", "--password", "--token"])
def test_a_flag_shaped_value_does_not_blind_the_next_token(filler):
    """The consumed value re-armed the machine on its own content, so the token
    AFTER it was never checked. The original test stopped one token short of a
    real secret, which is why it passed."""
    out = redact_argv(["hydra", "-l", "admin", "-p", filler, "hunter2", "10.0.0.5"])
    assert "hunter2" not in out, out


def test_the_same_hole_in_free_text():
    out = redact_text("hydra -p --password hunter2 10.0.0.5", "hydra")
    assert "hunter2" not in out, out


# ── a crash must not break the trail on the SECOND write ─────────────────────


def _torn(tmp_path):
    p = tmp_path / "audit.jsonl"
    first = AuditTrail(path=p)
    for i in range(3):
        first.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    p.write_text(p.read_text()[:-25])
    return p


def test_the_chain_survives_more_than_one_write_after_a_crash(tmp_path):
    """Resume only fixed memory; the torn bytes stayed on disk and _persist
    appended straight onto them. verify_file() held for exactly one write, which
    is all the original test asserted, then failed for ever."""
    p = _torn(tmp_path)
    r = AuditTrail(path=p)
    assert r.verify_file()
    for n in range(1, 5):
        r.record(outcome="executed", tool=f"after-{n}", argv=["x"])
        assert r.verify_file(), f"broke on post-resume write {n}"


def test_a_later_process_resumes_the_repaired_file(tmp_path):
    p = _torn(tmp_path)
    r = AuditTrail(path=p)
    r.record(outcome="executed", tool="a", argv=["a"])
    r.record(outcome="executed", tool="b", argv=["b"])
    third = AuditTrail(path=p)
    assert third.verify_file()
    assert third._seq == 4  # the torn entry is discarded, not resurrected


def test_a_damaged_middle_is_still_rejected_after_repair(tmp_path):
    p = _torn(tmp_path)
    AuditTrail(path=p).record(outcome="executed", tool="a", argv=["a"])
    lines = p.read_text().splitlines()
    lines[1] = "{broken"
    p.write_text("\n".join(lines) + "\n")
    assert not AuditTrail(path=p, resume=False).verify_file()


# ── the confirmation shortcut skipped every precondition ─────────────────────


def _gate(eng):
    g = ScopeGate()
    g.set_engagement(eng)
    return g


def test_require_confirmation_refuses_an_expired_engagement():
    now = datetime.now(UTC)
    eng = _eng(confirmed_tiers=frozenset({Tier.MITM}), dangerous_ops_phrase=PHRASE,
               started_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
    with pytest.raises(TargetValidationError, match="expired"):
        _gate(eng).require_confirmation(tier=Tier.MITM)


def test_require_confirmation_enforces_the_ceiling():
    eng = _eng(max_tier=Tier.SINGLE_TARGET, confirmed_tiers=frozenset({Tier.MITM}),
               dangerous_ops_phrase=PHRASE)
    with pytest.raises(TargetValidationError, match="exceeds this engagement"):
        _gate(eng).require_confirmation(tier=Tier.MITM)


def test_require_confirmation_detects_a_tampered_record():
    eng = _eng(confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))
    object.__setattr__(eng, "confirmed_tiers", frozenset({Tier.MITM}))
    object.__setattr__(eng, "dangerous_ops_phrase", PHRASE)
    with pytest.raises(TargetValidationError, match="consent hash"):
        _gate(eng).require_confirmation(tier=Tier.MITM)


def test_authorize_and_require_confirmation_agree():
    """They diverged: one ran the preconditions, the other ran none."""
    now = datetime.now(UTC)
    eng = _eng(confirmed_tiers=frozenset({Tier.SINGLE_TARGET}),
               started_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1))
    g = _gate(eng)
    with pytest.raises(TargetValidationError, match="expired"):
        g.authorize(["10.0.0.5"], tier=Tier.SINGLE_TARGET)
    with pytest.raises(TargetValidationError, match="expired"):
        g.require_confirmation(tier=Tier.SINGLE_TARGET)
