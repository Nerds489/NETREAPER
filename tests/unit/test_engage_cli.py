# SPDX-License-Identifier: GPL-3.0-or-later
"""`netreaper engage` lifecycle: start persists + arms, status, end clears.

Proves C-2: an engagement established in one invocation arms the process-wide
scope gate in a later one (here, after clearing the singleton to simulate a
fresh process, a command's callback rehydrates the gate from the consent file).
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from netreaper.cli import app
from netreaper.safety import engagement_store
from netreaper.safety.scope import get_scope_gate

runner = CliRunner()


@pytest.fixture(autouse=True)
def _redirect_store(tmp_path, monkeypatch):
    """Point the consent file at a temp path and keep the gate clean."""
    path = tmp_path / "engagement.json"
    monkeypatch.setattr(engagement_store, "engagement_file_path", lambda: path)
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


def test_status_without_engagement_exits_1():
    result = runner.invoke(app, ["engage", "status"])
    assert result.exit_code == 1
    assert "No active engagement" in result.stdout


def test_start_persists_and_arms_then_end_clears(tmp_path):
    r = runner.invoke(app, [
        "engage", "start", "--operator", "me", "--ref", "ROE-1",
        "--essid", "CorpWifi", "--max-tier", "mitm",
    ])
    assert r.exit_code == 0, r.stdout
    assert engagement_store.engagement_file_path().is_file()

    # Simulate a fresh process: drop the in-memory engagement, then invoke a
    # command. The app callback must rehydrate the gate from the consent file.
    get_scope_gate().clear_engagement()
    r2 = runner.invoke(app, ["engage", "status"])
    assert r2.exit_code == 0
    assert "active" in r2.stdout.lower()
    assert get_scope_gate().engagement is not None
    assert get_scope_gate().engagement.scope.allows_essid("CorpWifi")

    r3 = runner.invoke(app, ["engage", "end"])
    assert r3.exit_code == 0
    assert not engagement_store.engagement_file_path().exists()


def test_start_rejects_empty_ref():
    r = runner.invoke(app, [
        "engage", "start", "--operator", "me", "--ref", "   ",
        "--essid", "X",
    ])
    assert r.exit_code == 2
    assert "ref must not be empty" in r.stdout


def test_start_rejects_bad_tier():
    r = runner.invoke(app, [
        "engage", "start", "--operator", "me", "--ref", "R",
        "--cidr", "10.0.0.0/24", "--max-tier", "nonsense",
    ])
    assert r.exit_code == 2
    assert "invalid --max-tier" in r.stdout


def test_status_reports_expired_and_exits_1():
    from datetime import UTC, datetime, timedelta

    from netreaper.safety.engagement_store import save_engagement
    from netreaper.safety.scope import Engagement, Scope, Tier

    now = datetime.now(UTC)
    save_engagement(
        Engagement(operator="me", authorization_ref="R", scope=Scope(essids={"X"}),
                   started_at=now - timedelta(hours=3),
                   expires_at=now - timedelta(hours=1), max_tier=Tier.MITM),
        path=engagement_store.engagement_file_path(),
    )
    r = runner.invoke(app, ["engage", "status"])
    assert r.exit_code == 1
    assert "EXPIRED" in r.stdout


def test_garbage_file_does_not_crash_and_gate_stays_closed():
    engagement_store.engagement_file_path().write_text("] not json {")
    # A command still runs; hydration swallows the bad file and the gate is closed.
    r = runner.invoke(app, ["engage", "status"])
    assert r.exit_code == 1  # status: no usable engagement
    assert get_scope_gate().engagement is None
