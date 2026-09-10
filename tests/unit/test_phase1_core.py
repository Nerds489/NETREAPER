# SPDX-License-Identifier: GPL-3.0-or-later
"""Phase 1 regression + safety-contract tests.

These lock in the two defect classes that broke the inherited tree (a missing
module taking the whole package down; an ungated attack surface) and the version
single-source.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

# --- import smoke: the core package + spine must import (TUI is deferred) ---
CORE_MODULES = [
    "netreaper",
    "netreaper.core", "netreaper.core.process", "netreaper.core.exceptions",
    "netreaper.config", "netreaper.config.settings",
    "netreaper.safety", "netreaper.safety.scope", "netreaper.safety.protected",
    "netreaper.chaining", "netreaper.chaining.executor", "netreaper.chaining.registry",
    "netreaper.orchestration", "netreaper.plugins", "netreaper.db",
    "netreaper.detection", "netreaper.sessions", "netreaper.loot",
    "netreaper.tools", "netreaper.wireless", "netreaper.export",
    "netreaper.automation", "netreaper.automation.handlers",
    "netreaper.cli",
]


@pytest.mark.parametrize("name", CORE_MODULES)
def test_core_module_imports(name):
    importlib.import_module(name)


def test_version_is_single_sourced():
    import netreaper
    version_file = Path(netreaper.__file__).resolve().parents[2] / "VERSION"
    assert netreaper.__version__ == version_file.read_text(encoding="utf-8").strip()


# --- safety contract: nothing runs a target without passing the deny-by-default gate ---
from datetime import UTC

from netreaper.core.exceptions import TargetValidationError  # noqa: E402
from netreaper.core.process import ProcessRunner  # noqa: E402
from netreaper.safety.scope import Engagement, Scope, ScopeGate, Tier  # noqa: E402


def _runner_with(scope=None):
    gate = ScopeGate()
    if scope is not None:
        gate.set_engagement(Engagement(operator="test", authorization_ref="T", scope=scope))
    return ProcessRunner(gate=gate)


def test_no_engagement_denies_targeted_action():
    r = _runner_with()
    with pytest.raises(TargetValidationError):
        # dry_run must NOT bypass the gate: authorisation happens before it
        r.run_sync(["echo", "x"], targets=["192.168.1.10"], tier=Tier.ACTIVE_SCAN, dry_run=True)


def test_in_scope_target_is_allowed():
    r = _runner_with(Scope(cidrs=["192.168.1.0/24"]))
    res = r.run_sync(["echo", "ok"], targets=["192.168.1.10"], tier=Tier.ACTIVE_SCAN, dry_run=True)
    assert res.dry_run and res.returncode == 0


def test_out_of_scope_target_denied():
    r = _runner_with(Scope(cidrs=["192.168.1.0/24"]))
    with pytest.raises(TargetValidationError):
        r.run_sync(["echo", "x"], targets=["10.0.0.5"], tier=Tier.ACTIVE_SCAN, dry_run=True)


def test_protected_ip_refused_even_in_scope():
    r = _runner_with(Scope(cidrs=["127.0.0.0/8"]))
    with pytest.raises(TargetValidationError):
        r.run_sync(["echo", "x"], targets=["127.0.0.1"], tier=Tier.ACTIVE_SCAN, dry_run=True)


def test_broadcast_target_refused():
    r = _runner_with(Scope(bssids={"FF:FF:FF:FF:FF:FF"}))
    with pytest.raises(TargetValidationError):
        r.run_sync(["echo", "x"], targets=["FF:FF:FF:FF:FF:FF"], tier=Tier.BROADCAST, dry_run=True)


def test_targetless_passive_needs_no_engagement():
    r = _runner_with()
    res = r.run_sync(["echo", "hi"], tier=Tier.PASSIVE, dry_run=True)
    assert res.returncode == 0


def test_expired_engagement_denied():
    from datetime import datetime, timedelta
    gate = ScopeGate()
    eng = Engagement(
        operator="t", authorization_ref="T", scope=Scope(cidrs=["192.168.1.0/24"]),
        started_at=datetime.now(UTC) - timedelta(hours=2),
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    gate.set_engagement(eng)
    with pytest.raises(TargetValidationError):
        ProcessRunner(gate=gate).run_sync(
            ["echo", "x"], targets=["192.168.1.10"], tier=Tier.ACTIVE_SCAN, dry_run=True
        )
