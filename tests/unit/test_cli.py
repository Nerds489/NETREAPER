# SPDX-License-Identifier: GPL-3.0-or-later
"""Smoke tests for the Python CLI core commands (Typer CliRunner)."""
from __future__ import annotations

from typer.testing import CliRunner

from netreaper.cli import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0
    assert "NETREAPER" in r.stdout


def test_status_runs():
    r = runner.invoke(app, ["status"])
    assert r.exit_code == 0
    assert "System Status" in r.stdout
    assert "tools available" in r.stdout


def test_config_show():
    r = runner.invoke(app, ["config", "show"])
    assert r.exit_code == 0
    assert "database" in r.stdout


def test_config_get_nested():
    r = runner.invoke(app, ["config", "get", "safety.unsafe_mode"])
    assert r.exit_code == 0
    assert "safety.unsafe_mode" in r.stdout


def test_config_bad_usage_exits_nonzero():
    r = runner.invoke(app, ["config", "frobnicate"])
    assert r.exit_code != 0
