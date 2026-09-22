# SPDX-License-Identifier: GPL-3.0-or-later
"""`wifi monitor start` and `config reset` were documented, and are not real.

Both commands take their action as a plain `str` argument, so Click accepts
whatever you hand it and the command discovers the problem itself, deep in its
own body. Both then exited **1**.

That one digit is why the README carried them through several releases with
`test_readme_commands_exist.py` green. That guard fails only on exit 2 with a
recognised parse signature, and treats any other exit as a command that parsed
and then refused for want of an engagement or a real adapter, which is correct
behaviour to document. So an action that does not exist was indistinguishable
from a working command in a bare environment:

    netreaper wifi monitor start wlan0   ->  "Invalid action..."   exit 1
    netreaper wifi monitor enable wlan0  ->  no such interface     exit 1

A bad action value is a usage error, the same class as an unknown option, so it
now exits 2 through `typer.BadParameter`. The README guard gained the matching
signature, and the last test here stops a new free-string action being added
without validation.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netreaper.cli import app

CLI_SOURCE = Path(__file__).resolve().parents[2] / "src" / "netreaper" / "cli.py"

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    from netreaper.config import settings as settings_mod
    from netreaper.config.settings import get_settings
    from netreaper.core import constants

    monkeypatch.setattr(constants, "NETREAPER_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(settings_mod, "_USER_CONFIG_PATH", tmp_path / "config.toml")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.parametrize(
    "argv",
    [
        ["config", "reset"],
        ["config", "delete"],
        ["wifi", "monitor", "start", "wlan0"],
        ["wifi", "monitor", "stop", "wlan0"],
        ["wifi", "monitor", "on", "wlan0"],
    ],
)
def test_an_action_that_does_not_exist_is_a_usage_error(argv):
    """Exit 2, not 1. The README guard keys on exactly this."""
    result = runner.invoke(app, argv)
    assert result.exit_code == 2, (
        f"`{' '.join(argv)}` exited {result.exit_code}; a bad action value is a "
        f"usage error and must exit 2 so the docs guard can see it"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["config", "show"],
        ["config", "get", "logging.level"],
        ["config", "set", "logging.level", "10"],
    ],
)
def test_a_real_action_is_not_reported_as_a_usage_error(argv):
    """The other half: tightening this must not start rejecting real commands."""
    result = runner.invoke(app, argv)
    assert result.exit_code != 2, (
        f"`{' '.join(argv)}` is valid but exited 2:\n{result.output[:300]}"
    )


def test_the_refusal_names_the_actions_that_do_exist():
    out = runner.invoke(app, ["wifi", "monitor", "start", "wlan0"]).output
    for real in ("enable", "disable", "status"):
        assert real in out, f"the error does not mention {real!r}:\n{out[:300]}"


def test_a_missing_key_is_a_usage_error_not_a_silent_success():
    assert runner.invoke(app, ["config", "get"]).exit_code == 2
    assert runner.invoke(app, ["config", "set", "logging.level"]).exit_code == 2


def _action_arguments() -> list[tuple[str, str]]:
    """(function name, argument name) for every free-string action argument."""
    tree = ast.parse(CLI_SOURCE.read_text(encoding="utf-8"))
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for arg, default in zip(
            node.args.args[-len(node.args.defaults) :] if node.args.defaults else [],
            node.args.defaults,
            strict=False,
        ):
            if not isinstance(default, ast.Call):
                continue
            func = default.func
            name = getattr(func, "attr", getattr(func, "id", ""))
            if name != "Argument":
                continue
            for kw in default.keywords:
                if kw.arg == "help" and isinstance(kw.value, ast.Constant):
                    if str(kw.value.value).startswith(("Action:", "Mode:")):
                        found.append((node.name, arg.arg))
    return found


def test_every_free_string_action_argument_is_validated():
    """Stops the next one being added without a check.

    A `str` action argument that no one validates is the whole defect: Click
    will not reject it, so the command must, and it must do so as a usage
    error rather than by printing and exiting 1.
    """
    actions = _action_arguments()
    assert actions, "no action arguments found; has the extraction drifted?"

    source = CLI_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    bodies = {
        node.name: ast.get_source_segment(source, node) or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }

    unvalidated = [
        f"{fn}({arg})" for fn, arg in actions if "_one_of(" not in bodies.get(fn, "")
    ]
    assert not unvalidated, (
        "these take a free-string action and never validate it, so an invalid "
        "value reaches the command body and cannot exit 2:\n  "
        + "\n  ".join(unvalidated)
    )
