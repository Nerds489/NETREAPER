# SPDX-License-Identifier: GPL-3.0-or-later
"""CLI-output assertions must survive styling, because CI styles and you do not.

Eleven consecutive CI runs were red while the suite passed locally every single
time, and the entire difference was colour. Rich turns styling on when it
detects GitHub Actions and off when pytest captures output locally. With styling
on it emits escape codes INSIDE a token, so

    assert "--injection" in result.output

is true locally and false in CI, for output a human reads as identical. The
assertion was wrong from the day it was written and no local run could say so.

``tests/conftest.py`` now sets FORCE_COLOR for the whole suite, so the local run
is the harsher one by default and a colour-fragile assertion fails on the
machine of whoever wrote it. These are the tripwires for that arrangement.

They are deliberately CONDITION-AWARE rather than "colour is always on". Rich
honours NO_COLOR and TERM=dumb over FORCE_COLOR, and both are legitimate: a
developer on a plain terminal, or a CI image that sets TERM=dumb. A guard that
fires there would be a false alarm, and a guard that cries wolf gets disabled,
which is how the protection would actually be lost.
"""
from __future__ import annotations

from tests.conftest import plain
from typer.testing import CliRunner

from netreaper.cli import app

ESC = "\x1b["


def _help() -> str:
    return CliRunner().invoke(app, ["wifi", "wep", "--help"]).output


def test_the_assertion_target_is_correct_whether_or_not_colour_is_on():
    """The property every CLI-output assertion actually needs.

    plain() must yield the readable text in both renderings. This is the one
    that matters: it is true in CI, true locally, and true on a plain terminal.
    """
    out = plain(_help())
    assert "--injection" in out
    assert "Usage:" in out


def test_when_colour_is_on_the_raw_output_is_not_safe_to_assert_against():
    """The precise reason the CI failure was invisible locally.

    Skipped rather than failed where colour is genuinely off (NO_COLOR,
    TERM=dumb), because there is nothing wrong in that case.
    """
    import pytest

    raw = _help()
    if ESC not in raw:
        pytest.skip("colour is off in this environment; nothing to demonstrate")

    assert "--injection" not in raw, (
        "Rich is no longer splitting the token. That is not a failure in "
        "itself, but this guard has stopped measuring what it exists for, so "
        "re-check the CLI-output assertions before relaxing it."
    )
    assert "--injection" in plain(raw), "plain() failed to recover the token"


def test_plain_is_a_no_op_on_text_that_was_never_styled():
    assert plain("--injection TEXT") == "--injection TEXT"
    assert plain("") == ""


def test_plain_strips_the_styling_rich_actually_emits():
    styled = "\x1b[1m--\x1b[0m\x1b[36minjection\x1b[0m"
    assert "--injection" not in styled
    assert plain(styled) == "--injection"


def test_the_suite_defaults_to_the_ci_rendering():
    """Unless the environment explicitly refuses colour, it should be on.

    This is what keeps local and CI aligned. It defers to NO_COLOR and
    TERM=dumb, which Rich honours over FORCE_COLOR and which a developer or a
    CI image may set on purpose.
    """
    import os

    import pytest

    if os.environ.get("NO_COLOR") or os.environ.get("TERM") in {"dumb", ""}:
        pytest.skip("this environment refuses colour, which Rich honours")

    assert os.environ.get("FORCE_COLOR"), (
        "conftest no longer forces colour, so the local suite has stopped "
        "reproducing how CI renders and a colour-fragile assertion would once "
        "again only fail on a CI page nobody opens"
    )
    assert ESC in _help(), "FORCE_COLOR is set but Rich is not styling output"
