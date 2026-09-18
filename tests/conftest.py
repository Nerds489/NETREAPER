# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared pytest fixtures."""
from __future__ import annotations

import os
import re

import pytest

# ── make the local suite render the way CI renders ───────────────────────────
#
# Eleven consecutive CI runs were red while the suite passed locally every time,
# and the whole difference was colour. GitHub Actions is detected by Rich, which
# turns styling ON; pytest capturing output locally turns it OFF. Rich then
# emits style codes INSIDE a token, so `"--injection" in result.output` is true
# locally and false in CI, for output that reads identically to a human.
#
# Forcing colour on here makes the local run the harsher one. A test that only
# passes without styling now fails on the machine of whoever wrote it, rather
# than on a CI page nobody opened.
os.environ.setdefault("FORCE_COLOR", "1")

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def plain(text: str) -> str:
    """Rendered CLI output with the styling removed.

    Assert against this, never against the raw output. The raw bytes of
    `--injection` are not contiguous once Rich has styled them, so a substring
    check on them tests the renderer's internals rather than the CLI's
    behaviour.
    """
    return _ANSI.sub("", text)


@pytest.fixture
def strip_ansi():
    """The same helper, for tests that prefer a fixture."""
    return plain


@pytest.fixture
def temp_dir(tmp_path):
    """A throwaway directory for file-writing tests."""
    return tmp_path


@pytest.fixture
def sample_session_data():
    """A representative session payload for exporter tests."""
    return {
        "session": {
            "id": "session_001",
            "name": "test engagement",
            "created_at": "2026-09-11T10:00:00",
            "completed_at": "2026-09-11T11:30:00",
            "status": "completed",
        },
        "targets": [{"value": "192.168.1.10", "type": "ip"}],
        "tool_executions": [
            {"tool_name": "nmap", "exit_code": 0, "duration": 3},
        ],
        "loot": [],
        "findings": [],
    }


@pytest.fixture(autouse=True)
def _isolate_global_scope_gate():
    """Clear the process-wide engagement before and after every test.

    ``get_scope_gate()`` is a singleton. Any test that authorises through it,
    and especially one that drives the real CLI (``engage start`` sets the
    global gate), leaves that engagement in place for every test that runs
    afterwards in the same process.

    This is invisible to ordinary flake hunting. 150 suite runs, 50 of them with
    shuffled file order, found nothing: a leaked engagement is PERMISSIVE, so it
    makes later tests pass more easily rather than fail, and shuffling only
    surfaces leaks that break something. It was found by running one file and
    then asking the gate directly what it still held: a BROADCAST engagement,
    left behind by tests/unit/test_review_findings.py.

    The harm is a test passing for the wrong reason. A file asserting
    deny-by-default, running after one that left a permissive engagement behind,
    is no longer testing deny-by-default. Several files already defend
    themselves with their own clearing fixtures; this makes the isolation a
    property of the suite rather than something each author must remember.
    """
    from netreaper.safety.scope import get_scope_gate

    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()
