# SPDX-License-Identifier: GPL-3.0-or-later
"""Three regressions a single autofix merged into main, and the guards for them.

PR #76 was titled "use parameterized logging instead of f-strings". Eleven of
the twelve files it touched got exactly that. `tools/sqlmap.py` got something
else, described in the same PR body as removing "dead code" and "invalid
syntax", and main went red on 2026-09-18 and stayed red.

What it actually did:

  deleted a return   `_session_args` lost its `--proxy` handling AND its
                     `return args`, so it fell through into the class body and
                     returned None. `build_command` then did `cmd += None` and
                     raised TypeError on every sqlmap invocation.

  duplicated a       It added `_find_injection_points_with_regex`, which is
  parser             byte-for-byte equivalent to the existing
                     `_parse_injection_points`, and called BOTH, extending one
                     with the other. Every injection point was reported twice.

  stranded the       The `results["summary"]` block ended up AFTER a `return`,
  summary            so it became unreachable and the key vanished from the
                     output. `cli.py` and two TUI screens read
                     `data.get("summary", {})`, so they silently rendered
                     nothing while every other adapter still emitted one.

Only the first had a failing test. The other two are silent, which is why the
last two tests here are about shape rather than about sqlmap: a parser that is
called twice and a key that quietly disappears both pass a suite that only
checks the happy path of the thing that crashed.
"""
from __future__ import annotations

import importlib

import pytest

from netreaper.tools.sqlmap import SqlmapTool

TWO_POINTS = "Parameter: id (GET)\nParameter: user (POST)\n"


# ── the crash ────────────────────────────────────────────────────────────────


def test_session_args_returns_a_list_rather_than_none():
    """The deleted `return args`. None here becomes `cmd += None` upstream."""
    args = SqlmapTool()._session_args({})
    assert isinstance(args, list)


def test_the_proxy_option_survived():
    """Deleted in the same hunk as the return, under a logging-refactor banner."""
    args = SqlmapTool()._session_args({"proxy": "http://127.0.0.1:8080"})
    assert args == ["--proxy", "http://127.0.0.1:8080"]


def test_build_command_does_not_raise():
    """The end-to-end shape of the crash: every sqlmap run hit this."""
    argv = SqlmapTool().build_command("http://example.com/vuln.php?id=1", {})
    assert argv[0] == "-u"
    assert "--output-dir" in argv


# ── the silent duplicate ─────────────────────────────────────────────────────


def test_injection_points_are_not_double_counted():
    parsed = SqlmapTool().parse_output(TWO_POINTS)
    assert len(parsed["injection_points"]) == 2, parsed["injection_points"]
    assert parsed["injection_points"] == [
        {"parameter": "id", "type": "GET"},
        {"parameter": "user", "type": "POST"},
    ]


def test_there_is_exactly_one_injection_point_parser():
    """The duplicate was added, not renamed, so both existed and both ran.

    Pinning the absence of the second name is crude, but the defect was that
    two functions computed the same thing and the caller used both. One name is
    the invariant worth holding.
    """
    assert not hasattr(SqlmapTool, "_find_injection_points_with_regex")


def test_the_summary_count_agrees_with_the_list_it_counts():
    """The duplicate made these disagree: 2 points reported as 4."""
    parsed = SqlmapTool().parse_output(TWO_POINTS)
    assert parsed["summary"]["injection_points"] == len(parsed["injection_points"])


# ── the silently dropped key ─────────────────────────────────────────────────


def test_sqlmap_still_emits_the_summary_its_consumers_read():
    """cli.py and tui/screens/exploit.py both do data.get("summary", {})."""
    parsed = SqlmapTool().parse_output(TWO_POINTS)
    assert "summary" in parsed, "the key cli.py and two TUI screens read"
    assert set(parsed["summary"]) == {
        "vulnerable",
        "injection_points",
        "databases_found",
        "tables_found",
    }


@pytest.mark.parametrize(
    "module,cls",
    [
        ("sqlmap", "SqlmapTool"),
        ("subfinder", "SubfinderTool"),
        ("gobuster", "GobusterTool"),
        ("nikto", "NiktoTool"),
    ],
)
def test_every_summarising_adapter_still_summarises(module, cls):
    """The convention sqlmap silently fell out of.

    These four all build a results["summary"]. sqlmap stopped, and nothing
    failed, because the consumers use .get with a default. A shape test across
    the family catches the next one to drift.
    """
    tool = getattr(importlib.import_module(f"netreaper.tools.{module}"), cls)()
    assert "summary" in tool.parse_output(""), f"{module} stopped emitting a summary"


# ── the shape of the defect, generalised ─────────────────────────────────────


def test_no_unreachable_code_after_a_return_in_sqlmap():
    """31 lines sat after a `return` and nothing noticed.

    Walks the module's AST rather than reading it, so it stays true as the file
    changes. This is the cheapest possible guard against an autofix that
    "removes dead code" by making live code dead.
    """
    import ast
    import inspect

    import netreaper.tools.sqlmap as mod

    tree = ast.parse(inspect.getsource(mod))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for i, stmt in enumerate(node.body[:-1]):
            if isinstance(stmt, ast.Return):
                nxt = node.body[i + 1]
                offenders.append(f"{node.name}: line {nxt.lineno} is unreachable")
    assert not offenders, "unreachable code:\n  " + "\n  ".join(offenders)
