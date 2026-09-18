# SPDX-License-Identifier: GPL-3.0-or-later
"""The DeepSource findings (issues #59-#69), and the two that are wrong.

Eleven issues, seven distinct rules. Most were real. One pointed at a line where
the actual defect was worse than the rule described, and one would have caused a
safety regression if applied.

  #59  PYL-W0102 mutable default argument      1 occurrence. Real, and the
       parameter turned out to be vestigial: no caller passed it and the body
       never read it, so it is gone rather than defaulted to None.
  #63/#64 PYL-W1203 f-string to logging        77 occurrences. Real. Eager
       formatting does work even when the level is disabled.
  #65  PY-W2000 unused import                  18 occurrences. Real.
  #66/#68 PYL-W0212 protected member access    The interesting one, below.
  #61/#67 PYL-W0706 except handler raises      WRONG, and dangerous. Below.
  #60/#62 PYL-R0201 @staticmethod              69 occurrences of a style
       preference. Not pinned here; converting a bound method to a static one
       changes what a subclass can override, which is a real risk for no
       correctness gain.
  #69  PY-R1000 cyclomatic complexity          15 occurrences. Refactors of
       large functions in a security tool, for a metric. Not pinned here.

THE PROTECTED-MEMBER ONE WAS A CRASH. preflight_runner called
`AutoMonHandler._is_monitor_mode(...)`, and that method does not exist on
AutoMonHandler: it lives on AutoIfaceHandler. Every run of that path raised
AttributeError. Invisible because preflight_runner sits at 10% coverage and
ensure_interface() had never been executed by a test. DeepSource said "protected
member accessed from outside the class"; what was actually there was a call to a
member of the wrong class.

THE EXCEPT-HANDLER ONE IS A FALSE POSITIVE, TWICE. The rule says a handler whose
only statement is `raise` is useless. That is true only when no later handler
would catch the exception. At two of the three sites the next handler is
`except Exception`, so the bare re-raise is the only thing stopping a scope-gate
denial from being swallowed. Measured, not argued: removing it from
ChainExecutor turns a TargetValidationError into `success=False, status=failed`
and the denial disappears into a routine step failure. The third site
(tools/base.py) has a narrow following handler, so the re-raise is redundant
today, and it is kept as the guard against someone widening that handler later.
"""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from netreaper.core.exceptions import TargetValidationError

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"

LOG_LEVELS = frozenset(
    {"debug", "info", "warning", "error", "critical", "exception", "warn"}
)


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"))


# ── #61/#67: the re-raise is load-bearing, so it stays ───────────────────────


def test_a_scope_gate_denial_propagates_out_of_a_chain():
    """Remove the bare re-raise and this denial becomes a routine failure.

    This is the test that makes #61/#67 a won't-fix rather than an opinion.
    """
    from netreaper.chaining.executor import ChainExecutor
    from netreaper.chaining.models import ChainDefinition, ChainStep

    async def denied(step, target, state):
        raise TargetValidationError("denied by the scope gate")

    chain = ChainDefinition(
        id="c", name="c", description="d", steps=[ChainStep(id="s", tool="nmap")]
    )

    with pytest.raises(TargetValidationError):
        asyncio.run(ChainExecutor(step_runner=denied).execute(chain))


@pytest.mark.parametrize(
    "rel", ["chaining/executor.py", "automation/handlers/cleanup.py"]
)
def test_the_denial_reraise_still_precedes_a_broad_handler(rel):
    """Structural pin: the re-raise only matters while `except Exception` follows.

    If that later handler ever narrows, the re-raise becomes redundant and this
    test should be revisited. If the re-raise is deleted while the broad handler
    remains, the denial is swallowed and this fails.
    """
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or len(node.handlers) < 2:
            continue
        names = [
            ast.unparse(h.type) if h.type else "<bare>" for h in node.handlers
        ]
        if "TargetValidationError" not in names:
            continue
        i = names.index("TargetValidationError")
        handler = node.handlers[i]
        assert len(handler.body) == 1 and isinstance(handler.body[0], ast.Raise), (
            f"{rel}: the TargetValidationError handler no longer re-raises; a "
            f"scope-gate denial will be caught by {names[i + 1:]}"
        )
        assert any("Exception" in n for n in names[i + 1 :]), (
            f"{rel}: nothing broad follows the re-raise any more, so it is now "
            f"genuinely redundant. Re-check before removing it."
        )
        return
    raise AssertionError(f"{rel}: no TargetValidationError handler found")


# ── #66/#68: the crash under the style finding ───────────────────────────────


def test_monitor_mode_detection_is_public_on_the_class_that_implements_it():
    from netreaper.automation.handlers.iface import AutoIfaceHandler

    assert hasattr(AutoIfaceHandler, "is_monitor_mode")
    assert not hasattr(AutoIfaceHandler, "_is_monitor_mode"), (
        "both names exist; callers will keep reaching for the private one"
    )


def test_nobody_asks_automonhandler_for_monitor_mode_detection():
    """The exact crash: it has no such member, and never did."""
    from netreaper.automation.handlers.monitor import AutoMonHandler

    assert not hasattr(AutoMonHandler, "is_monitor_mode")
    assert not hasattr(AutoMonHandler, "_is_monitor_mode")

    src = (SRC / "tui" / "helpers" / "preflight_runner.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"is_monitor_mode", "_is_monitor_mode"}:
            continue
        receiver = ast.unparse(node.func.value)
        assert "AutoMon" not in receiver, (
            f"preflight_runner asks {receiver} for monitor-mode detection; that "
            f"class does not implement it and the call raises AttributeError"
        )


def test_monitor_mode_detection_still_works():
    from netreaper.automation.handlers.iface import AutoIfaceHandler

    assert asyncio.run(AutoIfaceHandler().is_monitor_mode("not-an-interface")) is False


def test_the_cleanup_registry_is_still_a_working_singleton():
    """Its init moved out of __new__; the behaviour must not have moved with it."""
    from netreaper.core.cleanup import CleanupRegistry

    first, second = CleanupRegistry(), CleanupRegistry()
    assert first is second, "the singleton broke"

    before = len(first._handlers)
    first.register(lambda: None, priority=10)
    assert len(CleanupRegistry()._handlers) == before + 1, (
        "state is no longer shared, so __init__ is re-initialising the instance"
    )


# ── the classes, guarded so the findings cannot come back ────────────────────


def test_no_logging_call_uses_an_f_string():
    """#63/#64. Eager formatting runs even when the level is disabled."""
    offenders = []
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", None) not in LOG_LEVELS:
                continue
            if node.args and isinstance(node.args[0], ast.JoinedStr):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not offenders, (
        "logging call(s) formatting their message eagerly; pass %s and the "
        "values as arguments:\n  " + "\n  ".join(offenders)
    )


def test_percent_style_logging_has_matching_placeholder_and_argument_counts():
    """The risk the conversion above introduces, checked rather than hoped.

    A miscounted %s only fails when that line is actually logged, which for
    most of these is never during a test run.
    """
    import re

    placeholder = re.compile(r"(?<!%)%[-+ #0]*[\d.*]*[hlL]?[diouxXeEfFgGcrsa]")
    checked, bad = 0, []
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", None) not in LOG_LEVELS:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            fmt = node.args[0].value
            if not isinstance(fmt, str) or "%" not in fmt:
                continue
            checked += 1
            want = len(placeholder.findall(fmt.replace("%%", "")))
            got = len(node.args) - 1
            if want != got:
                bad.append(
                    f"{path.relative_to(SRC)}:{node.lineno}: {want} placeholder(s), "
                    f"{got} argument(s): {fmt[:50]!r}"
                )
    assert checked > 50, f"only checked {checked}; the scan is not finding them"
    assert not bad, "logging format/argument mismatch:\n  " + "\n  ".join(bad)


def test_no_function_has_a_mutable_default_argument():
    """#59. Evaluated once at definition, then shared by every later call."""
    offenders = []
    roots = [SRC, SRC.parents[1] / "tests"]
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                defaults = list(node.args.defaults) + [
                    d for d in node.args.kw_defaults if d
                ]
                for d in defaults:
                    if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                        offenders.append(f"{path.name}:{d.lineno} in {node.name}()")
    assert not offenders, (
        "mutable default argument(s); use None and build inside the body:\n  "
        + "\n  ".join(offenders)
    )


def test_no_unused_imports_in_the_package():
    """#65. Checked through ruff, which already resolves this correctly."""
    import subprocess

    ruff = SRC.parents[1] / ".venv" / "bin" / "ruff"
    if not ruff.exists():
        pytest.skip("ruff not available in this environment")
    result = subprocess.run(
        [str(ruff), "check", str(SRC), "--select", "F401", "--output-format", "concise"],
        capture_output=True,
        text=True,
    )
    hits = [ln for ln in result.stdout.splitlines() if ":" in ln and "F401" in ln]
    assert not hits, "unused import(s):\n  " + "\n  ".join(hits)
