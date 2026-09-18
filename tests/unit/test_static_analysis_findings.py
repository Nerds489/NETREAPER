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

THE BRANCH REPORT (76 findings on PR #58) added three more classes, two of them
refused:

  PYL-R0201 @staticmethod, 8 further occurrences. Refused again, and on this
       branch the cost is concrete rather than theoretical: six of the eight are
       duck-typed stubs -- FakeProc.communicate/wait, _StubApp.push_screen_wait,
       _Boom.capture_for_target -- that exist to be called on an instance in
       place of the real object. Converting them to static methods changes the
       call they are standing in for, so the rule would break the tests it is
       reported against.
  PYL-W0603 global statement, 3 occurrences, all lazily built process
       singletons with a monkeypatch seam. Refused; pinned by
       test_the_audit_trail_singleton_stays_injectable below.
  PYL-W0125 constant conditional, 2 occurrences. Correct, and the reason it is
       correct is worth keeping: pinned by
       test_every_screen_menu_entry_names_an_action_that_exists.
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


def test_the_tool_wrapper_handler_stays_narrow():
    """base.py had a `except TargetValidationError: raise` that was dead.

    DeepSource rated it CRITICAL, and it was right about that ONE site: the
    following handler is `(SubprocessError, ToolNotFoundError)`, and
    TargetValidationError subclasses neither, so a denial propagated on its own.
    The re-raise is gone; this is what replaces it. If that handler ever widens
    to `except Exception`, the denial starts getting swallowed and the re-raise
    has to come back.
    """
    tree = ast.parse((SRC / "tools" / "base.py").read_text(encoding="utf-8"))
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef) or fn.name != "execute":
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.Try):
                continue
            for h in node.handlers:
                caught = ast.unparse(h.type) if h.type else "<bare>"
                assert "Exception" not in caught, (
                    f"tools/base.py execute() now catches {caught}, which will "
                    f"swallow a scope-gate denial. Restore the "
                    f"`except TargetValidationError: raise` above it."
                )
        return
    raise AssertionError("BaseToolWrapper.execute not found")


def test_the_denial_really_does_propagate_out_of_the_tool_wrapper():
    """The behaviour the structural test above protects."""
    import asyncio as _aio

    from netreaper.tools.base import BaseToolWrapper

    class _Denying(BaseToolWrapper):
        TOOL_BINARY = "bash"

        def build_command(self, target, options):
            return ["-c", "true"]

        def parse_output(self, output):
            return {}

    tool = _Denying()

    async def _denied(*a, **k):
        raise TargetValidationError("denied by the scope gate")

    import netreaper.tools.base as base_mod

    original = base_mod.get_process_runner

    class _Runner:
        run = staticmethod(_denied)

    base_mod.get_process_runner = lambda: _Runner()
    try:
        with pytest.raises(TargetValidationError):
            _aio.run(tool.execute("10.0.0.1", {}))
    finally:
        base_mod.get_process_runner = original


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
        check=False,  # ruff exits 1 when it finds something; that IS the result
        capture_output=True,
        text=True,
    )
    hits = [ln for ln in result.stdout.splitlines() if ":" in ln and "F401" in ln]
    assert not hits, "unused import(s):\n  " + "\n  ".join(hits)


# ── the preflight entry points, which all raised on every call ───────────────
#
# Six methods in tui/helpers/preflight_runner.py hoisted an import of
# netreaper.tui.modals.preflight_modal (a module that does not exist) to the TOP
# of the function, ABOVE the fast path that needs no modal at all. So:
#
#   ensure_interface     raised even with zero or one interface
#   ensure_monitor_mode  raised even when already in monitor mode
#   ensure_wordlist      raised even when rockyou.txt was already on disk
#   ensure_api_key       raised even when the key was already saved
#   ensure_root          raised whenever not already root
#   prepare_tool         raised before it had even built its ToolContext
#
# prepare_tool is the entry point for every tool run in the traffic, exploit and
# credentials screens, so all three screens' actions were dead. ensure_tool in
# the same file always worked, because its import sits AFTER the shutil.which
# check: the correct pattern was already there to copy.


class _StubApp:
    """Enough App surface for PreflightRunner, with no Textual involved."""

    def __init__(self) -> None:
        self.notifications: list[str] = []

    def notify(self, message, **kwargs) -> None:
        self.notifications.append(str(message))

    def bell(self) -> None:
        """Swallowed. A bell is exactly the non-answer these tests exist to
        catch, so it must not fail the stub either."""

    async def push_screen_wait(self, *a, **k):
        return None


def _runner():
    from netreaper.tui.helpers.preflight_runner import PreflightRunner

    app = _StubApp()
    return PreflightRunner(app), app


@pytest.mark.parametrize(
    "call",
    [
        "prepare_tool",
        "ensure_interface",
        "ensure_monitor_mode",
        "ensure_wordlist",
        "ensure_api_key",
        "ensure_root",
        "ensure_target",
        "ensure_tool",
    ],
)
def test_no_preflight_entry_point_raises_on_a_missing_module(call):
    """A missing optional module must degrade, never explode at the operator."""
    runner, _app = _runner()
    args = {
        "prepare_tool": ("bash",),
        "ensure_interface": ("wireless",),
        "ensure_monitor_mode": ("wlan0",),
        "ensure_wordlist": (),
        "ensure_api_key": ("shodan",),
        "ensure_root": (),
        "ensure_target": ("ip",),
        "ensure_tool": ("bash",),
    }[call]

    try:
        asyncio.run(getattr(runner, call)(*args))
    except ModuleNotFoundError as e:
        raise AssertionError(
            f"{call}() raised {e}. The import is hoisted above the fast path "
            f"again; move it to the point of use as ensure_tool does."
        ) from e


def test_prepare_tool_reaches_ready_for_a_tool_that_is_installed():
    """The whole point: the happy path has to actually complete.

    bash is present on any box this runs on and needs no root, target,
    interface, wordlist, API key or GPU, so it exercises prepare_tool end to end
    with every requirement satisfied.
    """
    runner, _app = _runner()
    ctx = asyncio.run(runner.prepare_tool("bash"))
    assert ctx.ready is True, f"prepare_tool did not complete: {ctx.error}"
    assert ctx.error is None


def test_a_missing_tool_is_reported_not_raised():
    runner, app = _runner()
    ctx = asyncio.run(runner.prepare_tool("no-such-binary-xyz"))
    assert ctx.ready is False
    assert ctx.error, "prepare_tool failed without saying why"
    assert app.notifications, "the operator was told nothing"


def test_the_dangling_imports_are_not_hoisted_above_a_fast_path():
    """Structural: no function may import a KNOWN_DANGLING module before its
    first `if`, because that is exactly what made the fast paths unreachable."""
    tree = ast.parse(
        (SRC / "tui" / "helpers" / "preflight_runner.py").read_text(encoding="utf-8")
    )
    dangling = ("preflight_modal", "handlers.privilege", "handlers.install")
    offenders = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Line numbers inside any try block. ast.walk yields context objects
        # (Load/Store) that carry no lineno, hence the getattr rather than
        # n.lineno, which raised AttributeError on the first run.
        guarded = {
            getattr(n, "lineno", None)
            for t in ast.walk(fn)
            if isinstance(t, ast.Try)
            for n in ast.walk(t)
        } - {None}
        for node in ast.walk(fn):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if not any(d in node.module for d in dangling):
                continue
            if node.lineno in guarded:
                continue  # wrapped in try/except: degrades, does not explode
            offenders.append(f"{fn.name}:{node.lineno} -> {node.module}")
    assert not offenders, (
        "unguarded import(s) of a module that does not exist. Wrap in "
        "try/except ImportError and degrade, or load at the point of use:\n  "
        + "\n  ".join(offenders)
    )


# ── the two "unused variable" findings that were not about unused variables ───
#
# DeepSource reported PYL-W0612 at settings.py:171 and exploit.py:494 as dead
# assignments. Both are, but that is the symptom. One of them is a crash and the
# other is a feature that does nothing, and deleting the line is only the right
# fix for one of them.


class _RemovableWidget:
    """A widget that leaves the tree when removed, which is the whole point."""

    def __init__(self, wid: str, tree: dict) -> None:
        self.id = wid
        self._tree = tree

    def update(self, *_a, **_k) -> None:
        pass

    def mount(self, *_a, **_k) -> None:
        pass

    def query(self, _selector: str = "*") -> list:
        return [w for w in self._tree.values() if w is not self]

    def remove(self) -> None:
        self._tree.pop(self.id, None)


class _FakeScreenTree:
    """``query_one`` over a dict of widgets, raising NoMatches like Textual."""

    def __init__(self, ids: tuple[str, ...]) -> None:
        self.widgets: dict[str, _RemovableWidget] = {}
        for wid in ids:
            self.widgets[wid] = _RemovableWidget(wid, self.widgets)

    def query_one(self, selector: str, _type=None):
        from textual.css.query import NoMatches

        wid = selector.lstrip("#")
        if wid not in self.widgets:
            raise NoMatches(selector)
        return self.widgets[wid]


def test_selecting_a_settings_category_twice_does_not_raise():
    """settings.py:171. Not an unused variable: NoMatches on the second click.

    ``compose()`` yields ``#panel-content`` INSIDE ``#settings-panel``, and
    ``_show_category`` clears that container of everything except
    ``#panel-title``. The first selection therefore deleted ``#panel-content``,
    and the second selection looked it up again. Textual's ``query_one`` raises
    on a miss, so the method blew up on a widget it had itself removed, and the
    Settings screen was single-use. Nothing read the result either way.
    """
    from netreaper.tui.screens.settings import SettingsScreen

    tree = _FakeScreenTree(("settings-panel", "panel-title", "panel-content"))
    screen = object.__new__(SettingsScreen)
    screen.query_one = tree.query_one
    screen._current_category = None
    # The composers build real Textual widgets; the defect is upstream of the
    # dispatch, so they are stubbed out to keep this hermetic.
    for name in dir(SettingsScreen):
        if name.startswith("_compose_"):
            setattr(screen, name, lambda _panel: None)

    screen._show_category("General")
    assert "panel-content" not in tree.widgets, (
        "the clear-out no longer removes #panel-content, so this test has "
        "stopped reproducing the condition it exists to guard"
    )
    screen._show_category("General")  # second click: used to raise NoMatches


def test_lfi_payloads_are_offered_as_urls_against_the_target():
    """exploit.py:494. The URL was built for the operator and then dropped.

    The screen says "test manually" and handed over six bare traversal strings
    with no target attached, while the resolved URL sat in a local that nothing
    read. The details column said the literal word "test" on every row.
    """
    from netreaper.tui.screens.exploit import ExploitScreen

    target = "http://10.0.0.1/page.php?f="
    rows: list[tuple[str, str, str]] = []
    offered: list[str] = []

    screen = object.__new__(ExploitScreen)
    screen._preflight = None
    screen._get_target = lambda: target
    screen._write_output = lambda _m, level="info": None
    screen._add_result = lambda t, e, d="": rows.append((t, e, d))
    screen._set_payload_text = lambda text: offered.append(text)

    asyncio.run(screen.action_lfi_test())

    assert offered, "no payloads were offered at all"
    lines = [ln for ln in offered[0].splitlines() if ln.strip()]
    assert len(lines) >= 5, lines
    assert all(ln.startswith(target) for ln in lines), (
        "the payload area still offers bare payloads with no target:\n  "
        + "\n  ".join(lines)
    )
    assert rows, "nothing was added to the results table"
    assert all(detail.startswith(target) for _t, _p, detail in rows), (
        "the details column is not the URL to test:\n  " + repr(rows)
    )


def test_no_local_is_assigned_and_then_never_read():
    """The class, not the three instances. Checked through ruff (F841).

    Two of the three findings under this rule were real defects rather than
    tidiness, so the rule earns a standing guard rather than three pinned
    exceptions.
    """
    import subprocess

    ruff = SRC.parents[1] / ".venv" / "bin" / "ruff"
    if not ruff.exists():
        pytest.skip("ruff not available in this environment")
    result = subprocess.run(
        [
            str(ruff),
            "check",
            str(SRC),
            "--select",
            "F841",
            "--output-format",
            "concise",
        ],
        check=False,  # ruff exits 1 when it finds something; that IS the result
        capture_output=True,
        text=True,
    )
    hits = [ln for ln in result.stdout.splitlines() if "F841" in ln]
    assert not hits, "assigned and never read:\n  " + "\n  ".join(hits)


# ── the branch report's remaining classes, and what was refused ───────────────


def test_every_screen_menu_entry_names_an_action_that_exists():
    """PYL-W0125 at exploit.py:149 and traffic.py:188, read properly.

    DeepSource called `if action_method:` a constant condition. It is right that
    it is constant, and this is why: every MENU_ITEMS entry resolves. That is
    worth pinning rather than deleting, because the failure mode when it stops
    being true is the one this repo keeps producing -- a click that does nothing
    and says nothing. The dispatch now reports the miss; this makes sure there
    is never one to report.
    """
    screens = SRC / "tui" / "screens"
    checked = 0
    missing: list[str] = []
    for path in sorted(screens.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            menu = None
            for node in cls.body:
                if isinstance(node, ast.Assign) and any(
                    getattr(t, "id", "") == "MENU_ITEMS" for t in node.targets
                ):
                    menu = node.value
                elif (
                    isinstance(node, ast.AnnAssign)
                    and getattr(node.target, "id", "") == "MENU_ITEMS"
                ):
                    menu = node.value
            if menu is None:
                continue
            actions = {
                n.name
                for n in cls.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for entry in ast.literal_eval(menu):
                checked += 1
                if f"action_{entry[2]}" not in actions:
                    missing.append(f"{path.name}:{cls.name}.action_{entry[2]}")
    assert checked >= 20, f"only found {checked} menu entries; the scan is broken"
    assert not missing, (
        "menu entries with no action behind them:\n  " + "\n  ".join(missing)
    )


def test_nmap_result_xml_is_not_parsed_through_the_stdlib():
    """BAN-B405/BAN-B314. The result file is re-read by a different call than
    the one that wrote it, so it is untrusted input by the time it is parsed.

    The DOCTYPE refusal stays as well, and means something separate: nmap does
    not emit one, so a result file that declares a DTD was not produced by the
    scan it claims to be. This pins the parser, which is the part that holds
    whether or not that regex is right.
    """
    src = (SRC / "tools" / "nmap.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    stdlib_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) in ("fromstring", "parse", "XML")
        and getattr(getattr(node.func, "value", None), "id", None) == "ET"
    ]
    assert not stdlib_calls, (
        f"xml.etree.ElementTree parses untrusted nmap output at line(s) "
        f"{stdlib_calls}; use defusedxml.ElementTree"
    )
    assert "defusedxml" in src, "the defusedxml parser is gone from nmap.py"


def test_the_audit_trail_singleton_stays_injectable():
    """PYL-W0603 (global statement) at audit.py:713, refused, and this is why.

    The three `global` statements DeepSource flagged are lazily built process
    singletons. Rewriting `get_audit_trail` as an lru_cache would drop the
    `global` and also drop the seam four tests use to point the trail at a
    tmp_path, which would mean the audit tests stopped testing the audit trail
    the rest of the process actually uses. `get_db` is worse still: it is async,
    so a cache would memoise the coroutine rather than the engine.

    Minor severity, real cost, no correctness gain. Refused, and pinned so the
    refusal is a decision rather than an oversight.
    """
    import netreaper.core.audit as audit_mod

    assert hasattr(audit_mod, "_TRAIL"), "the injection seam is gone"
    sentinel = object()
    original = audit_mod._TRAIL
    try:
        audit_mod._TRAIL = sentinel
        assert audit_mod.get_audit_trail() is sentinel, (
            "get_audit_trail no longer reads the module-level singleton, so "
            "monkeypatching _TRAIL silently does nothing"
        )
    finally:
        audit_mod._TRAIL = original
