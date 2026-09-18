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

THE MAIN-BRANCH REPORT (265 findings at 08e3607) is mostly the same classes
seen before this branch fixed them. What remains after it, and the one thing
refused outright:

  PY-R1000 on ProcessRunner.run, 15 branches. REFUSED. It is the single gated
       spawn seam: every subprocess in the framework goes through it, and the
       gate call, the audit record and the spawn are one sequence on purpose.
       Splitting it produces a helper that can be called without the gate,
       which is the exact defect class this repository keeps producing -- a
       path to the dangerous thing that does not go past the check. 15 is also
       below the band DeepSource reports as high risk, every instance of which
       was 16 or more. Pinned by tests/unit/test_no_shell_spawn.py, which
       already requires every spawn site to pair with a gate call.

  PY-A6006 (configuring loggers is security sensitive), 2 occurrences. An
       advisory "look at this" rule, and it has been looked at: core/logging.py
       configures the application's own logger, writes under NETREAPER_LOG_DIR,
       and the credential redaction that matters is in core/audit.py and is
       covered by tests/unit/test_audit_redaction.py.
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
        """Accepts and discards: the test is about the tree, not the render."""

    def mount(self, *_a, **_k) -> None:
        """See update()."""

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


def test_no_local_is_assigned_and_then_never_read_and_no_name_is_undefined():
    """Two classes, both checked through ruff, both earned.

    F841 (assigned, never read): two of the three findings under this rule on
    this branch were real defects rather than tidiness, so it gets a standing
    guard instead of three pinned exceptions.

    F821 (undefined name): `from __future__ import annotations` makes a class
    body's annotations lazy, so `X: ClassVar[...] = {...}` with ClassVar not
    imported creates the class, imports the module and runs the tests without a
    murmur. Importing a module is not evidence that its names resolve.
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
            "F841,F821",
            "--output-format",
            "concise",
        ],
        check=False,  # ruff exits 1 when it finds something; that IS the result
        capture_output=True,
        text=True,
    )
    hits = [ln for ln in result.stdout.splitlines() if "F841" in ln or "F821" in ln]
    assert not hits, "unused local or undefined name:\n  " + "\n  ".join(hits)


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
    checked = 0
    missing: list[str] = []
    for path in sorted((SRC / "tui" / "screens").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            menu = _class_attribute(cls, "MENU_ITEMS")
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


def test_the_aireplay_attack_dispatch_table_names_methods_that_exist():
    """PY-R1000 at aireplay.py:128, refactored to a table. Same class of defect
    as the screen menus above: a table entry naming something that is not there.

    Looked up with [] rather than getattr's default on purpose, so a stale name
    raises instead of quietly falling through to --deauth, which would send a
    deauth where a chopchop was asked for.
    """
    from netreaper.tools.aireplay import AireplayTool

    missing = [
        f"{mode.name} -> {name}"
        for mode, name in AireplayTool.ATTACK_BUILDERS.items()
        if not callable(getattr(AireplayTool, name, None))
    ]
    assert not missing, "attack builders that do not exist:\n  " + "\n  ".join(missing)


def test_no_substring_test_can_never_match_its_own_haystack():
    """`if "WPS pin:" in line.lower()` was false for every input ever.

    Found by running the old and new reaver parsers side by side over the same
    corpus during a complexity refactor, not by reading the line, which had
    looked correct to everyone including the reviews that passed it. The needle
    carries an upper-case "WPS" and the haystack has just been lower-cased.

    The class is small, mechanical and invisible to the eye, so it is pinned:
    a cased literal tested against a .lower() (or .upper()) call is dead code,
    and dead code in a parser means a branch of the tool's output is silently
    not handled.
    """
    offenders = []
    for root in (SRC, SRC.parents[1] / "tests"):
        for path in sorted(root.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover
                continue
            folded = _case_folded_names(tree)
            for node in ast.walk(tree):
                dead = _dead_substring_test(node, folded)
                if dead:
                    offenders.append(f"{path.relative_to(root.parent)}:{node.lineno}: {dead}")
    assert not offenders, (
        "substring test that cannot match:\n  " + "\n  ".join(offenders)
    )


def _class_attribute(cls: ast.ClassDef, name: str):
    """The value node assigned to a class attribute, annotated or not."""
    found = None
    for node in cls.body:
        if isinstance(node, ast.Assign) and any(
            getattr(t, "id", "") == name for t in node.targets
        ):
            found = node.value
        elif isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == name:
            found = node.value
    return found


def _case_folded_names(tree: ast.AST) -> dict[str, str]:
    """Names bound to a ``.lower()`` or ``.upper()`` call, and which one.

    `lowered = line.lower()` then `"X" in lowered` is the same defect wearing a
    local, so the guard has to resolve the local or it only catches the spelling
    the bug happened to use the first time.
    """
    folded: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        case = getattr(node.value.func, "attr", None)
        if case not in ("lower", "upper"):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                folded[target.id] = case
    return folded


def _dead_substring_test(node: ast.AST, folded: dict[str, str]) -> str | None:
    """A description of the dead comparison at this node, or None."""
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return None
    if not isinstance(node.ops[0], (ast.In, ast.NotIn)):
        return None

    needle, haystack = node.left, node.comparators[0]
    if not (isinstance(needle, ast.Constant) and isinstance(needle.value, str)):
        return None

    if isinstance(haystack, ast.Call):
        case = getattr(haystack.func, "attr", None)
        shown = f"....{case}()"
    elif isinstance(haystack, ast.Name):
        case = folded.get(haystack.id)
        shown = haystack.id
    else:
        return None
    if case not in ("lower", "upper"):
        return None

    want = needle.value.lower() if case == "lower" else needle.value.upper()
    if want == needle.value:
        return None
    return f"{needle.value!r} in {shown} is never true"


def test_every_settings_category_resolves_a_panel_and_a_saver():
    """PY-R1000 at settings.py:667, refactored to one table for both halves.

    _show_category and _save_current_category were two parallel if/elif ladders
    over the same nine category names, which is how a category ends up with a
    panel and no way to save it. They now resolve through CATEGORY_SLUGS, and
    this checks the table against the methods that have to exist.
    """
    from netreaper.tui.screens.settings import SETTINGS_CATEGORIES, SettingsScreen

    declared = {c.name for c in SETTINGS_CATEGORIES}
    tabled = set(SettingsScreen.CATEGORY_SLUGS)
    assert declared == tabled, (
        f"the menu and the dispatch table disagree: "
        f"only in the menu {declared - tabled}, only in the table {tabled - declared}"
    )

    screen = object.__new__(SettingsScreen)
    broken = []
    for name in sorted(declared):
        if screen._composer_for(name) is None:
            broken.append(f"{name}: no panel builder")
        has_saver = screen._saver_for(name) is not None
        should_save = name not in SettingsScreen.CATEGORIES_WITHOUT_A_SAVER
        if has_saver != should_save:
            broken.append(
                f"{name}: saver {'exists' if has_saver else 'missing'}, "
                f"expected {'one' if should_save else 'none'}"
            )
    assert not broken, "settings dispatch:\n  " + "\n  ".join(broken)


def test_the_version_flag_still_works_after_being_renamed():
    """PYL-W0613 at cli.py:34. The parameter is unused and has to exist.

    Nothing reads it: typer needs a parameter so --version/-v is registered,
    and version_callback does the work eagerly before any subcommand runs. It
    is named `_version` rather than suppressed, which is the convention every
    linter already understands, and which is safe here only because the option
    strings are given explicitly so the Python name is free.

    That last part is exactly the sort of thing that is true until it is not,
    so it is checked rather than asserted in a comment.
    """
    import re as _re

    from typer.testing import CliRunner

    from netreaper import __version__
    from netreaper.cli import app

    runner = CliRunner()
    for flag in ("--version", "-v"):
        result = runner.invoke(app, [flag])
        plain = _re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert result.exit_code == 0, f"{flag} exited {result.exit_code}"
        assert __version__ in plain.replace("\n", ""), f"{flag} printed {plain!r}"

    help_text = _re.sub(r"\x1b\[[0-9;]*m", "", runner.invoke(app, ["--help"]).output)
    assert "--version" in help_text, "--version has dropped out of the help"


@pytest.mark.parametrize(
    "raised",
    [ProcessLookupError, PermissionError, OSError, BlockingIOError],
)
def test_a_failed_group_signal_still_falls_back_to_the_process(monkeypatch, raised):
    """PYL-W0714 at process.py:179, and why the narrowing is safe.

    The handler read ``except (ProcessLookupError, PermissionError, OSError)``.
    Both named types are OSError subclasses, so the tuple caught exactly what
    OSError catches while reading as though it were narrower. It is now just
    OSError, and this pins the behaviour that matters: whatever the group signal
    fails with, the signal still reaches the process itself. This is the kill
    path, so a swallowed fallback leaves a spawned tool running.
    """
    import os

    from netreaper.core.process import ProcessRunner

    sent: list[int] = []

    class _Proc:
        pid = 4242

        def send_signal(self, sig):
            sent.append(sig)

    def _boom(*_a, **_k):
        raise raised("group signal refused")

    monkeypatch.setattr(os, "getpgid", lambda _pid: 4242)
    monkeypatch.setattr(os, "killpg", _boom)

    ProcessRunner._signal(_Proc(), 15)
    assert sent == [15], f"{raised.__name__} from killpg did not fall back to the process"


def test_the_process_fallback_does_not_swallow_a_non_oserror(monkeypatch):
    """The inner tuple keeps ValueError for a reason, and the outer one must not
    grow to Exception: a bug in the signal path has to be visible, not quiet."""
    import os

    from netreaper.core.process import ProcessRunner

    class _Proc:
        pid = 4242

        def send_signal(self, _sig):
            raise AssertionError("must not be reached")

    def _boom(*_a, **_k):
        raise RuntimeError("not an OSError")

    monkeypatch.setattr(os, "getpgid", lambda _pid: 4242)
    monkeypatch.setattr(os, "killpg", _boom)

    with pytest.raises(RuntimeError):
        ProcessRunner._signal(_Proc(), 15)


# PYL-R0201 in src, reviewed rather than swept. Every method here never touches
# self and is deliberately still an instance method. The reason is per entry,
# because "it is an override" and "it is one of eight duck-typed
# implementations" are different reasons and only one of them is visible to a
# static analyser.
SELFLESS_BY_DESIGN: dict[str, str] = {
    # Textual calls compose() on the instance; Screen and App both define it,
    # so these are overrides of an external base class that no analyser looking
    # only at this repository can see.
    "MainMenu.compose": "Textual Screen.compose override",
    "CredentialsScreen.compose": "Textual Screen.compose override",
    "HelpScreen.compose": "Textual Screen.compose override",
    "SettingsScreen.compose": "Textual Screen.compose override",
    "FirstRunWizard.compose": "Textual Screen.compose override",
    "ScanWizard.compose": "Textual Screen.compose override",
    # pyee defines EventEmitter.on. `off` is ours, and stays an instance method
    # so the pair reads as one API rather than one override and one static.
    "NetreaperEventBus.on": "pyee EventEmitter.on override",
    "NetreaperEventBus.off": "pairs with on(), which is an override",
    # Eight Auto*Handler classes share no base class and are duck-typed to the
    # same protocol: can_fix / fix / get_ui_prompt. Converting the three that
    # happen not to read self would make one protocol read three ways.
    "AutoDataHandler.can_fix": "duck-typed handler protocol, 8 implementations",
    "AutoKeysHandler.fix": "duck-typed handler protocol, 8 implementations",
    "AutoValidateHandler.can_fix": "duck-typed handler protocol, 8 implementations",
    # LootStorage's sibling methods all take self; delete alone does not, and a
    # repository whose delete is static and whose list_by_type is not is worse
    # than one that is uniform.
    "LootStorage.delete": "uniform with the rest of the repository API",
}


def test_a_method_that_never_touches_self_is_static_or_listed():
    """PYL-R0201 across src, as a decision rather than 28 open findings.

    The rule is right about the fact and blind to the reason: it cannot see
    Textual's Screen, pyee's EventEmitter, or a protocol that exists only
    because eight classes happen to implement the same three method names. So
    the fact is enforced here and each exception has to say which of those it
    is.
    """
    import collections

    method_owners: dict[str, set[str]] = collections.defaultdict(set)
    class_bases: dict[str, list[str]] = {}
    found: list[tuple[str, str]] = []

    trees = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        trees[path] = tree
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            class_bases[node.name] = [
                getattr(b, "id", getattr(b, "attr", "")) for b in node.bases
            ]
            for fn in node.body:
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_owners[fn.name].add(node.name)

    def ancestors(name: str, seen: set[str] | None = None) -> set[str]:
        seen = seen if seen is not None else set()
        for base in class_bases.get(name, []):
            if base and base not in seen:
                seen.add(base)
                ancestors(base, seen)
        return seen

    for path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for fn in node.body:
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if fn.name.startswith("__"):
                    continue
                decorators = {
                    getattr(d, "id", getattr(d, "attr", "")) for d in fn.decorator_list
                }
                if decorators & {
                    "staticmethod",
                    "classmethod",
                    "property",
                    "abstractmethod",
                }:
                    continue
                if not fn.args.args or fn.args.args[0].arg != "self":
                    continue
                if any(
                    isinstance(n, ast.Name) and n.id == "self" for n in ast.walk(fn)
                ):
                    continue
                # An override inside this repository is its own reason, and so
                # is an override of a base this scan cannot see: Textual's
                # Screen, pyee's EventEmitter and abc.ABC are not in src, so a
                # class with an unknown base gets the benefit of the doubt and
                # is listed by name below instead.
                # method_owners is keyed by METHOD name and holds class names.
                # The first cut of this line had the lookup the other way round
                # (`fn.name in method_owners.get(ancestor)`), which is always
                # false, so the guard reported every override in the repository.
                # Exactly the class of defect it was written to catch.
                if any(a in method_owners.get(fn.name, ()) for a in ancestors(node.name)):
                    continue
                found.append((f"{node.name}.{fn.name}", f"{path.name}:{fn.lineno}"))

    unlisted = [f"{q}  ({w})" for q, w in found if q not in SELFLESS_BY_DESIGN]
    assert not unlisted, (
        "method(s) that never touch self and are neither @staticmethod nor "
        "listed in SELFLESS_BY_DESIGN with a reason:\n  " + "\n  ".join(unlisted)
    )

    stale = sorted(set(SELFLESS_BY_DESIGN) - {q for q, _ in found})
    assert not stale, (
        "SELFLESS_BY_DESIGN entries that no longer describe anything; delete "
        "them so the list stays a record of live decisions:\n  " + "\n  ".join(stale)
    )


def test_every_name_in_every___all___actually_exists():
    """PYL-E0603, and it was mine.

    Renaming the two exception classes that shadowed builtins left
    core/exceptions.py's own ``__all__`` still listing ``PermissionError`` and
    ``TimeoutError``, so ``from netreaper.core.exceptions import *`` raised
    AttributeError. Nothing caught it: the package imports fine, every other
    module imports the names directly, and 745 tests passed. Only a star-import
    or a linter that reads __all__ ever touches it.

    The fix DeepSource proposed was to delete the two entries, which would have
    left the renamed classes unexported. They are renamed here instead.
    """
    import importlib

    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not (
                isinstance(node, ast.Assign)
                and any(getattr(t, "id", "") == "__all__" for t in node.targets)
            ):
                continue
            try:
                names = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue  # computed __all__; nothing static to check
            dotted = ".".join(
                path.with_suffix("").relative_to(SRC.parent).parts
            ).removesuffix(".__init__")
            try:
                module = importlib.import_module(dotted)
            except Exception as e:  # noqa: BLE001 - reported, not swallowed
                offenders.append(f"{dotted}: will not import ({type(e).__name__}: {e})")
                continue
            missing = [n for n in names if not hasattr(module, n)]
            if missing:
                offenders.append(f"{dotted}: __all__ names that do not exist: {missing}")

    assert not offenders, (
        "__all__ promising names the module does not have; `import *` raises "
        "AttributeError on every one of these:\n  " + "\n  ".join(offenders)
    )


# ── the autofixes that were refused, and why ──────────────────────────────────
#
# DeepSource proposes a patch alongside each finding. Most are fine and were
# taken. Four were not, and three of those would have broken something. They
# are pinned here rather than argued in a review comment, because the next
# person to click Autofix gets a failing test instead of a regression.


def test_get_db_is_still_a_singleton():
    """The proposed autofix for PYL-W0603 on db/engine.py was:

        async def get_db() -> DatabaseEngine:
            db_engine = DatabaseEngine()
            await db_engine.initialize()
            return db_engine

    That removes the `global` by removing the singleton. Every caller would get
    its own engine, and initialize() re-runs the schema script on every call.
    The rule is about the statement; the statement is doing something.
    """
    src = (SRC / "db" / "engine.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "get_db"
    )
    constructs = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "DatabaseEngine"
    ]
    assert constructs, "get_db no longer builds a DatabaseEngine at all"
    guarded = any(isinstance(n, ast.If) for n in ast.walk(fn))
    assert guarded, (
        "get_db constructs a DatabaseEngine unconditionally: it is no longer a "
        "singleton, so every caller gets its own engine and initialize() re-runs "
        "the schema on every call"
    )


def test_nmap_does_not_import_a_name_defusedxml_does_not_have():
    """The proposed autofix for BAN-B405 was:

        from defusedxml.ElementTree import parse, Element

    defusedxml.ElementTree has no `Element`. That import fails at module load,
    which takes the whole nmap wrapper with it.
    """
    import defusedxml.ElementTree as safe_et

    assert not hasattr(safe_et, "Element"), (
        "defusedxml.ElementTree has gained an Element; this test can be removed"
    )
    src = (SRC / "tools" / "nmap.py").read_text(encoding="utf-8")
    assert "from defusedxml.ElementTree import" not in src or "Element" not in src.split(
        "from defusedxml.ElementTree import"
    )[1].split("\n")[0], "nmap.py imports Element from defusedxml.ElementTree, which has none"
