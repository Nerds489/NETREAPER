# SPDX-License-Identifier: GPL-3.0-or-later
"""The two structural guards: everything imports, and everything is reachable.

A repo-wide analysis found that every defect uncovered over the v11 spine review
had one shape, a declaration with no path connecting it to anything:

    requires_confirmation   a parameter with no reader
    the audit trail         a writer with no report reader
    CleanupRegistry         a registry with no registrant, SIGTERM handlers included
    confirm_dangerous       config with no consumer
    manifest destructive    a flag that drove a "[confirm]" badge and nothing else
    the confirmation gate   a lock with no key: no CLI flag could issue a grant
    5 tool wrappers         ~1,500 lines of callee with no caller
    3 more tool wrappers    reachable only through modules that could not import
    AUTOMOTIVE_MANIFESTS    declared and never registered (added in the same pass
                            that catalogued the others, which is the point)

That is not eight bugs, it is one property: things get built, things get
documented, and nothing forces the two to meet. The v11 rebuild reimplemented
27k lines of Bash in Python with docs written from the Master Plan rather than
from the code, so the docs describe the plan and the code implements a subset.

Reviews do not catch this class reliably: it passed 384 tests, a self-review and
a merge check. A test does, because it asks the one question a reviewer reading a
diff never thinks to ask: can a user actually get here?
"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import re
import warnings
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"


# ── guard 1: every module imports ────────────────────────────────────────────
#
# A module that cannot be imported cannot be tested, cannot be meaningfully
# linted and cannot be reached. Four were in that state: preflight_runner.py
# imported netreaper.automation.preflight and .engine at module level and
# neither was ever written, which took three TUI screens down with it, and
# tui/modals/__init__.py re-exported from a module that does not exist.


def _all_module_names() -> list[str]:
    import netreaper

    return [m.name for m in pkgutil.walk_packages(netreaper.__path__, "netreaper.")]


def test_every_module_in_the_package_imports():
    warnings.filterwarnings("ignore")
    failures = []
    for name in _all_module_names():
        try:
            importlib.import_module(name)
        except BaseException as e:
            failures.append(f"{name}: {type(e).__name__}: {e}")
    assert not failures, (
        "module(s) cannot be imported, so they cannot be tested or reached:\n"
        + "\n".join(failures)
    )


def test_the_package_is_not_empty_so_this_guard_cannot_pass_vacuously():
    """A broken walk_packages would make the guard above trivially green."""
    assert len(_all_module_names()) > 50


# ── guard 2: every tool wrapper is reachable ─────────────────────────────────

# Wrappers with no user-facing path, each with the reason it is tolerated.
# This list is a debt register, not a dumping ground: the test below fails if a
# name here has become reachable (delete the entry) and fails if a new
# unreachable wrapper appears (wire it, or add it here with a reason).
DELIBERATELY_UNWIRED: dict[str, str] = {}

# Whole modules and classes that exist, export a public surface, and are called
# by nothing. Distinct from DELIBERATELY_UNWIRED above (tool wrappers) and from
# KNOWN_DANGLING below (imports of modules that were never written): these were
# written, they work, and no path reaches them.
# Modules that exist, export a public surface, and are reached by nothing a user
# can invoke. Distinct from DELIBERATELY_UNWIRED above (tool wrappers) and from
# KNOWN_DANGLING below (imports of modules never written): these were written,
# they work, and no live path arrives at them.
#
# Each entry declares the importers it is KNOWN to have, so "unreachable" stays
# an assertion about a measured set rather than a claim of zero. An import is not
# a caller: safety/protected.py imports validators, but the only function that
# uses it (check_target_safety) has no caller of its own, so the chain still
# terminates in dead code.
UNREACHABLE_MODULES: dict[str, dict[str, object]] = {
    "safety/validators.py": {
        "importers": frozenset({"safety/protected.py"}),
        "why": (
            "all 10 validators are dead. THREE independent implementations of "
            "'is this a valid IP/MAC/URL/hostname' exist in this tree: this one, "
            "core/validation.py (alive, gates ~12 call sites) and "
            "automation/handlers/validate.py (also dead). They disagree: "
            "validate_cidr accepts 0.0.0.0/0 while the handler's _validate_cidr "
            "refuses it as 'Cannot target entire internet'. The one in the "
            "package named safety is the one nothing calls. Its trailing-newline "
            "anchoring is fixed so wiring it later is safe; which of the three "
            "survives is a design decision"
        ),
    },
    "plugins/lifecycle.py": {
        "importers": frozenset(),
        "why": (
            "PluginLifecycleManager, a state machine with error recording and "
            "the only place a plugin load timeout could plausibly have been "
            "enforced. Zero references in src/ or tests/. discovery.py and "
            "registry.py never import it; the timeout is now enforced in "
            "discovery.load_plugin instead"
        ),
    },
    "chaining/paths.py": {
        "importers": frozenset(),
        "why": (
            "all four public functions have no caller outside their own module. "
            "Part of the inert DataBinding data-flow design; see "
            "tests/unit/test_chaining_dataflow_is_inert.py"
        ),
    },
}


def _importers_of(rel: str) -> set[str]:
    """Modules that import ``rel``, excluding package __init__ re-exports."""
    mod = rel.removesuffix(".py").replace("/", ".")
    found: set[str] = set()
    for other in SRC.rglob("*.py"):
        if other.relative_to(SRC).as_posix() in (rel, ""):
            continue
        if other.name == "__init__.py":
            continue  # a re-export is not a consumer
        for node in ast.walk(ast.parse(other.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and (node.module == f"netreaper.{mod}" or node.module.endswith(f".{mod}"))
            ):
                found.add(other.relative_to(SRC).as_posix())
    return found


def test_unreachable_modules_match_their_declared_importer_set():
    """Each entry must still exist, and its importers must not have grown.

    The register stays short and true: a module that gains a real consumer is
    no longer unreachable and the entry must go, rather than the list absorbing
    whatever happens to be unused this week.
    """
    stale = []
    for rel, entry in sorted(UNREACHABLE_MODULES.items()):
        path = SRC / rel
        if not path.exists():
            stale.append(f"{rel}: gone; drop the entry")
            continue
        assert len(str(entry["why"])) > 40, f"{rel} needs a real reason"
        actual = _importers_of(rel)
        declared = set(entry["importers"])
        gained = sorted(actual - declared)
        lost = sorted(declared - actual)
        if gained:
            stale.append(f"{rel}: newly imported by {gained}; it may be reachable now")
        if lost:
            stale.append(f"{rel}: no longer imported by {lost}; update the entry")
    assert not stale, "UNREACHABLE_MODULES is out of date:\n  " + "\n  ".join(stale)


def test_the_importer_scan_can_actually_see_an_import():
    """Negative control: if this returns nothing, every check above is vacuous."""
    assert _importers_of("safety/scope.py"), "importer scan found nothing at all"

# Where a user-facing path can legitimately originate.
REACHABLE_FROM = (
    SRC / "cli.py",
    SRC / "wireless",
    SRC / "chaining",
    SRC / "automotive",
    SRC / "ble",
    SRC / "web",
    SRC / "mobile",
    SRC / "automation",
    SRC / "tui",
)


def _public_tool_classes() -> dict[str, Path]:
    """Every public *Tool class defined under tools/."""
    found: dict[str, Path] = {}
    for path in (SRC / "tools").rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
            continue
        for node in tree.body:
            if (
                isinstance(node, ast.ClassDef)
                and node.name.endswith("Tool")
                and not node.name.startswith("_")
                and node.name not in {"BaseToolWrapper", "ToolPlugin"}
            ):
                found[node.name] = path
    return found


def _code_references(name: str) -> int:
    """Real code uses of a name, counted from the AST.

    Deliberately not a text search. The first version of this guard used a
    regex over the file, and it passed on a mutation that removed the import
    AND the call, because the name still appeared in a COMMENT a few lines up
    listing the orphans. A guard a comment can satisfy is exactly the vacuous
    pass this module exists to prevent, so comments, docstrings and strings do
    not count: only a Name, an attribute access, or an import.
    """
    count = 0
    for root in REACHABLE_FROM:
        paths = [root] if root.is_file() else list(root.rglob("*.py"))
        for path in paths:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError):  # pragma: no cover
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == name:
                    count += 1
                elif isinstance(node, ast.Attribute) and node.attr == name:
                    count += 1
                elif isinstance(node, ast.ImportFrom):
                    count += sum(
                        1 for a in node.names if name in (a.name, a.asname)
                    )
    return count


def test_every_tool_wrapper_is_reachable_or_declared_unwired():
    classes = _public_tool_classes()
    assert classes, "no tool wrappers found; the discovery above is broken"

    orphans = []
    for name in sorted(classes):
        if name in DELIBERATELY_UNWIRED:
            continue
        if _code_references(name) == 0:
            orphans.append(f"{name} ({classes[name].relative_to(SRC)})")

    assert not orphans, (
        "tool wrapper(s) no user can invoke. Wire a CLI command or register a "
        "manifest, or add the name to DELIBERATELY_UNWIRED with a reason:\n  "
        + "\n  ".join(orphans)
    )


def test_the_unwired_register_has_no_stale_entries():
    """An entry that has become reachable must be deleted, not left to rot."""
    classes = _public_tool_classes()
    stale = []
    for name, reason in DELIBERATELY_UNWIRED.items():
        if name not in classes:
            stale.append(f"{name}: no such tool wrapper any more")
        elif _code_references(name) > 0:
            stale.append(f"{name}: now reachable, drop it (was: {reason})")
    assert not stale, "stale DELIBERATELY_UNWIRED entries:\n  " + "\n  ".join(stale)


def test_every_unwired_entry_gives_a_reason():
    for name, reason in DELIBERATELY_UNWIRED.items():
        assert reason and len(reason) > 20, f"{name} needs a real reason, got {reason!r}"


# ── guard 2b: a manifest set that nothing registers is the same defect ───────


def test_every_manifest_set_has_a_registrar():
    """AUTOMOTIVE_MANIFESTS was declared and registered nowhere.

    WIFI_MANIFESTS has build_wifi_registry; a declared capability set with no
    builder is unreachable by the planner and therefore by a user.
    """
    sets = {}
    for path in SRC.rglob("manifests.py"):
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id.endswith("_MANIFESTS"):
                    sets[node.target.id] = path
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id.endswith("_MANIFESTS"):
                        sets[tgt.id] = path
    assert sets, "no manifest sets found; discovery is broken"

    unregistered = []
    for name, path in sorted(sets.items()):
        domain = path.parent
        text = "\n".join(
            p.read_text(encoding="utf-8")
            for p in [*domain.rglob("*.py"), SRC / "cli.py"]
            if p.name != "manifests.py"
        )
        if not re.search(rf"\b{re.escape(name)}\b", text):
            unregistered.append(f"{name} ({path.relative_to(SRC)})")
    assert not unregistered, (
        "manifest set(s) declared but never registered, so the planner cannot "
        "reach them:\n  " + "\n  ".join(unregistered)
    )


# ── guard 3: imports of modules that do not exist ───────────────────────────
#
# Guard 1 asserts every module in the package imports. It cannot see an import
# of a module that was never written, because such a module is not walked and
# the import sits inside a function where it costs nothing until a user reaches
# it. Fourteen of them were found by resolving every `netreaper.*` import in the
# tree against importlib: six distinct modules, all referenced, none existing.
# netreaper.tui.app was a fifteenth, and it was the entry point for the whole
# TUI, so the operator hit it by running `netreaper` with no arguments.
#
# This is a debt register, not a dumping ground: an entry that has become real
# must be deleted, and a new dangling import fails until it is listed with a
# reason or the module is written.
KNOWN_DANGLING: dict[str, str] = {
    "netreaper.tui.modals.preflight_modal": (
        "the preflight UI (9 sites in helpers/preflight_runner.py). Part of the "
        "TUI rebuild, #31; run_with_preflight degrades with a message instead"
    ),
    "netreaper.automation.preflight": (
        "PreflightChecker. Dangling from the v11 Bash-to-Python rebuild; "
        "designing it belongs with the TUI rebuild, #31"
    ),
    "netreaper.automation.handlers.privilege": (
        "privilege escalation handler for the preflight flow; same family, #31"
    ),
    "netreaper.automation.handlers.install": (
        "tool install handler for the preflight flow; same family, #31"
    ),
}


def _dangling_imports() -> dict[str, list[str]]:
    """Every `netreaper.*` import in the tree that does not resolve."""
    import importlib.util

    found: dict[str, list[str]] = {}
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("netreaper"):
                    names = [node.module]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names if a.name.startswith("netreaper")]
            for name in names:
                try:
                    if importlib.util.find_spec(name) is not None:
                        continue
                except (ImportError, AttributeError, ValueError):
                    pass
                found.setdefault(name, []).append(
                    f"{path.relative_to(SRC)}:{node.lineno}"
                )
    return found


def test_no_import_points_at_a_module_that_was_never_written():
    dangling = _dangling_imports()
    undeclared = {k: v for k, v in dangling.items() if k not in KNOWN_DANGLING}
    assert not undeclared, (
        "import(s) of module(s) that do not exist. Write the module, or add it "
        "to KNOWN_DANGLING with a reason:\n  "
        + "\n  ".join(f"{k} <- {', '.join(v)}" for k, v in sorted(undeclared.items()))
    )


def test_the_dangling_register_has_no_stale_entries():
    """A module that now exists must be dropped from the register."""
    import importlib.util

    stale = []
    for name in KNOWN_DANGLING:
        try:
            if importlib.util.find_spec(name) is not None:
                stale.append(f"{name}: exists now, drop it from KNOWN_DANGLING")
        except (ImportError, AttributeError, ValueError):
            continue
    assert not stale, "stale KNOWN_DANGLING entries:\n  " + "\n  ".join(stale)


def test_every_dangling_entry_gives_a_reason():
    for name, reason in KNOWN_DANGLING.items():
        assert len(reason) > 30, f"{name} needs a real reason, got {reason!r}"


def test_the_dangling_scan_is_not_vacuous():
    """If find_spec resolution broke, every assertion above goes green."""
    import importlib.util

    assert importlib.util.find_spec("netreaper.cli") is not None
    assert importlib.util.find_spec("netreaper.definitely_not_a_module") is None
