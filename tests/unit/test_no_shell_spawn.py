# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard: the single spawn seam is real, not just asserted.

M-1 (outside-perspective review): the automation handlers called
create_subprocess_shell with interpolated interface names, which bypassed the
ProcessRunner scope gate and opened a shell-injection vector.

Issue #43 (v11.0.0 review, HIGH): banning *shell* spawns was not enough. The
"single spawn seam" invariant that ``core/process.py`` and ``safety/scope.py``
both assert was false, because ~15 sites called ``create_subprocess_exec`` or
``subprocess.run`` directly. Those spawns skip the gate, the timeout, the
process-group teardown and the hash-chained audit trail.

REWRITTEN after this guard was found to be permissive. The previous version
asked ``gates >= spawns - 1`` on file-wide substring counts, and three things
were wrong with it at once: the ``def _authorise_capture(`` line counted as a
gate, the ``- 1`` granted another free pass, and counting says nothing about
which function a gate is in or whether it runs before the spawn. Measured, not
argued: two ``await _authorise_capture(interface)`` calls could be deleted from
traffic.py, including the one in front of ``tcpdump -i <iface> -A -s0``, and
this file stayed green. An ungated credential sniffer is the exact thing the
exemption exists to prevent.

So the pairing is now checked per function with the AST: for every function that
spawns, the same function must authorise first, by line number. Counting is
replaced by structure, and the exemptions are pinned to a spawn count so a new
spawn added to an already-exempt file fails instead of inheriting its licence.
"""
from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"

# The one place allowed to spawn anything.
SEAM = "core/process.py"

# Exact (module, attribute) pairs. Not a bare name set: `run` is `subprocess.run`
# but also `asyncio.run` (the event loop) and `ProcessRunner.run` (the seam
# itself), and treating the name alone as a spawn flagged 20 event-loop calls in
# cli.py as unseamed subprocess spawns.
SHELL_SPAWNS = frozenset({
    ("asyncio", "create_subprocess_shell"),
    ("os", "system"),
    ("os", "popen"),
})
EXEC_SPAWNS = frozenset({
    ("asyncio", "create_subprocess_exec"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
})
ALL_SPAWNS = SHELL_SPAWNS | EXEC_SPAWNS

GATE_CALL = "_authorise_capture"

# Local diagnostics and installer plumbing with no target. Pinned to the number
# of spawns each file is allowed, so adding a spawn to an exempt file fails here
# and has to be justified, rather than inheriting the file's existing licence.
ALLOWED_DIAGNOSTICS: dict[str, int] = {
    "core/bootstrap.py": 5,                 # env probes incl. connectivity ping
    "detection/tools.py": 2,                # tool version probe + installer
    "export/exporters.py": 1,               # wkhtmltopdf report hand-off
    "tui/helpers/preflight_runner.py": 1,   # preflight probe
}

# Long-running capture streams. tcpdump/tshark run until killed, which the
# seam's blocking run() structurally cannot host, so the spawn stays local. The
# exemption is conditional: every spawning function must authorise first, which
# test_every_streaming_spawn_is_gated_in_its_own_function enforces.
#
# tui/screens/exploit.py used to sit here too. It no longer does: searchsploit,
# msfvenom, the msfconsole launch and the live xsstrike attack all route through
# get_process_runner().run() now, with xsstrike naming its target so the scope
# gate actually checks it. That was the CRITICAL blocking the #31 TUI rebuild.
STREAMING_GATED: dict[str, int] = {
    "tui/screens/traffic.py": 6,
}

EXEMPT: dict[str, int] = {**ALLOWED_DIAGNOSTICS, **STREAMING_GATED}


def _spawn_calls(tree: ast.AST) -> list[tuple[int, str]]:
    """Every real spawn call in a module, as (lineno, description).

    AST rather than substring search, because the previous version of this file
    was defeated by a docstring: ``_host.py`` describes the
    create_subprocess_shell it no longer calls, and a text scan cannot tell the
    difference between a spawn and a sentence about one.
    """
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not isinstance(fn, ast.Attribute):
            continue
        name = fn.attr
        # Walk to the root of the dotted path: asyncio.subprocess.run -> asyncio.
        base = fn.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if not isinstance(base, ast.Name):
            continue
        root = base.id
        if (root, name) not in ALL_SPAWNS:
            continue
        out.append((node.lineno, f"{root}.{name}()"))
    return out


def _modules() -> list[tuple[str, Path, ast.AST]]:
    mods = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        try:
            mods.append((rel, path, ast.parse(path.read_text(encoding="utf-8"))))
        except SyntaxError as e:  # pragma: no cover
            raise AssertionError(f"{rel} does not parse: {e}") from e
    return mods


def test_the_scan_finds_the_seam_itself_so_it_cannot_pass_vacuously():
    """If detection breaks, every test below goes green for the wrong reason."""
    for rel, _path, tree in _modules():
        if rel == SEAM:
            assert _spawn_calls(tree), "spawn detection is broken: the seam has none"
            return
    raise AssertionError(f"{SEAM} not found")


def test_no_shell_spawns_in_source():
    offenders = []
    for rel, _path, tree in _modules():
        for lineno, what in _spawn_calls(tree):
            root, _, attr = what.partition(".")
            if (root, attr.rstrip("()")) in SHELL_SPAWNS:
                offenders.append(f"{rel}:{lineno}: {what}")
    assert not offenders, (
        "shell spawn(s) found; route through ProcessRunner instead:\n"
        + "\n".join(offenders)
    )


def test_no_unseamed_spawns_outside_the_allowlist():
    """Any new direct spawn fails here until it is routed or explicitly exempted."""
    offenders = []
    for rel, _path, tree in _modules():
        if rel == SEAM or rel in EXEMPT:
            continue
        offenders += [f"{rel}:{ln}: {what}" for ln, what in _spawn_calls(tree)]
    assert not offenders, (
        "spawn(s) outside the seam. Route through get_process_runner().run(...) "
        "(or run_host(...) for a local host action) so the call is gated, "
        "timed out, torn down and audited:\n" + "\n".join(offenders)
    )


def test_exempt_files_may_not_grow_new_spawns():
    """An exemption covers the spawns that were justified, not the file forever.

    Without the pinned count, `core/bootstrap.py` could acquire a spawn of any
    target tomorrow and no test would notice, because the file already holds a
    licence earned by five environment probes.
    """
    wrong = []
    for rel, expected in sorted(EXEMPT.items()):
        path = SRC / rel
        if not path.exists():
            wrong.append(f"{rel}: file is gone; drop the exemption")
            continue
        actual = len(_spawn_calls(ast.parse(path.read_text(encoding="utf-8"))))
        if actual == 0:
            wrong.append(f"{rel}: no longer spawns; drop it from the allowlist")
        elif actual != expected:
            wrong.append(
                f"{rel}: exempted for {expected} spawn(s) but has {actual}. "
                f"If the new one is justified, raise the count deliberately; "
                f"if not, route it through the seam."
            )
    assert not wrong, "spawn allowlist is out of date:\n" + "\n".join(wrong)


def test_every_streaming_spawn_is_gated_in_its_own_function():
    """The streaming exemption is conditional on the gate actually running.

    Per function and by line number, because the count-based version of this
    check passed while two captures, including the credential sniffer, had no
    authorisation at all.
    """
    ungated = []
    for rel in sorted(STREAMING_GATED):
        tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            spawns = _spawn_calls(fn)
            if not spawns:
                continue
            gates = [
                n.lineno
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == GATE_CALL
            ]
            for lineno, what in spawns:
                if not any(g < lineno for g in gates):
                    ungated.append(
                        f"{rel}:{lineno}: {what} in {fn.name}() with no "
                        f"{GATE_CALL}() before it"
                    )
    assert not ungated, (
        "streaming capture(s) that spawn without authorising first. Each one is "
        "an ungated sniffer of third-party traffic:\n  " + "\n  ".join(ungated)
    )


def test_the_gate_helper_itself_reaches_the_scope_gate():
    """_authorise_capture must do what its name says, or the check above is theatre."""
    tree = ast.parse((SRC / "tui" / "screens" / "traffic.py").read_text(encoding="utf-8"))
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name == GATE_CALL:
            names = {
                n.func.id if isinstance(n.func, ast.Name) else n.func.attr
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, (ast.Name, ast.Attribute))
            }
            assert "authorize" in names or "get_scope_gate" in names, (
                f"{GATE_CALL}() never reaches the scope gate; every capture "
                f"'authorised' by it is in fact ungated. Calls found: {sorted(names)}"
            )
            return
    raise AssertionError(f"{GATE_CALL}() is not defined in traffic.py")
