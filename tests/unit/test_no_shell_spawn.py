# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard: the single spawn seam is real, not just asserted.

M-1 (outside-perspective review): the automation handlers called
create_subprocess_shell with interpolated interface names, which bypassed the
ProcessRunner scope gate and opened a shell-injection vector.

Issue #43 (v11.0.0 review, HIGH): banning *shell* spawns was not enough. The
"single spawn seam" invariant that ``core/process.py`` and ``safety/scope.py``
both assert was false, because ~15 sites called ``create_subprocess_exec`` or
``subprocess.run`` directly. Those spawns skip the gate, the timeout, the
process-group teardown and the hash-chained audit trail. This module now fails
on any spawn outside the seam, so the invariant is enforced rather than claimed.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"

# The one place allowed to spawn anything.
SEAM = "core/process.py"

FORBIDDEN_SHELL = ("create_subprocess_shell(", "os.system(", "os.popen(")

# Actual spawn calls. Deliberately not a bare "subprocess." match, which would
# also hit asyncio.subprocess.PIPE/DEVNULL/Process type annotations.
SPAWN = re.compile(
    r"create_subprocess_exec\(|subprocess\.(?:run|Popen|call|check_output|check_call)\("
)

# Kept deliberately: local diagnostics and installer plumbing with no attack
# surface and no target. They predate the seam and are benign, but they are
# listed one by one so the exemption is a decision, not an accident.
ALLOWED_DIAGNOSTICS = {
    "core/bootstrap.py",                 # env probes incl. connectivity ping
    "detection/tools.py",                # pip install of optional tooling
    "export/exporters.py",               # report renderer hand-off
    "tui/helpers/preflight_runner.py",   # preflight probe
}

# Long-running capture streams. tcpdump/tshark run until killed, which the
# seam's blocking run() structurally cannot host, so the spawn stays local.
# What is NOT tolerated any more is it being ungated: every capture here calls
# _authorise_capture(interface) first, so the gate and the audit line happen
# even though the spawn does not go through run().
#
# tui/screens/exploit.py used to sit here too. It no longer does: searchsploit,
# msfvenom, the msfconsole launch and the live xsstrike attack all route through
# get_process_runner().run() now, with xsstrike naming its target so the scope
# gate actually checks it. That was the CRITICAL blocking the #31 TUI rebuild.
STREAMING_GATED = {
    "tui/screens/traffic.py",
}

QUARANTINED_UNREACHABLE: set[str] = set()

EXEMPT = ALLOWED_DIAGNOSTICS | STREAMING_GATED | QUARANTINED_UNREACHABLE


def _scan(predicate) -> list[str]:
    found: list[str] = []
    for path in SRC.rglob("*.py"):
        rel = path.relative_to(SRC).as_posix()
        found.extend(predicate(rel, path.read_text(encoding="utf-8")))
    return found


def test_no_shell_spawns_in_source():
    def check(rel, text):
        return [f"{rel}: {n}" for n in FORBIDDEN_SHELL if n in text]

    offenders = _scan(check)
    assert not offenders, (
        "shell spawn(s) found; route through ProcessRunner instead:\n"
        + "\n".join(offenders)
    )


def test_no_unseamed_spawns_outside_the_allowlist():
    """Any new direct spawn fails here until it is routed or explicitly exempted."""

    def check(rel, text):
        if rel == SEAM or rel in EXEMPT:
            return []
        return [
            f"{rel}:{i}: {m.group(0)}"
            for i, line in enumerate(text.splitlines(), 1)
            if (m := SPAWN.search(line))
        ]

    offenders = _scan(check)
    assert not offenders, (
        "spawn(s) outside the seam. Route through get_process_runner().run(...) "
        "(or run_host(...) for a local host action) so the call is gated, "
        "timed out, torn down and audited:\n" + "\n".join(offenders)
    )


def test_allowlist_has_no_stale_entries():
    """An exemption that is no longer needed must be deleted, not left to rot."""
    stale = []
    for rel in sorted(EXEMPT):
        path = SRC / rel
        if not path.exists():
            stale.append(f"{rel}: file is gone")
        elif not SPAWN.search(path.read_text(encoding="utf-8")):
            stale.append(f"{rel}: no longer spawns; drop it from the allowlist")
    assert not stale, "stale spawn allowlist entries:\n" + "\n".join(stale)


def test_every_streaming_capture_is_gated_before_it_spawns():
    """The streaming exemption is conditional on the gate being called.

    traffic.py keeps raw spawns because tcpdump runs until killed, so the
    exemption is only defensible while every one of them authorises first.
    """
    src = (SRC / "tui" / "screens" / "traffic.py").read_text(encoding="utf-8")
    spawns = src.count("create_subprocess_exec(")
    gates = src.count("_authorise_capture(")
    assert gates >= spawns - 1, (
        f"{spawns} spawns but only {gates} authorisation calls in traffic.py; "
        "a capture that does not gate first is an ungated credential sniffer"
    )
