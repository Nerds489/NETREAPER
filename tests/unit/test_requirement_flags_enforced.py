# SPDX-License-Identifier: GPL-3.0-or-later
"""Every requirement a tool declares must be one the preflight acts on.

``ToolRequirement`` carries a set of ``needs_*`` flags, and the preflight
(``PreflightRunner.prepare_tool``) resolves them one by one: root, target,
interface, wordlist, api key, gpu. The same shape as the root defect (#90/#102)
turned up here too: ``needs_capture_file`` was declared, set ``True`` on
aircrack-ng, given a ``ToolContext.capture_file`` slot, and then read by nothing.
aircrack-ng is driven from the CLI and the chain with its ``.cap`` passed in, so
it never reaches the preflight, and the flag connected to nothing at all.

This is the reachability guard for that surface: a ``needs_*`` field on
``ToolRequirement`` must be referenced in the preflight source, or be named here
as carried-for-documentation with a reason. A new flag that nothing enforces
fails this test rather than sitting dead.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from netreaper.automation.tool_requirements import ToolRequirement

_PREFLIGHT = (
    Path(__file__).resolve().parents[2]
    / "src" / "netreaper" / "tui" / "helpers" / "preflight_runner.py"
)

# needs_* fields the preflight deliberately does not act on, with the reason.
# Distinct from an unenforced flag: these are documentation, not a dangling
# declaration. Keep this list minimal; a new entry needs a real justification.
INFORMATIONAL: dict[str, str] = {
    "needs_network": (
        "defaults True for nearly every tool; the preflight cannot meaningfully "
        "pre-check connectivity, so it is carried for documentation, not enforced"
    ),
}


def _needs_fields() -> list[str]:
    return [
        f.name
        for f in dataclasses.fields(ToolRequirement)
        if f.name.startswith("needs_")
    ]


def test_there_are_needs_fields_to_check():
    """If the introspection stops finding fields, every check below goes green
    for the wrong reason."""
    fields = _needs_fields()
    assert len(fields) >= 5, f"expected several needs_* flags, found {fields}"


def test_every_requirement_flag_is_enforced_or_documented_informational():
    source = _PREFLIGHT.read_text(encoding="utf-8")
    offenders = []
    for name in _needs_fields():
        if name in INFORMATIONAL:
            continue
        if name not in source:
            offenders.append(name)
    assert not offenders, (
        "ToolRequirement declares needs_* flags the preflight never reads "
        "(a declaration connected to nothing):\n  "
        + "\n  ".join(offenders)
        + "\nWire it into PreflightRunner, or add it to INFORMATIONAL with a reason."
    )


def test_informational_flags_are_real_and_still_unreferenced():
    """Stops the exception list going stale: each named flag must still exist and
    still be genuinely unenforced, or it should leave the list."""
    source = _PREFLIGHT.read_text(encoding="utf-8")
    fields = set(_needs_fields())
    stale = []
    for name in INFORMATIONAL:
        if name not in fields:
            stale.append(f"{name}: no longer a field, drop it from INFORMATIONAL")
        elif name in source:
            stale.append(f"{name}: the preflight reads it now, drop it from INFORMATIONAL")
    assert not stale, "stale INFORMATIONAL entries:\n  " + "\n  ".join(stale)
