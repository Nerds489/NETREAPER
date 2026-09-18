# SPDX-License-Identifier: GPL-3.0-or-later
"""The bash completion offered commands the CLI does not have, and vice versa.

`completions/netreaper.bash` carried a header reading "Version: 10.0.0" and a
command list to match. The application is v12. Nine of the thirteen commands it
offered do not exist (menu, wizard, discover, install, session, update, logs,
export, help) and nine that do exist were missing, among them `engage`, which
establishes the authorisation every gated action requires.

This is the same defect as the TUI command palette offering nine screens that
were never written, and as the README documenting commands the CLI would
refuse: a declaration with no path connecting it to anything. The README one
already has a guard (test_readme_commands_exist.py). This is the third place
that needed one.

Read out of the shell file rather than generated into it, because a completion
has to be a static file that a shell can source without Python present.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netreaper.cli import app

COMPLETION = Path(__file__).resolve().parents[2] / "completions" / "netreaper.bash"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _declared(variable: str) -> set[str]:
    """The words assigned to `local <variable>="..."` in the completion file."""
    text = COMPLETION.read_text(encoding="utf-8")
    match = re.search(rf'^\s*local {re.escape(variable)}="([^"]*)"', text, re.M)
    assert match, f"{variable} is not declared in {COMPLETION.name}"
    return set(match.group(1).split())


def _real(argv: list[str]) -> set[str]:
    """The subcommands the CLI itself lists under `<argv> --help`."""
    output = _ANSI.sub("", CliRunner().invoke(app, [*argv, "--help"]).output)
    panel = re.split(r"Commands", output)
    if len(panel) < 2:
        return set()
    return set(re.findall(r"^\s*│\s+([a-z][a-z0-9-]*)\s", panel[-1], re.M))


def test_the_completion_offers_exactly_the_commands_that_exist():
    offered, real = _declared("commands"), _real([])
    assert real, "could not read the CLI's own command list; this test is broken"
    assert offered == real, (
        "bash completion and the CLI disagree.\n"
        f"  offered but does not exist: {sorted(offered - real) or 'none'}\n"
        f"  exists but not offered:     {sorted(real - offered) or 'none'}"
    )


@pytest.mark.parametrize(
    "group",
    ["can", "creds", "engage", "osint", "plugin", "resources", "web", "wifi"],
)
def test_the_completion_offers_exactly_the_subcommands_that_exist(group):
    offered, real = _declared(f"{group}_cmds"), _real([group])
    assert real, f"`netreaper {group}` lists no subcommands; this test is broken"
    assert offered == real, (
        f"bash completion and `netreaper {group}` disagree.\n"
        f"  offered but does not exist: {sorted(offered - real) or 'none'}\n"
        f"  exists but not offered:     {sorted(real - offered) or 'none'}"
    )


def test_the_completion_still_works_without_the_bash_completion_package():
    """`_init_completion || return` meant no bash-completion, no completion, no
    message. The fallback has to be there, and reachable."""
    text = COMPLETION.read_text(encoding="utf-8")
    assert "COMP_WORDS[COMP_CWORD]" in text, (
        "the COMP_WORDS fallback is gone: on a box without bash-completion "
        "installed, pressing Tab will silently do nothing again"
    )
    assert "declare -F _init_completion" in text, (
        "_init_completion is called without checking it exists"
    )


def _code_lines() -> str:
    """The completion with comments stripped.

    Needed because the first cut of the check below matched the comment that
    explains what it is checking for. A guard that reads its own explanation as
    evidence is not a guard.
    """
    lines = COMPLETION.read_text(encoding="utf-8").splitlines()
    return "\n".join(ln.split("#", 1)[0] for ln in lines)


def test_the_completion_does_not_word_split_its_candidates():
    """COMPREPLY=($(compgen ...)) splits and globs every candidate."""
    code = _code_lines()
    assert "mapfile -t COMPREPLY" in code, "candidates are not read with mapfile"
    assert not re.search(r"COMPREPLY=\(\$\(", code), (
        "COMPREPLY=($(...)) is back; a candidate containing a space or a "
        "bracket will come back mangled"
    )
