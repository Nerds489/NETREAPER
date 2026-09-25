# SPDX-License-Identifier: GPL-3.0-or-later
"""docs/ must not document commands or files that do not exist.

docs/TOOL_REFERENCE.md was headed v10.0.0 and described `netreaper session`,
`netreaper crack`, `netreaper install` and `netreaper help` -- none of which are
registered commands -- and docs/README.md indexed two files that were never in
the folder. The main README already has test_readme_commands_exist.py executing
every command on it; this is the lighter equivalent for the docs folder: a
top-level `netreaper <word>` named in the docs must be a real command, and a
Markdown link to a sibling doc must resolve.
"""
from __future__ import annotations

import re
from pathlib import Path

from typer.main import get_command

from netreaper.cli import app

DOCS = Path(__file__).resolve().parents[2] / "docs"


def _real_top_level_commands() -> set[str]:
    """The command/group names Typer actually registers on the app."""
    return set(get_command(app).commands.keys())


def _documented_commands(text: str) -> set[str]:
    """Top-level `netreaper <word>` tokens named in prose or code spans."""
    out = set()
    for m in re.finditer(r"netreaper\s+([a-z][a-z-]+)", text):
        word = m.group(1)
        # skip the installer binary invoked as `netreaper-install`
        if word == "install" and "netreaper-install" in text:
            # only count it if it appears as a bare `netreaper install`
            if not re.search(r"netreaper\s+install\b", text):
                continue
        out.add(word)
    return out


# words that follow `netreaper ` in the docs but are not commands: global flags
# and the installer binary's own suffix.
_NOT_COMMANDS = {"install"}  # `netreaper-install` is a separate binary, not a subcommand


def test_docs_do_not_document_nonexistent_top_level_commands():
    real = _real_top_level_commands()
    offenders = []
    for md in sorted(DOCS.glob("*.md")):
        text = md.read_text(encoding="utf-8")
        for word in _documented_commands(text):
            if word in _NOT_COMMANDS:
                continue
            if word not in real:
                offenders.append(f"{md.name}: `netreaper {word}` is not a command")
    assert not offenders, "docs reference commands that do not exist:\n  " + "\n  ".join(
        sorted(set(offenders))
    )


def test_docs_markdown_links_to_sibling_docs_resolve():
    offenders = []
    link = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for md in sorted(DOCS.glob("*.md")):
        for target in link.findall(md.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "#")):
                continue
            resolved = (md.parent / target.split("#")[0]).resolve()
            if not resolved.exists():
                offenders.append(f"{md.name} -> {target} (missing)")
    assert not offenders, "docs link to files that do not exist:\n  " + "\n  ".join(offenders)
