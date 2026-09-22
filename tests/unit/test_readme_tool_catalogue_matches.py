# SPDX-License-Identifier: GPL-3.0-or-later
"""The README said 124 tools. The catalogue held 102.

Not a rounding error: the page listed `cowpatty`, `hcxtools` and `pixiewps`,
none of which are in `TOOL_DEFINITIONS`, and omitted `packetforge-ng`,
`hcxpcapngtool` and `fern-wifi-cracker`, which are. The wireless section alone
was wrong in six places. A reader installing from that list would have asked for
three tools NETREAPER cannot install and missed three it drives natively.

The list drifted because it was maintained by hand, in a second place, with
nothing comparing the two. `test_readme_commands_exist.py` already does this for
the command surface by executing it. This does it for the tool surface by
comparing it, which is the same idea applied to the other half of the page.

Every number and every name in the README's Tool catalogue section is checked
against `ToolRegistry.TOOL_DEFINITIONS`, and the asterisks against the adapters
that actually exist on disk. Adding a tool to the catalogue without touching the
README now fails here rather than shipping a page that quietly understates what
the tool can do.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from netreaper.detection.tools import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
TOOLS_DIR = ROOT / "src" / "netreaper" / "tools"

# `**Wireless** (18)` then a line of `name` / `name`* entries.
_HEADING = re.compile(r"^\*\*([A-Za-z]+)\*\*\s*\((\d+)\)\s*$", re.M)
_ENTRY = re.compile(r"`([^`]+)`(\*?)")


def _readme_catalogue() -> dict[str, list[tuple[str, bool]]]:
    """category -> [(tool name, has an asterisk)], as the README states it."""
    text = README.read_text(encoding="utf-8")
    # Bound the scan to the catalogue section: the installer section below it
    # names categories too, and must not be read as tool entries.
    start = text.index("## Tool catalogue")
    end = text.index("## Tool installer", start)
    section = text[start:end]

    out: dict[str, list[tuple[str, bool]]] = {}
    for m in _HEADING.finditer(section):
        # Only the entry line itself. Reading to the next heading swept up the
        # prose after the last category, where `netreaper status` in backticks
        # parsed as an eleventh utility tool.
        rest = section[m.end() :].lstrip("\n")
        entry_line = rest.split("\n", 1)[0]
        out[m.group(1).lower()] = [
            (name, star == "*") for name, star in _ENTRY.findall(entry_line)
        ]
    return out


def _readme_declared_counts() -> dict[str, int]:
    text = README.read_text(encoding="utf-8")
    start = text.index("## Tool catalogue")
    end = text.index("## Tool installer", start)
    return {
        m.group(1).lower(): int(m.group(2))
        for m in _HEADING.finditer(text[start:end])
    }


def _catalogue() -> dict[str, list[str]]:
    """category -> tool KEYS, which are the addressable strings.

    The key is what `get_tool`, the installer and `check_tool` all look up. One
    entry disagrees with its own `.name` (`netcat` keyed, `nc` named), so the
    key is the one a reader can act on.
    """
    out: dict[str, list[str]] = {}
    for key, entry in ToolRegistry.TOOL_DEFINITIONS.items():
        out.setdefault(entry.category.value, []).append(key)
    return out


def _adapter_binaries() -> set[str]:
    """TOOL_BINARY from every wrapper module, read without importing them."""
    found: set[str] = set()
    for path in TOOLS_DIR.glob("*.py"):
        if path.name in {"__init__.py", "base.py"}:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.AnnAssign):
                continue
            target = node.target
            if isinstance(target, ast.Name) and target.id == "TOOL_BINARY":
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    found.add(node.value.value)
    return found


def test_the_extraction_is_not_vacuous():
    """If the parse stops finding entries, every assertion below passes for nothing."""
    listed = _readme_catalogue()
    assert len(listed) == 9, f"expected 9 category headings, parsed {len(listed)}"
    total = sum(len(v) for v in listed.values())
    assert total > 90, f"only parsed {total} tool entries; the regex has drifted"


def test_every_category_lists_exactly_the_tools_it_has():
    listed = _readme_catalogue()
    actual = _catalogue()

    assert set(listed) == set(actual), (
        f"README categories {sorted(listed)} != catalogue {sorted(actual)}"
    )

    problems: list[str] = []
    for category, entries in listed.items():
        shown = {name for name, _ in entries}
        real = set(actual[category])
        for extra in sorted(shown - real):
            problems.append(f"{category}: README lists `{extra}`, not in the catalogue")
        for missing in sorted(real - shown):
            problems.append(f"{category}: catalogue has `{missing}`, README omits it")
    assert not problems, "the README tool list has drifted:\n  " + "\n  ".join(problems)


def test_each_declared_count_matches_what_is_listed():
    """`**Wireless** (18)` must be followed by 18 names."""
    listed = _readme_catalogue()
    problems = [
        f"{cat}: heading says {declared}, {len(listed[cat])} names follow"
        for cat, declared in _readme_declared_counts().items()
        if declared != len(listed[cat])
    ]
    assert not problems, "\n  ".join(problems)


def test_the_headline_total_matches_the_catalogue():
    """The 124-vs-102 defect, in one assertion."""
    real = len(ToolRegistry.TOOL_DEFINITIONS)
    text = README.read_text(encoding="utf-8")
    claims = {int(n) for n in re.findall(r"(\d+)\s+tools\b", text, re.I)}
    assert claims, "the README no longer states a tool total anywhere"
    wrong = sorted(c for c in claims if c != real)
    assert not wrong, (
        f"README claims {wrong} tools; the catalogue holds {real}"
    )


def test_the_asterisks_mark_exactly_the_tools_with_an_adapter():
    """The asterisk promises NETREAPER parses that tool's output itself."""
    starred = {
        name for entries in _readme_catalogue().values() for name, star in entries if star
    }
    adapters = _adapter_binaries()
    assert starred == adapters, (
        f"README stars {sorted(starred - adapters)} with no adapter; "
        f"adapters exist for {sorted(adapters - starred)} with no star"
    )
