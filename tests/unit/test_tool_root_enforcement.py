# SPDX-License-Identifier: GPL-3.0-or-later
"""requires_root was declared on four tools and enforced on none (after #90).

#90 made nmap refuse a privileged scan before the spawn, but the fix lived in
``NmapTool``: a ``needs_root`` keyed on the scan type and an ``execute`` that
returned a named failure when unprivileged. Four other wrappers carried
``requires_root=True`` in their METADATA and nothing ever read it:

    reaver.py      requires_root=True
    airodump.py    requires_root=True
    masscan.py     requires_root=True
    aireplay.py    requires_root=True

So a non-root run of any of them reached the process seam and failed there with
masscan's "FAIL: could not determine default interface" or aircrack's terse
"Operation not permitted", far from the cause and looking like a bug rather than
a missing sudo. ``masscan`` is the plainest case: it is a direct CLI command
(``netreaper ... masscan`` -> ``MasscanTool().execute``), exactly nmap's shape.

The gate now lives once in ``BaseToolWrapper.execute`` via ``needs_root``, which
defaults to ``METADATA.requires_root``. The declared flag is enforced for every
tool and any future one; nmap keeps its per-invocation override on top (it sets
``requires_root=False`` and decides from the scan), so the two do not collide.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.plugins.base import PluginMetadata, PluginType
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.airodump import AirodumpTool
from netreaper.tools.base import BaseToolWrapper
from netreaper.tools.masscan import MasscanTool
from netreaper.tools.reaver import ReaverTool

ROOT_TOOLS = [ReaverTool, AirodumpTool, MasscanTool, AireplayTool]


# ── the declared flag is real, and needs_root reads it ────────────────────────


@pytest.mark.parametrize("cls", ROOT_TOOLS, ids=lambda c: c.__name__)
def test_the_four_privileged_tools_declare_and_report_root(cls):
    """The flag exists AND is now reported through needs_root (the thing the
    gate reads). Before, only the first assertion held; the second was False."""
    tool = cls()
    assert tool.METADATA.requires_root is True
    assert tool.needs_root() is True
    assert tool.needs_root({}) is True


def test_a_tool_without_the_flag_does_not_need_root():
    """The default. A wrapper that never set requires_root reports False, so the
    gate leaves it alone."""
    from netreaper.tools.whatweb import WhatWebTool

    assert WhatWebTool().METADATA.requires_root is False
    assert WhatWebTool().needs_root() is False


# ── enforcement in execute(), on a synthetic wrapper to isolate the gate ───────
#
# Using a real tool here would drag in its build_command and option shape; the
# gate is a property of the base class, so a minimal wrapper tests it cleanly.


class _RootTool(BaseToolWrapper):
    TOOL_BINARY = "true"
    DESTRUCTIVE = False
    METADATA = PluginMetadata(
        name="roottool",
        version="1.0.0",
        description="a wrapper that needs root",
        author="test",
        plugin_type=PluginType.TOOL,
        capabilities=[],
        requires_root=True,
    )

    async def initialize(self) -> None:
        # Skip binary resolution; the gate under test runs before this anyway.
        self._initialized = True

    def build_command(self, target, options):
        return ["--go"]

    def parse_output(self, output):
        return {}


class _PlainTool(_RootTool):
    METADATA = PluginMetadata(
        name="plaintool",
        version="1.0.0",
        description="a wrapper that does not need root",
        author="test",
        plugin_type=PluginType.TOOL,
        capabilities=[],
        requires_root=False,
    )


def _run(tool, target, options):
    return asyncio.run(tool.execute(target, options))


@pytest.fixture
def fake_runner(monkeypatch):
    """Record whether the process seam was reached, and never really spawn."""
    calls: list[dict] = []

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    class _Runner:
        async def run(self, *args, **kwargs):
            calls.append(kwargs)
            return _Result()

    monkeypatch.setattr(
        "netreaper.tools.base.get_process_runner", lambda: _Runner()
    )
    return calls


def test_a_root_tool_is_refused_cleanly_when_unprivileged(monkeypatch, fake_runner):
    """Exit through a named failure that names the binary, and never spawn."""
    monkeypatch.setattr("netreaper.tools.base.os.geteuid", lambda: 1000)
    result = _run(_RootTool(), "10.0.0.1", {})
    assert result.success is False
    assert any("root" in e for e in result.errors)
    assert "true" in result.errors[0], "the failure should name the tool binary"
    assert fake_runner == [], "a refused tool must not reach the process seam"


def test_a_dry_run_of_a_root_tool_is_not_gated(monkeypatch, fake_runner):
    """A dry run spawns nothing real, so previewing without root is allowed."""
    monkeypatch.setattr("netreaper.tools.base.os.geteuid", lambda: 1000)
    result = _run(_RootTool(), "10.0.0.1", {"dry_run": True})
    assert fake_runner, "dry run should reach the runner (which handles the preview)"
    assert not (
        result.success is False and result.errors and "root" in result.errors[0]
    ), "a dry run must not be refused for lack of root"


def test_root_runs_the_tool(monkeypatch, fake_runner):
    """With privilege the gate is transparent."""
    monkeypatch.setattr("netreaper.tools.base.os.geteuid", lambda: 0)
    _run(_RootTool(), "10.0.0.1", {})
    assert fake_runner, "as root the tool must reach the runner"


def test_a_tool_without_the_flag_is_never_gated(monkeypatch, fake_runner):
    """The gate keys on the declared need; a tool that declares none reaches the
    runner even unprivileged, so this cannot regress into gating everything."""
    monkeypatch.setattr("netreaper.tools.base.os.geteuid", lambda: 1000)
    _run(_PlainTool(), "10.0.0.1", {})
    assert fake_runner, "a non-root tool must reach the runner without privilege"
