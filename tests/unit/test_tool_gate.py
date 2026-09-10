# SPDX-License-Identifier: GPL-3.0-or-later
"""Every tool adapter must pass the scope gate before it spawns."""
from __future__ import annotations

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.tools.nmap import NmapTool


@pytest.fixture(autouse=True)
def _clean_gate():
    gate = get_scope_gate()
    gate.clear_engagement()
    yield
    gate.clear_engagement()


def _ready(tool):
    # skip initialize()'s which() so we exercise the gate, not tool presence
    tool._initialized = True
    return tool


@pytest.mark.asyncio
async def test_adapter_denied_without_engagement():
    tool = _ready(NmapTool())
    with pytest.raises(TargetValidationError):
        await tool.execute("192.168.1.10", {"dry_run": True})


@pytest.mark.asyncio
async def test_adapter_denied_out_of_scope():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(cidrs=["192.168.1.0/24"]))
    )
    tool = _ready(NmapTool())
    with pytest.raises(TargetValidationError):
        await tool.execute("10.0.0.9", {"dry_run": True})


@pytest.mark.asyncio
async def test_adapter_allowed_in_scope():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(cidrs=["192.168.1.0/24"]))
    )
    tool = _ready(NmapTool())
    result = await tool.execute("192.168.1.10", {"dry_run": True})
    assert result.success is True


def test_default_tier_is_declared():
    assert NmapTool.DEFAULT_TIER is Tier.ACTIVE_SCAN
