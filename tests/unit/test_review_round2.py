# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for the second review pass (round 2)."""
from __future__ import annotations

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.john import JohnTool
from netreaper.tools.sqlmap import SqlmapTool
from netreaper.wireless.scan import essid_from_airodump_row


@pytest.fixture(autouse=True)
def _clean_gate():
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


# §1: an active/destructive action with no identifiable target is denied
def test_empty_target_destructive_denied():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(bssids={"11:11:11:11:11:11"}), max_tier=Tier.BROADCAST,
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET, Tier.BROADCAST}))
    )
    with pytest.raises(TargetValidationError):
        get_scope_gate().authorize([], tier=Tier.SINGLE_TARGET, destructive=True)


def test_empty_target_passive_allowed():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope())
    )
    get_scope_gate().authorize([], tier=Tier.PASSIVE)  # no raise


# §2: single-host CIDR still hits the protected-address guard
def test_protected_ip_as_slash32_denied():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(cidrs=["169.254.0.0/16"]))
    )
    with pytest.raises(TargetValidationError):
        get_scope_gate().authorize(["169.254.169.254/32"], tier=Tier.ACTIVE_SCAN)


# §3: URL-target adapters scope-check the host, not the whole URL
@pytest.mark.asyncio
async def test_sqlmap_scopes_url_host():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(hostnames={"example.com"}))
    )
    tool = SqlmapTool(); tool._initialized = True
    r = await tool.execute("http://example.com/vuln.php?id=1", {"dry_run": True})
    assert r.success is True


# §4: john is target-less + passive (runs with no engagement)
@pytest.mark.asyncio
async def test_john_is_targetless_passive():
    get_scope_gate().clear_engagement()
    tool = JohnTool(); tool._initialized = True
    assert tool.target_identifiers("/tmp/hashes.txt", {}) == []
    assert tool.execution_tier("/tmp/hashes.txt", {}) is Tier.PASSIVE


# §6: aireplay tiers. A deauth bounded to one in-scope AP is SINGLE_TARGET
# (finite burst or client-specific, the normal handshake technique); only a
# sustained client-less deauth (count 0 = continuous) is an AP-wide DoS.
def test_aireplay_tiers():
    t = AireplayTool()
    ap = "AA:BB:CC:DD:EE:FF"
    assert t.execution_tier("wlan0mon", {"attack": "fakeauth", "bssid": ap}) is Tier.SINGLE_TARGET
    # finite/unspecified-count client-less deauth -> single-target (handshake)
    assert t.execution_tier("wlan0mon", {"attack": "deauth", "bssid": ap}) is Tier.SINGLE_TARGET
    assert t.execution_tier("wlan0mon", {"attack": "deauth", "bssid": ap, "count": 5}) is Tier.SINGLE_TARGET
    # sustained client-less deauth (count 0 = continuous) -> broadcast/DoS
    assert t.execution_tier("wlan0mon", {"attack": "deauth", "bssid": ap, "count": 0}) is Tier.BROADCAST
    # a client-specific deauth is always single-target
    assert t.execution_tier("wlan0mon", {"attack": "deauth", "bssid": ap, "client": "11:22:33:44:55:66", "count": 0}) is Tier.SINGLE_TARGET


# §9: ESSID with comma survives a row that is missing the trailing Key column
def test_essid_helper_handles_missing_key_column():
    row = ["AA:BB:CC:DD:EE:01","t","t","6","130","WPA2","CCMP","PSK","-42","10","0","0.0.0.0","11","My","Home","Net"]
    assert essid_from_airodump_row(row) == "My,Home,Net"
    row_with_key = [*row, ""]
    assert essid_from_airodump_row(row_with_key) == "My,Home,Net"


@pytest.mark.asyncio
async def test_chain_executor_reraises_scope_denial():
    from netreaper.chaining.executor import ChainExecutor
    from netreaper.chaining.models import ChainDefinition, ChainStep

    async def denier(step, target, state):
        raise TargetValidationError("out of scope")

    chain = ChainDefinition(id="x", name="x", description="", steps=[ChainStep(id="a", tool="nmap")])
    with pytest.raises(TargetValidationError):
        await ChainExecutor(step_runner=denier).execute(chain, "1.2.3.4")
