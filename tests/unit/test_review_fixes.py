# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for the DEV-004 code-review findings (§ numbers from the review)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.tools.aireplay import AireplayTool
from netreaper.wireless.scan import parse_airodump_csv


@pytest.fixture(autouse=True)
def _clean_gate():
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


def _ready(t):
    t._initialized = True
    return t


# §1 CRITICAL: aireplay gates the real AP, not the interface name
@pytest.mark.asyncio
async def test_aireplay_gates_bssid_not_interface():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(hostnames={"wlan0mon"}), max_tier=Tier.BROADCAST,
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET, Tier.BROADCAST}))
    )
    with pytest.raises(TargetValidationError):
        await _ready(AireplayTool()).execute(
            "wlan0mon",
            {"attack": "deauth", "bssid": "DE:AD:BE:EF:00:00", "client": "AA:AA:AA:AA:AA:AA",
             "count": 5, "dry_run": True},
        )


@pytest.mark.asyncio
async def test_aireplay_in_scope_ap_allowed():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(bssids={"DE:AD:BE:EF:00:00"}),
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))
    )
    r = await _ready(AireplayTool()).execute(
        "wlan0mon",
        {"attack": "deauth", "bssid": "DE:AD:BE:EF:00:00", "client": "AA:AA:AA:AA:AA:AA",
         "count": 5, "dry_run": True},
    )
    assert r.success is True


# §2: tier ceiling enforced
@pytest.mark.asyncio
async def test_broadcast_denied_under_single_target_ceiling():
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(bssids={"DE:AD:BE:EF:00:00"}),
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))
    )  # default max_tier == SINGLE_TARGET
    with pytest.raises(TargetValidationError):
        await _ready(AireplayTool()).execute(
            "wlan0mon", {"attack": "deauth", "bssid": "DE:AD:BE:EF:00:00", "count": 0, "dry_run": True}
        )


# §6: every Events.X referenced under tools/ resolves on the enum
def test_all_referenced_events_exist():
    from netreaper.orchestration.events import Events

    missing = []
    for path in Path("src/netreaper/tools").glob("*.py"):
        for name in re.findall(r"Events\.([A-Z_]+)", path.read_text()):
            if not hasattr(Events, name):
                missing.append(f"{path.name}:{name}")
    assert not missing, f"referenced but undefined Events members: {missing}"


# §9: a CIDR target that is a subnet of the scope is authorised; otherwise denied
def test_cidr_target_in_scope_allowed_and_out_denied():
    gate = get_scope_gate()
    gate.set_engagement(
        Engagement(operator="t", authorization_ref="T", scope=Scope(cidrs=["10.0.0.0/16"]))
    )
    gate.authorize(["10.0.5.0/24"], tier=Tier.ACTIVE_SCAN)  # subnet -> ok (no raise)
    with pytest.raises(TargetValidationError):
        gate.authorize(["192.168.0.0/24"], tier=Tier.ACTIVE_SCAN)


# §11: ESSID containing a comma is not truncated
def test_essid_with_comma_preserved():
    csv = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:01, t, t, 6, 130, WPA2, CCMP, PSK, -42, 10, 0, 0.0.0.0, 11, My,Home,Net,\n"
    )
    r = parse_airodump_csv(csv)
    assert r.access_points[0].essid == "My,Home,Net"
