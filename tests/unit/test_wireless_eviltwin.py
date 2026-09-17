# SPDX-License-Identifier: GPL-3.0-or-later
"""Evil-twin config builders and orchestration teardown (no radio)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate, DANGEROUS_OPS_PHRASE
from netreaper.wireless.eviltwin import (
    EvilTwin,
    channel_hw_mode,
    delete_form,
    dnsmasq_config,
    hostapd_config,
    portal_iptables_rules,
)


@pytest.fixture(autouse=True)
def _arm_gate():
    """Evil-twin is a gated MITM action; authorise the cloned SSID for each test."""
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(essids={"HomeNet"}), max_tier=Tier.MITM,
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET, Tier.BROADCAST, Tier.MITM}), dangerous_ops_phrase=DANGEROUS_OPS_PHRASE)
    )
    yield
    get_scope_gate().clear_engagement()


# --- pure builders ---


@pytest.mark.parametrize("channel,mode", [(1, "g"), (6, "g"), (11, "g"), (14, "g"),
                                          (36, "a"), (149, "a")])
def test_hw_mode_band(channel, mode):
    assert channel_hw_mode(channel) == mode


@pytest.mark.parametrize("channel", [0, 20, 35])
def test_hw_mode_rejects_bad_channel(channel):
    with pytest.raises(ValueError):
        channel_hw_mode(channel)


def test_hostapd_config_derives_band():
    g = hostapd_config("HomeNet", 6, "wlan0")
    assert "hw_mode=g" in g and "channel=6" in g and "ssid=HomeNet" in g
    assert "interface=wlan0" in g
    a = hostapd_config("HomeNet", 36, "wlan0")
    assert "hw_mode=a" in a and "channel=36" in a


def test_dnsmasq_config_spoofs_dns():
    conf = dnsmasq_config("wlan0", "10.0.0.1")
    assert "interface=wlan0" in conf
    assert "address=/#/10.0.0.1" in conf
    assert "dhcp-option=3,10.0.0.1" in conf
    assert "dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h" in conf


def test_portal_iptables_rules_shape():
    rules = portal_iptables_rules("wlan0", "10.0.0.1", 8080)
    assert len(rules) == 5
    prerouting = rules[0]
    assert "PREROUTING" in prerouting and "10.0.0.1:8080" in prerouting
    assert any("MASQUERADE" in r for r in rules)


def test_delete_form_swaps_append_for_delete():
    rule = ["-t", "nat", "-A", "PREROUTING", "-i", "wlan0", "-j", "DNAT"]
    assert delete_form(rule) == ["-t", "nat", "-D", "PREROUTING", "-i", "wlan0",
                                 "-j", "DNAT"]


# --- orchestration ---


class FakeRunner:
    def __init__(self):
        self.cmds: list[list[str]] = []

    async def __call__(self, cmd, **kw):
        self.cmds.append(cmd)
        return None


class FakeAireplay:
    def __init__(self):
        self.calls: list[tuple] = []

    async def deauth_attack(self, interface, bssid, count=10, continuous=False):
        self.calls.append((interface, bssid, count, continuous))
        return {}


def _iptables(cmds):
    return [c for c in cmds if c and c[0] == "iptables"]


def test_start_writes_configs_and_applies_rules(tmp_path):
    fake = FakeRunner()
    et = EvilTwin(runner=fake)
    state = asyncio.run(et.start("wlan0", "HomeNet", 36, config_dir=tmp_path))

    assert "hw_mode=a" in (tmp_path / "hostapd.conf").read_text()
    assert (tmp_path / "dnsmasq.conf").exists()
    assert state.running is True
    assert len(state.applied_rules) == 5

    joined = [" ".join(c) for c in fake.cmds]
    assert any("ip addr add 10.0.0.1/24 dev wlan0" in j for j in joined)
    assert any("sysctl -w net.ipv4.ip_forward=1" in j for j in joined)
    assert any(j.startswith("hostapd -B") and "-P" in j for j in joined)
    assert any(j.startswith("dnsmasq ") and "-C" in j and "-x" in j for j in joined)
    assert len(_iptables(fake.cmds)) == 5  # all appends


def test_stop_deletes_exactly_added_rules_no_flush(tmp_path):
    fake = FakeRunner()
    et = EvilTwin(runner=fake)
    asyncio.run(et.start("wlan0", "HomeNet", 6, config_dir=tmp_path))
    added = _iptables(fake.cmds)  # iptables append commands
    # simulate the daemons having written their pidfiles so teardown can kill them
    (tmp_path / "hostapd.pid").write_text("4242\n")
    (tmp_path / "dnsmasq.pid").write_text("4243\n")
    fake.cmds.clear()

    asyncio.run(et.stop())
    teardown = fake.cmds
    joined = [" ".join(c) for c in teardown]

    # every added rule has a matching delete-form call, and nothing is flushed
    for rule in added:
        expected = ["iptables", *delete_form(rule[1:])]
        assert expected in teardown
    assert not any("-F" in c for c in teardown), "must not flush the whole table"
    assert any("sysctl -w net.ipv4.ip_forward=0" in j for j in joined)
    # daemons are killed by their tracked PID, never a global killall
    assert not any("killall" in c for c in teardown), "must not use global killall"
    assert ["kill", "4242"] in teardown
    assert ["kill", "4243"] in teardown
    assert et.state.running is False
    assert et.state.applied_rules == []


def test_add_delete_symmetry(tmp_path):
    fake = FakeRunner()
    et = EvilTwin(runner=fake)
    asyncio.run(et.start("wlan0", "HomeNet", 6, config_dir=tmp_path))
    adds = sum(1 for c in _iptables(fake.cmds) if "-A" in c or "-I" in c)
    fake.cmds.clear()
    asyncio.run(et.stop())
    dels = sum(1 for c in _iptables(fake.cmds) if "-D" in c)
    assert adds == dels == 5


def test_start_denied_without_engagement(tmp_path):
    # C-1 gate: cloning a network with no active engagement is denied, before
    # any config is written or host mutation attempted.
    get_scope_gate().clear_engagement()
    fake = FakeRunner()
    et = EvilTwin(runner=fake)
    with pytest.raises(TargetValidationError):
        asyncio.run(et.start("wlan0", "HomeNet", 6, config_dir=tmp_path))
    assert fake.cmds == []  # nothing ran
    assert not (tmp_path / "hostapd.conf").exists()
    assert et.state is None


def test_start_denied_when_essid_out_of_scope(tmp_path):
    # Engagement active, but the cloned SSID is not in scope -> denied.
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(essids={"OtherNet"}), max_tier=Tier.MITM,
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET, Tier.BROADCAST, Tier.MITM}), dangerous_ops_phrase=DANGEROUS_OPS_PHRASE)
    )
    fake = FakeRunner()
    et = EvilTwin(runner=fake)
    with pytest.raises(TargetValidationError):
        asyncio.run(et.start("wlan0", "HomeNet", 6, config_dir=tmp_path))
    assert fake.cmds == []


def test_invalid_interface_rejected(tmp_path):
    et = EvilTwin(runner=FakeRunner())
    with pytest.raises(TargetValidationError):
        asyncio.run(et.start("wlan0; rm -rf /", "HomeNet", 6, config_dir=tmp_path))


def test_deauth_real_ap_uses_gated_aireplay():
    rep = FakeAireplay()
    et = EvilTwin(runner=FakeRunner(), aireplay=rep)
    asyncio.run(et.deauth_real_ap("wlan1mon", "AA:BB:CC:DD:EE:01", count=0))
    assert rep.calls == [("wlan1mon", "AA:BB:CC:DD:EE:01", 0, True)]


def test_stop_without_start_is_noop():
    et = EvilTwin(runner=FakeRunner())
    asyncio.run(et.stop())  # no state; must not raise
