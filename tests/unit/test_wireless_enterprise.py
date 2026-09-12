# SPDX-License-Identifier: GPL-3.0-or-later
"""WPA-Enterprise credential parsing, hashcat formatting, orchestration (no radio)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.wireless.enterprise import (
    EnterpriseAttack,
    EnterpriseCredential,
    export_hashcat,
    hashcat_5500_line,
    hostapd_wpe_config,
    parse_enterprise_credentials,
)


@pytest.fixture(autouse=True)
def _arm_gate():
    """A rogue enterprise AP is a gated MITM action; authorise its SSID per test."""
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(essids={"CorpNet"}), max_tier=Tier.MITM)
    )
    yield
    get_scope_gate().clear_engagement()

LOG = """\
wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.1X: authentication
mschapv2: Thu Jan 01
	username: alice
	challenge: 11:22:33:44:55:66:77:88
	response: aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11
mschapv2: Thu Jan 01
	username: bob
	challenge: de:ad:be:ef:de:ad:be:ef
	response: 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77
"""


# --- parsing ---


def test_parse_two_credentials():
    creds = parse_enterprise_credentials(LOG)
    assert len(creds) == 2
    assert creds[0].username == "alice"
    assert creds[0].challenge == "11:22:33:44:55:66:77:88"
    assert creds[1].username == "bob"


def test_partial_credential_not_emitted():
    text = "\tusername: carol\n\tchallenge: 11:22:33:44:55:66:77:88\n"  # no response
    assert parse_enterprise_credentials(text) == []


def test_fields_reset_between_credentials():
    # a second full credential after the first must be captured independently
    creds = parse_enterprise_credentials(LOG)
    assert creds[0].username != creds[1].username
    assert creds[0].response != creds[1].response


# --- hashcat formatting ---


def test_hashcat_5500_line_strips_colons():
    cred = EnterpriseCredential("alice", "11:22:33:44:55:66:77:88", "aa:bb:cc:dd")
    assert hashcat_5500_line(cred) == "alice::::aabbccdd:1122334455667788"


def test_export_hashcat_joins_lines():
    out = export_hashcat(parse_enterprise_credentials(LOG))
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("alice::::")
    assert ":" not in lines[0].split("::::", 1)[1].replace(":", "")  # colons stripped


# --- config builder ---


def test_hostapd_wpe_config_has_eap_and_band(tmp_path):
    conf = hostapd_wpe_config("wlan0", "CorpNet", 36, tmp_path, tmp_path / "eap")
    assert "ssid=CorpNet" in conf
    assert "wpa_key_mgmt=WPA-EAP" in conf
    assert "eap_server=1" in conf
    assert "hw_mode=a" in conf  # 5 GHz channel


# --- orchestration ---


class FakeRunner:
    def __init__(self):
        self.cmds: list[list[str]] = []

    async def __call__(self, cmd, **kw):
        self.cmds.append(cmd)
        return None


def test_start_writes_config_and_starts_hostapd_wpe(tmp_path):
    ent = EnterpriseAttack(runner=FakeRunner())
    state = asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))
    assert (tmp_path / "hostapd-wpe.conf").exists()
    assert (tmp_path / "hostapd-wpe.eap_user").exists()
    assert state.running and state.dirty
    joined = [" ".join(c) for c in ent._run.cmds]
    assert any(j.startswith("openssl ") for j in joined)  # cert chain generated
    assert any(j.startswith("hostapd-wpe -B -P") and "-f" in j for j in joined)


def test_read_credentials_parses_log(tmp_path):
    ent = EnterpriseAttack(runner=FakeRunner())
    asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))
    (tmp_path / "hostapd-wpe.log").write_text(LOG)
    creds = ent.read_credentials()
    assert [c.username for c in creds] == ["alice", "bob"]


def test_stop_kills_by_pidfile_and_flushes(tmp_path):
    ent = EnterpriseAttack(runner=FakeRunner())
    asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))
    (tmp_path / "hostapd-wpe.pid").write_text("5150\n")
    asyncio.run(ent.stop())
    teardown = [" ".join(c) for c in ent._run.cmds]
    assert "kill 5150" in teardown
    assert not any("killall" in t for t in teardown)
    assert any("ip addr flush dev wlan0" in t for t in teardown)
    assert ent.state.running is False and ent.state.dirty is False


def test_double_start_blocked(tmp_path):
    ent = EnterpriseAttack(runner=FakeRunner())
    asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))
    with pytest.raises(RuntimeError):
        asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))


def test_invalid_interface_rejected(tmp_path):
    ent = EnterpriseAttack(runner=FakeRunner())
    with pytest.raises(TargetValidationError):
        asyncio.run(ent.start("wlan0; rm -rf /", "CorpNet", 6, config_dir=tmp_path))


def test_start_denied_without_engagement(tmp_path):
    # C-1 gate: standing up a rogue enterprise AP with no engagement is denied,
    # before any cert/config write or host mutation.
    get_scope_gate().clear_engagement()
    fake = FakeRunner()
    ent = EnterpriseAttack(runner=fake)
    with pytest.raises(TargetValidationError):
        asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))
    assert fake.cmds == []
    assert ent.state is None


def test_start_denied_when_essid_out_of_scope(tmp_path):
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(essids={"OtherNet"}), max_tier=Tier.MITM)
    )
    fake = FakeRunner()
    ent = EnterpriseAttack(runner=fake)
    with pytest.raises(TargetValidationError):
        asyncio.run(ent.start("wlan0", "CorpNet", 6, config_dir=tmp_path))
    assert fake.cmds == []
