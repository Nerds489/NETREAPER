# SPDX-License-Identifier: GPL-3.0-or-later
"""Advanced wireless techniques: hidden-SSID reveal, WPA3 classify/downgrade,
isolation check, ARP-spoof, evasion. Pure logic + orchestration shape (no radio)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.core.process import ProcessResult
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.wireless import advanced
from netreaper.wireless.advanced import (
    ArpSpoof,
    HiddenSSIDReveal,
    WPA3Downgrade,
    check_isolation,
    classify_security,
    clone_ap_mac,
    dragonblood_advisory,
    find_hidden_aps,
    is_hidden_ap,
    randomize_mac,
    revealed_essid,
    wpa2_downgrade_config,
)
from netreaper.wireless.scan import AccessPoint, parse_airodump_csv


@pytest.fixture(autouse=True)
def _clean_gate():
    """Keep the process-wide scope gate clean around every test."""
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


def _mitm_engagement(*cidrs: str) -> None:
    """Authorise the given networks up to MITM tier for the current test."""
    get_scope_gate().set_engagement(
        Engagement(
            operator="t",
            authorization_ref="T",
            scope=Scope(cidrs=list(cidrs)),
            max_tier=Tier.MITM,
        )
    )


_HEADER = (
    "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
    "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
)


def _csv(bssid: str, essid: str, privacy: str = "WPA2", auth: str = "PSK") -> str:
    return (
        _HEADER
        + f"{bssid}, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, {privacy}, "
        f"CCMP, {auth}, -40, 100, 0, 0.0.0.0, {len(essid)}, {essid}, \n"
    )


# --- hidden-AP detection (pure) ---


def test_is_hidden_ap_empty_essid():
    assert is_hidden_ap(AccessPoint(bssid="AA:BB:CC:DD:EE:FF", essid=""))


def test_is_hidden_ap_length_marker():
    assert is_hidden_ap(AccessPoint(bssid="AA:BB:CC:DD:EE:FF", essid="<length:  7>"))


def test_is_hidden_ap_visible_is_not_hidden():
    assert not is_hidden_ap(AccessPoint(bssid="AA:BB:CC:DD:EE:FF", essid="HomeNet"))


def test_find_hidden_aps_filters():
    scan = parse_airodump_csv(_csv("AA:BB:CC:DD:EE:FF", "") + "\n\n")
    scan.access_points.append(AccessPoint(bssid="11:22:33:44:55:66", essid="Visible"))
    hidden = find_hidden_aps(scan)
    assert [ap.bssid for ap in hidden] == ["AA:BB:CC:DD:EE:FF"]


def test_revealed_essid_returns_name_when_visible():
    scan = parse_airodump_csv(_csv("AA:BB:CC:DD:EE:FF", "SecretNet"))
    assert revealed_essid(scan, "aa:bb:cc:dd:ee:ff") == "SecretNet"


def test_revealed_essid_none_when_still_hidden():
    scan = parse_airodump_csv(_csv("AA:BB:CC:DD:EE:FF", ""))
    assert revealed_essid(scan, "AA:BB:CC:DD:EE:FF") is None


# --- WPA3 classification (pure) ---


@pytest.mark.parametrize(
    "privacy,auth,expected",
    [
        ("WPA3", "SAE", "wpa3"),
        ("WPA2", "SAE", "wpa3"),  # SAE in auth alone is enough
        ("OWE", "OWE", "owe"),
        ("WPA2", "PSK", "wpa2"),
        ("WPA", "PSK", "wpa"),
        ("WEP", "", "wep"),
        ("OPN", "", "open"),
    ],
)
def test_classify_security(privacy, auth, expected):
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", privacy=privacy, auth=auth)
    assert classify_security(ap) == expected


# --- dragonblood advisory (pure, passive) ---


def test_dragonblood_advisory_lists_cves_and_tools():
    text = dragonblood_advisory().render()
    assert "CVE-2019-9494" in text
    assert "CVE-2019-9496" in text
    assert "dragonslayer" in text
    assert "dragondrain" in text


# --- WPA2 downgrade config (pure) ---


def test_wpa2_downgrade_config_is_wpa2_only_and_banded():
    conf = wpa2_downgrade_config("wlan0", "CorpWiFi", 36)
    assert "ssid=CorpWiFi" in conf
    assert "wpa=2" in conf
    assert "wpa_key_mgmt=WPA-PSK" in conf
    assert "hw_mode=a" in conf  # 5 GHz channel
    assert "wpa_passphrase=12345678" in conf


# --- fakes ---


class FakeRunner:
    """Fake ProcessRunner recording (cmd, kwargs); writes an airodump CSV."""

    def __init__(
        self,
        *,
        reveal_csv: str | None = None,
        ping_ok: bool = True,
        block_arpspoof: bool = False,
        ping_tool_missing: bool = False,
    ):
        self.calls: list[tuple[list[str], dict]] = []
        self._reveal_csv = reveal_csv
        self._ping_ok = ping_ok
        self._block_arpspoof = block_arpspoof
        self._ping_tool_missing = ping_tool_missing

    async def run(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if cmd[0] == "ping" and self._ping_tool_missing:
            from netreaper.core.exceptions import ToolNotFoundError

            raise ToolNotFoundError("ping not installed")
        if cmd[0] == "airodump-ng" and self._reveal_csv is not None:
            # Emit the CSV airodump would have written, at its --write prefix.
            prefix = cmd[cmd.index("--write") + 1]
            from pathlib import Path

            Path(f"{prefix}-01.csv").write_text(self._reveal_csv)
        if cmd[0] == "arpspoof" and self._block_arpspoof:
            # Stay live until the poison task is cancelled, so stop()'s
            # cancel-then-reap path is actually exercised (L1).
            await asyncio.Event().wait()
        rc = 0 if (cmd[0] != "ping" or self._ping_ok) else 1
        return ProcessResult(cmd=list(cmd), returncode=rc)

    def cmd_strings(self) -> list[str]:
        return [" ".join(c) for c, _ in self.calls]


class FakeAireplay:
    def __init__(self):
        self.deauths: list[tuple] = []

    async def deauth_attack(self, interface, bssid, *, client=None, count=10):
        self.deauths.append((interface, bssid, client, count))
        return {"packets_sent": count}


class FakeHostRunner:
    """Fake run_host callable recording (cmd, kwargs)."""

    def __init__(self):
        self.calls: list[tuple[list[str], dict]] = []

    async def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        return ProcessResult(cmd=list(cmd), returncode=0)

    def cmd_strings(self) -> list[str]:
        return [" ".join(c) for c, _ in self.calls]


# --- hidden reveal: orchestration ---


def test_reveal_by_deauth_captures_and_reads_essid():
    runner = FakeRunner(reveal_csv=_csv("AA:BB:CC:DD:EE:FF", "NowVisible"))
    aireplay = FakeAireplay()
    reveal = HiddenSSIDReveal(aireplay=aireplay, runner=runner)
    essid = asyncio.run(
        reveal.reveal_by_deauth(
            "wlan0mon", "AA:BB:CC:DD:EE:FF", 6,
            capture_seconds=1, settle_seconds=0,
        )
    )
    assert essid == "NowVisible"
    # deauth was finite + single-target (no broadcast), scoped to the BSSID
    assert aireplay.deauths[0][1] == "AA:BB:CC:DD:EE:FF"
    assert aireplay.deauths[0][3] == 5  # default finite count
    # the capture was a targeted, channel-locked airodump at ACTIVE_SCAN
    airodump = next(c for c, _ in runner.calls if c[0] == "airodump-ng")
    assert "--bssid" in airodump and "AA:BB:CC:DD:EE:FF" in airodump
    _, kw = next(x for x in runner.calls if x[0][0] == "airodump-ng")
    assert kw["tier"] == Tier.ACTIVE_SCAN
    assert kw["targets"] == ["AA:BB:CC:DD:EE:FF"]


def test_reveal_by_deauth_returns_none_when_still_hidden():
    runner = FakeRunner(reveal_csv=_csv("AA:BB:CC:DD:EE:FF", ""))
    reveal = HiddenSSIDReveal(aireplay=FakeAireplay(), runner=runner)
    essid = asyncio.run(
        reveal.reveal_by_deauth(
            "wlan0mon", "AA:BB:CC:DD:EE:FF", 6, capture_seconds=1, settle_seconds=0
        )
    )
    assert essid is None


def test_reveal_by_deauth_rejects_bad_interface():
    reveal = HiddenSSIDReveal(aireplay=FakeAireplay(), runner=FakeRunner())
    with pytest.raises(TargetValidationError):
        asyncio.run(reveal.reveal_by_deauth("wlan0; rm -rf /", "AA:BB:CC:DD:EE:FF", 6))


def test_reveal_by_probe_runs_mdk4_per_ssid(tmp_path):
    wl = tmp_path / "ssids.txt"
    wl.write_text("# comment\nalpha\n\nbravo\n")
    runner = FakeRunner()
    reveal = HiddenSSIDReveal(runner=runner)
    asyncio.run(reveal.reveal_by_probe("wlan0mon", "AA:BB:CC:DD:EE:FF", wl))
    mdk4 = [(c, kw) for c, kw in runner.calls if c[0] == "mdk4"]
    assert len(mdk4) == 2  # comment + blank line skipped
    for _c, kw in mdk4:
        assert kw["targets"] == ["AA:BB:CC:DD:EE:FF"]
        assert kw["tier"] == Tier.SINGLE_TARGET


def test_reveal_by_probe_missing_wordlist(tmp_path):
    reveal = HiddenSSIDReveal(runner=FakeRunner())
    with pytest.raises(FileNotFoundError):
        asyncio.run(
            reveal.reveal_by_probe("wlan0mon", "AA:BB:CC:DD:EE:FF", tmp_path / "nope.txt")
        )


# --- WPA3 downgrade twin ---


def test_downgrade_start_writes_config_and_starts_hostapd(tmp_path):
    host = FakeHostRunner()
    dg = WPA3Downgrade(runner=host)
    state = asyncio.run(dg.start("wlan0", "CorpWiFi", 6, config_dir=tmp_path))
    assert (tmp_path / "downgrade-hostapd.conf").read_text().count("wpa=2") == 1
    assert state.running and state.dirty
    assert any(c[:3] == ["hostapd", "-B", "-P"] for c, _ in host.calls)


def test_downgrade_double_start_blocked(tmp_path):
    dg = WPA3Downgrade(runner=FakeHostRunner())
    asyncio.run(dg.start("wlan0", "CorpWiFi", 6, config_dir=tmp_path))
    with pytest.raises(RuntimeError):
        asyncio.run(dg.start("wlan0", "CorpWiFi", 6, config_dir=tmp_path))


def test_downgrade_stop_kills_by_pidfile_no_killall(tmp_path):
    host = FakeHostRunner()
    dg = WPA3Downgrade(runner=host)
    asyncio.run(dg.start("wlan0", "CorpWiFi", 6, config_dir=tmp_path))
    (tmp_path / "downgrade-hostapd.pid").write_text("4242\n")
    asyncio.run(dg.stop())
    teardown = host.cmd_strings()
    assert "kill 4242" in teardown
    assert not any("killall" in t for t in teardown)
    assert "ip link set wlan0 down" in teardown
    assert dg.state.running is False and dg.state.dirty is False


def test_downgrade_rejects_bad_interface(tmp_path):
    dg = WPA3Downgrade(runner=FakeHostRunner())
    with pytest.raises(TargetValidationError):
        asyncio.run(dg.start("bad;iface", "CorpWiFi", 6, config_dir=tmp_path))


# --- client isolation ---


def test_check_isolation_reachable_true():
    runner = FakeRunner(ping_ok=True)
    assert asyncio.run(check_isolation("10.0.0.5", runner=runner)) is True
    cmd, kw = runner.calls[0]
    assert cmd[0] == "ping" and "10.0.0.5" in cmd
    assert kw["targets"] == ["10.0.0.5"] and kw["tier"] == Tier.ACTIVE_SCAN


def test_check_isolation_unreachable_false():
    runner = FakeRunner(ping_ok=False)
    assert asyncio.run(check_isolation("10.0.0.5", runner=runner)) is False


# --- ARP spoof ---


def test_arpspoof_start_stop_lifecycle():
    _mitm_engagement("10.0.0.0/24")
    # block_arpspoof keeps the poison tasks LIVE so stop() genuinely cancels and
    # reaps them (rather than finding them already done - the L1 no-op trap).
    runner = FakeRunner(block_arpspoof=True)
    captured: dict = {}

    async def scenario():
        spoof = ArpSpoof(runner=runner)
        await spoof.start("eth0", "10.0.0.1", "10.0.0.5")
        for _ in range(5):  # let both poison tasks enter run() and block
            await asyncio.sleep(0)
        captured["tasks"] = list(spoof._tasks)
        await spoof.stop()
        return spoof

    spoof = asyncio.run(scenario())
    cmds = runner.cmd_strings()
    # forwarding toggled on then off (host actions)
    assert "sysctl -w net.ipv4.ip_forward=1" in cmds
    assert "sysctl -w net.ipv4.ip_forward=0" in cmds
    # two directional poison streams, each at MITM tier scoped to both hosts
    arps = [(c, kw) for c, kw in runner.calls if c[0] == "arpspoof"]
    assert len(arps) == 2
    for _c, kw in arps:
        assert kw["tier"] == Tier.MITM
        assert set(kw["targets"]) == {"10.0.0.1", "10.0.0.5"}
    assert not any("killall" in t for t in cmds)
    # the live poison tasks were cancelled and reaped by stop()
    assert captured["tasks"] and all(t.cancelled() for t in captured["tasks"])
    assert spoof.state.running is False and spoof.state.dirty is False


def test_arpspoof_double_start_blocked():
    _mitm_engagement("10.0.0.0/24")

    async def scenario():
        spoof = ArpSpoof(runner=FakeRunner())
        await spoof.start("eth0", "10.0.0.1", "10.0.0.5")
        await asyncio.sleep(0)
        with pytest.raises(RuntimeError):
            await spoof.start("eth0", "10.0.0.1", "10.0.0.5")
        await spoof.stop()

    asyncio.run(scenario())


def test_arpspoof_rejects_bad_interface():
    spoof = ArpSpoof(runner=FakeRunner())
    with pytest.raises(TargetValidationError):
        asyncio.run(spoof.start("bad iface", "10.0.0.1", "10.0.0.5"))


def test_arpspoof_denied_out_of_scope_without_enabling_forwarding():
    # No engagement (clean gate): the MITM targets are denied up front, BEFORE
    # ip_forward is enabled or any poison stream launches (fail closed).
    runner = FakeRunner()
    spoof = ArpSpoof(runner=runner)
    with pytest.raises(TargetValidationError):
        asyncio.run(spoof.start("eth0", "10.0.0.1", "10.0.0.5"))
    assert not any("ip_forward" in " ".join(c) for c, _ in runner.calls)
    assert spoof.state is None


# --- evasion (MAC) ---


def test_randomize_mac_delegates_to_change_mac(monkeypatch):
    seen = {}

    async def fake_change_mac(interface, new_mac=None, vendor="random"):
        seen.update(interface=interface, new_mac=new_mac, vendor=vendor)
        return "02:11:22:33:44:55"

    monkeypatch.setattr(advanced, "change_mac", fake_change_mac)
    mac = asyncio.run(randomize_mac("wlan0", vendor="intel"))
    assert mac == "02:11:22:33:44:55"
    assert seen == {"interface": "wlan0", "new_mac": None, "vendor": "intel"}


def test_clone_ap_mac_sets_mac_and_channel(monkeypatch):
    seen = {}

    async def fake_change_mac(interface, new_mac=None, vendor="random"):
        seen.update(interface=interface, new_mac=new_mac)
        return new_mac

    monkeypatch.setattr(advanced, "change_mac", fake_change_mac)
    host = FakeHostRunner()
    mac = asyncio.run(clone_ap_mac("wlan0", "AA:BB:CC:DD:EE:FF", 11, runner=host))
    assert mac == "AA:BB:CC:DD:EE:FF"
    assert seen["new_mac"] == "AA:BB:CC:DD:EE:FF"
    assert "iw dev wlan0 set channel 11" in host.cmd_strings()


def test_clone_ap_mac_rejects_bad_bssid(monkeypatch):
    monkeypatch.setattr(advanced, "change_mac", lambda *a, **k: None)
    with pytest.raises(TargetValidationError):
        asyncio.run(clone_ap_mac("wlan0", "not-a-mac", 11, runner=FakeHostRunner()))


def test_clone_ap_mac_normalises_hyphen_and_bare_hex(monkeypatch):
    # M1: require_bssid accepts hyphen/bare-hex; change_mac needs colon-upper form.
    seen: list = []

    async def fake_change_mac(interface, new_mac=None, vendor="random"):
        seen.append(new_mac)
        return new_mac

    monkeypatch.setattr(advanced, "change_mac", fake_change_mac)
    host = FakeHostRunner()
    for form in ("aa-bb-cc-dd-ee-ff", "aabbccddeeff", "Aa:Bb:Cc:Dd:Ee:Ff"):
        asyncio.run(clone_ap_mac("wlan0", form, 6, runner=host))
    assert seen == ["AA:BB:CC:DD:EE:FF"] * 3


# --- L2: teardown / error-path coverage ---


def test_reveal_by_deauth_missing_csv_returns_none():
    # airodump produced no CSV (never started) -> None, missing-capture branch.
    runner = FakeRunner(reveal_csv=None)
    reveal = HiddenSSIDReveal(aireplay=FakeAireplay(), runner=runner)
    essid = asyncio.run(
        reveal.reveal_by_deauth(
            "wlan0mon", "AA:BB:CC:DD:EE:FF", 6, capture_seconds=1, settle_seconds=0
        )
    )
    assert essid is None


def test_reveal_by_deauth_cleans_temp_dir(tmp_path, monkeypatch):
    # M2: the mkdtemp scratch dir is removed on the success path.
    scratch = tmp_path / "cap"

    def fake_mkdtemp(*a, **k):
        scratch.mkdir(parents=True, exist_ok=True)
        return str(scratch)

    monkeypatch.setattr(advanced.tempfile, "mkdtemp", fake_mkdtemp)
    runner = FakeRunner(reveal_csv=_csv("AA:BB:CC:DD:EE:FF", "Shown"))
    reveal = HiddenSSIDReveal(aireplay=FakeAireplay(), runner=runner)
    essid = asyncio.run(
        reveal.reveal_by_deauth(
            "wlan0mon", "AA:BB:CC:DD:EE:FF", 6, capture_seconds=1, settle_seconds=0
        )
    )
    assert essid == "Shown"
    assert not scratch.exists()


def test_check_isolation_tool_missing_returns_false():
    runner = FakeRunner(ping_tool_missing=True)
    assert asyncio.run(check_isolation("10.0.0.5", runner=runner)) is False


def test_downgrade_stop_without_pidfile_no_kill(tmp_path):
    host = FakeHostRunner()
    dg = WPA3Downgrade(runner=host)
    asyncio.run(dg.start("wlan0", "CorpWiFi", 6, config_dir=tmp_path))
    # no pidfile written -> stop() issues no kill, still brings the iface down
    asyncio.run(dg.stop())
    teardown = host.cmd_strings()
    assert not any(t.startswith("kill ") for t in teardown)
    assert "ip link set wlan0 down" in teardown
    assert dg.state.dirty is False
