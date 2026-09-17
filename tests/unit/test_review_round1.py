# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for round-1 independent-review fixes (F1-F9)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.automation.handlers.cleanup import AutoCleanupHandler
from netreaper.core.exceptions import SubprocessError, TargetValidationError
from netreaper.core.process import ProcessRunner
from netreaper.core.validation import require_bssid, valid_bssid
from netreaper.safety.scope import (
    Engagement,
    Scope,
    ScopeGate,
    Tier,
    get_scope_gate,
    DANGEROUS_OPS_PHRASE,
)
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.airodump import AirodumpTool
from netreaper.wireless import eapol
from netreaper.wireless.eviltwin import EvilTwin
from netreaper.wireless.wps import candidate_pins


@pytest.fixture(autouse=True)
def _arm_global_gate():
    """Arm the global scope gate for the evil-twin SSID ("N") these tests clone.
    Only affects EvilTwin.start(), which uses the global gate; tests that build a
    local ScopeGate() for a ProcessRunner are unaffected.
    """
    get_scope_gate().set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(essids={"N"}), max_tier=Tier.MITM,
                   confirmed_tiers=frozenset({Tier.SINGLE_TARGET, Tier.BROADCAST, Tier.MITM}), dangerous_ops_phrase=DANGEROUS_OPS_PHRASE)
    )
    yield
    get_scope_gate().clear_engagement()

# --- F1: ProcessRunner kills the child on cancellation, not only self-timeout ---


def test_run_terminates_process_on_cancellation():
    async def scenario():
        runner = ProcessRunner(gate=ScopeGate())
        real = runner._terminate_and_reap
        killed = []

        async def spy(proc):
            killed.append(proc)
            await real(proc)  # actually kill+reap it, so the test leaks nothing

        runner._terminate_and_reap = spy  # type: ignore[method-assign]
        task = asyncio.create_task(runner.run(["sleep", "30"], host_action=True))
        await asyncio.sleep(0.15)  # let the process actually spawn
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return killed

    assert asyncio.run(scenario()), "cancelled run must terminate the spawned process"


# --- F5: cleanup never swallows a scope-gate denial ---


def test_cleanup_all_reraises_target_validation_error():
    AutoCleanupHandler.clear_cleanup_stack()

    async def denied():
        raise TargetValidationError("bad interface in a cleanup action")

    AutoCleanupHandler.register_cleanup("bad", denied)
    with pytest.raises(TargetValidationError):
        asyncio.run(AutoCleanupHandler.cleanup_all())
    AutoCleanupHandler.clear_cleanup_stack()


def test_cleanup_all_still_swallows_ordinary_failures():
    AutoCleanupHandler.clear_cleanup_stack()

    async def boom():
        raise RuntimeError("transient")

    AutoCleanupHandler.register_cleanup("boom", boom)
    assert asyncio.run(AutoCleanupHandler.cleanup_all()) is False
    AutoCleanupHandler.clear_cleanup_stack()


# --- F6: WPS rejects a malformed BSSID with TargetValidationError, not ValueError ---


def test_valid_bssid_forms():
    assert valid_bssid("AA:BB:CC:DD:EE:FF")
    assert valid_bssid("aa-bb-cc-dd-ee-ff")
    assert valid_bssid("001122334455")
    assert not valid_bssid("not-a-bssid")
    assert not valid_bssid("AA:BB:CC:DD:EE")  # too short


def test_wps_candidate_pins_rejects_bad_bssid():
    with pytest.raises(TargetValidationError):
        candidate_pins("not-a-real-bssid")
    with pytest.raises(TargetValidationError):
        require_bssid("zz:zz:zz:zz:zz:zz")


# --- F7: eapol parser robustness ---


def _mac_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def _m1_with_pmkid(mic_len, pmkid=bytes(range(16)), ap="AA:BB:CC:DD:EE:01",
                   sta="11:22:33:44:55:66"):
    kde = bytes([0xDD, 0x14]) + b"\x00\x0f\xac" + b"\x04" + pmkid
    keyframe = (
        b"\x02" + (0x0088).to_bytes(2, "big") + b"\x00\x10" + b"\x00" * 8
        + b"\x11" * 32 + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8
        + b"\x00" * mic_len + len(kde).to_bytes(2, "big") + kde
    )
    fc = bytes([0x08, 0x02])
    hdr = fc + b"\x00\x00" + _mac_bytes(sta) + _mac_bytes(ap) + _mac_bytes(ap) + b"\x00\x00"
    llc = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E])
    return hdr + llc + bytes([0x02, 0x03]) + len(keyframe).to_bytes(2, "big") + keyframe


def _pcap(*frames, empty_between=False):
    import struct

    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                     eapol.LINKTYPE_IEEE802_11_RADIO)
    rt = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
    out = gh
    for i, fr in enumerate(frames):
        if empty_between and i == 1:
            out += struct.pack("<IIII", 0, 0, 0, 0)  # zero-length record
        pkt = rt + fr
        out += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return out


def test_pmkid_extracted_with_24_byte_mic():
    # a SHA-384 AKM shifts Key Data by 8 bytes; extraction must still find it
    got = eapol.parse_pmkids(_pcap(_m1_with_pmkid(24)))
    assert len(got) == 1 and got[0].pmkid == bytes(range(16)).hex()


def test_zero_length_record_does_not_end_parse():
    # frame, then a zero-length record, then a PMKID frame that must still be seen
    cap = _pcap(_m1_with_pmkid(16, ap="AA:BB:CC:DD:EE:0A"),
                _m1_with_pmkid(16, ap="AA:BB:CC:DD:EE:0B"),
                empty_between=True)
    aps = {p.bssid for p in eapol.parse_pmkids(cap)}
    assert "AA:BB:CC:DD:EE:0B" in aps  # frame after the empty record survived


# --- F9: wireless adapters reject a malformed/flag-like interface ---


def test_airodump_rejects_bad_interface():
    with pytest.raises(TargetValidationError):
        AirodumpTool().build_command("-x", {"bssid": "AA:BB:CC:DD:EE:01"})


def test_aireplay_rejects_bad_interface():
    with pytest.raises(TargetValidationError):
        AireplayTool().build_command("wlan0; rm -rf /", {"attack": "deauth"})


# --- F3: evil-twin re-entrancy + partial-state visibility ---


class _FakeRunner:
    def __init__(self):
        self.cmds = []

    async def __call__(self, cmd, **kw):
        self.cmds.append(cmd)
        return None


def test_eviltwin_rejects_double_start(tmp_path):
    et = EvilTwin(runner=_FakeRunner())
    asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    with pytest.raises(RuntimeError):
        asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))


def test_eviltwin_state_visible_before_daemons(tmp_path):
    # state must be published (with pidfiles) as soon as start() runs, so a later
    # stop() can always undo whatever mutations actually happened
    et = EvilTwin(runner=_FakeRunner())
    state = asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    assert et.state is state
    assert state.hostapd_pidfile and state.dnsmasq_pidfile


# ======================================================================
# Round-2 verification-review fixes
# ======================================================================


class _FlakyRunner:
    """Fails on the Nth iptables call, to simulate a partial-setup failure."""

    def __init__(self, fail_on_nth_iptables: int):
        self.cmds: list[list[str]] = []
        self._n = 0
        self._fail_on = fail_on_nth_iptables

    async def __call__(self, cmd, **kw):
        self.cmds.append(cmd)
        if cmd and cmd[0] == "iptables":
            self._n += 1
            if self._n == self._fail_on:
                raise SubprocessError("iptables failed")
        return None


def test_eviltwin_partial_start_then_retry_is_blocked(tmp_path):
    et = EvilTwin(runner=_FlakyRunner(fail_on_nth_iptables=2))
    with pytest.raises(SubprocessError):
        asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    # partial state remains, so a naive retry must be refused (not silently orphan)
    assert et.state is not None and not et.state.running and et.state.applied_rules
    with pytest.raises(RuntimeError):
        asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    # stop() reconciles: it deletes exactly the rules that were applied
    asyncio.run(et.stop())
    assert et.state.applied_rules == []


def test_eviltwin_restart_after_clean_stop_is_allowed(tmp_path):
    et = EvilTwin(runner=_FakeRunner())
    asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    asyncio.run(et.stop())
    # a clean post-stop state (not running, no rules) permits a fresh start
    asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    assert et.state.running is True


def test_pmkid_not_fabricated_from_trailing_bytes():
    # 16-byte-MIC Key-Data-Length is 0 (no PMKID), but a valid PMKID KDE sits at
    # the 24-byte-MIC offset with an over-long kd_len that overruns the frame.
    # The exact-length check must reject it rather than fabricate a PMKID.
    frame = bytearray(103)
    frame[101], frame[102] = 0x00, 0xFF  # 24-MIC kd_len = 255 (overruns remaining)
    frame += bytes([0xDD, 0x14]) + b"\x00\x0f\xac" + b"\x04" + b"\xAA" * 16
    assert len(frame) == 125
    assert eapol._pmkid_from_m1(bytes(frame)) is None


def test_killall_cleanup_methods_removed():
    # the global-killall stop_hostapd/stop_dnsmasq landmine is gone
    assert not hasattr(AutoCleanupHandler, "stop_hostapd")
    assert not hasattr(AutoCleanupHandler, "stop_dnsmasq")


# ======================================================================
# Round-3 verification-review fixes
# ======================================================================


def test_run_sigkills_process_that_ignores_sigterm():
    # A process that traps SIGTERM must still be killed (SIGKILL escalation) and
    # the run must not hang. Before the fix this blocked forever on proc.wait().
    async def scenario():
        runner = ProcessRunner(gate=ScopeGate())
        runner._grace = 0.3  # short grace so the test is quick
        task = asyncio.create_task(
            runner.run(
                ["bash", "-c", "trap '' TERM; while true; do sleep 1; done"],
                host_action=True,
            )
        )
        await asyncio.sleep(0.3)  # let it spawn and install the trap
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=6)  # must not hang

    asyncio.run(scenario())


def test_pmkid_survives_trailing_fcs():
    frame = _m1_with_pmkid(16)  # a real 16-byte-MIC M1 carrying a PMKID
    assert len(eapol.parse_pmkids(_pcap(frame))) == 1
    # the identical frame with a 4-byte FCS trailer must still yield the PMKID
    got = eapol.parse_pmkids(_pcap(frame + b"\xde\xad\xbe\xef"))
    assert len(got) == 1 and got[0].pmkid == bytes(range(16)).hex()


class _FailAtNthRunner:
    """Fails on the Nth host call, to hit failures before any iptables rule."""

    def __init__(self, fail_on_nth: int):
        self.n = 0
        self._fail_on = fail_on_nth
        self.cmds: list[list[str]] = []

    async def __call__(self, cmd, **kw):
        self.cmds.append(cmd)
        self.n += 1
        if self.n == self._fail_on:
            raise SubprocessError("host op failed")
        return None


def test_eviltwin_retry_blocked_after_failure_before_first_rule(tmp_path):
    # fail on the 2nd host call ("ip link set up"), before any iptables rule
    et = EvilTwin(runner=_FailAtNthRunner(fail_on_nth=2))
    with pytest.raises(SubprocessError):
        asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    assert et.state.applied_rules == []  # no rule applied yet
    assert et.state.dirty  # but a mutation was attempted
    with pytest.raises(RuntimeError):  # so a naive retry is refused
        asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))


# ======================================================================
# Round-4 verification-review fixes (LOW hardening)
# ======================================================================


def test_eapol_tiny_declared_length_still_classifies():
    # a corrupt/too-short 802.1X declared length must not drop an otherwise-valid
    # frame; the parser falls back to the unbounded body so key_info is readable
    frame = bytearray(_m1_with_pmkid(16))
    frame[34], frame[35] = 0x00, 0x02  # EAPOL length field -> 2 (too short)
    parsed = eapol._parse_dot11(bytes(frame))
    assert parsed is not None and parsed.msg == 1


def test_eviltwin_stop_incrementally_untracks_rules(tmp_path):
    class _FailNthDelete:
        def __init__(self, fail_on_nth_delete):
            self.n = 0
            self._fail_on = fail_on_nth_delete

        async def __call__(self, cmd, **kw):
            if cmd[:1] == ["iptables"] and "-D" in cmd:
                self.n += 1
                if self.n == self._fail_on:
                    raise SubprocessError("delete failed")
            return None

    et = EvilTwin(runner=_FailNthDelete(fail_on_nth_delete=2))
    asyncio.run(et.start("wlan0", "N", 6, config_dir=tmp_path))
    assert len(et.state.applied_rules) == 5
    with pytest.raises(SubprocessError):
        asyncio.run(et.stop())
    # the first delete untracked its rule before the second failed
    assert len(et.state.applied_rules) == 4
    assert et.state.dirty  # stop() did not complete, so a stop() is still required
