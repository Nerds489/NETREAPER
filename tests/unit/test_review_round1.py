# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for round-1 independent-review fixes (F1-F9)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.automation.handlers.cleanup import AutoCleanupHandler
from netreaper.core.exceptions import TargetValidationError
from netreaper.core.process import ProcessRunner
from netreaper.core.validation import require_bssid, valid_bssid
from netreaper.safety.scope import ScopeGate
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.airodump import AirodumpTool
from netreaper.wireless import eapol
from netreaper.wireless.eviltwin import EvilTwin
from netreaper.wireless.wps import candidate_pins

# --- F1: ProcessRunner kills the child on cancellation, not only self-timeout ---


def test_run_terminates_process_on_cancellation():
    async def scenario():
        runner = ProcessRunner(gate=ScopeGate())
        real = ProcessRunner._terminate
        killed = []

        def spy(proc):
            killed.append(proc)
            real(proc)  # actually kill it too, so the test leaks nothing

        runner._terminate = spy  # type: ignore[method-assign]
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
