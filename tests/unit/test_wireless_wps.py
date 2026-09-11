# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline WPS PIN algorithms and PIN-list attack orchestration (no radio)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.wireless.wps import (
    STATIC_PINS,
    WpsAttack,
    candidate_pins,
    format_pin,
    generate_pin,
    is_valid_wps_pin,
    pin24,
    pin_asus,
    pin_checksum,
    pin_dlink,
    pin_dlink1,
)

MAC = "00:11:22:33:44:55"


def _independent_checksum(pin7: int) -> int:
    """A separately-written checksum, to genuinely cross-check pin_checksum."""
    d = [int(c) for c in str(pin7).zfill(7)]
    s = 3 * (d[0] + d[2] + d[4] + d[6]) + (d[1] + d[3] + d[5])
    return (10 - s % 10) % 10


# --- checksum / validation ---


def test_checksum_matches_independent_computation():
    for seed in (0, 1234567, 9999999, 3359317, 7654321):
        assert pin_checksum(seed) == _independent_checksum(seed)


def test_famous_default_pin_is_valid():
    assert pin_checksum(1234567) == 0
    assert generate_pin(1234567) == 12345670
    assert is_valid_wps_pin(12345670)
    assert is_valid_wps_pin("12345670")


def test_invalid_pins_rejected():
    assert not is_valid_wps_pin(12345678)  # wrong checksum
    assert not is_valid_wps_pin("1234567")  # too short after zfill? 7 digits
    assert not is_valid_wps_pin("abcdefgh")


def test_generate_pin_always_valid():
    for seed in range(0, 10_000_000, 137_913):
        assert is_valid_wps_pin(generate_pin(seed))


# --- algorithms ---


def test_pin24_exact():
    mac = int(MAC.replace(":", ""), 16)
    nic = mac & 0xFFFFFF
    expected = nic * 10 + _independent_checksum(nic)
    assert pin24(mac) == expected


def test_vendor_algorithms_valid_and_deterministic():
    mac = int(MAC.replace(":", ""), 16)
    for algo in (pin24, pin_dlink, pin_dlink1, pin_asus):
        pin = algo(mac)
        assert is_valid_wps_pin(pin)
        assert algo(mac) == pin  # deterministic


# --- candidate list ---


def test_candidate_pins_all_valid_and_bounded():
    for bssid in ("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "de:ad:be:ef:12:34"):
        pins = candidate_pins(bssid)
        assert pins, "expected at least one candidate"
        for pin in pins:
            assert 0 <= pin <= 99_999_999
            assert is_valid_wps_pin(pin)


def test_candidate_pins_deterministic_and_deduped():
    a = candidate_pins(MAC)
    assert a == candidate_pins(MAC)
    assert len(a) == len(set(a))


def test_candidate_pins_starts_with_statics():
    pins = candidate_pins(MAC)
    assert pins[: len(STATIC_PINS)] == list(STATIC_PINS)


def test_mac_separator_formats_accepted():
    assert candidate_pins("001122334455") == candidate_pins("00:11:22:33:44:55")
    assert candidate_pins("00-11-22-33-44-55") == candidate_pins("00:11:22:33:44:55")


def test_format_pin_zero_pads():
    assert format_pin(0) == "00000000"
    assert format_pin(12345670) == "12345670"


# --- attack orchestration ---


class _Result:
    def __init__(self, data):
        self.data = data
        self.success = True


class FakeReaver:
    def __init__(self, outcomes, raise_gate=False):
        self.outcomes = list(outcomes)
        self.calls: list[tuple] = []
        self.raise_gate = raise_gate

    async def execute(self, bssid, options):
        self.calls.append((bssid, dict(options)))
        if self.raise_gate:
            raise TargetValidationError("BSSID not authorised by scope")
        idx = len(self.calls) - 1
        data = self.outcomes[idx] if idx < len(self.outcomes) else self.outcomes[-1]
        return _Result(data)


def _run(reaver, **kw):
    return asyncio.run(WpsAttack(reaver=reaver).run("wlan0mon", MAC, 6, **kw))


def test_pixie_dust_success_short_circuits():
    reaver = FakeReaver([{"status": "success", "pin": "12345670", "psk": "secret"}])
    res = _run(reaver)
    assert res.success and res.pin == "12345670" and res.psk == "secret"
    assert res.pixie_dust and res.tried == 0
    assert len(reaver.calls) == 1  # no PIN attempts needed


def test_pin_list_success_after_pixie_fails():
    reaver = FakeReaver([
        {"status": "running"},                       # pixie fails
        {"status": "success", "psk": "pw", "pin": "00000000"},  # first PIN wins
    ])
    res = _run(reaver)
    assert res.success and res.psk == "pw"
    assert res.tried == 1
    assert len(reaver.calls) == 2


def test_no_success_tries_all_candidates():
    reaver = FakeReaver([{"status": "running"}])  # every call fails
    res = _run(reaver, pins=[11111111, 22222222, 33333333], try_pixie_dust=False)
    assert res.success is False
    assert res.tried == 3
    assert len(reaver.calls) == 3


def test_scope_gate_denial_propagates():
    reaver = FakeReaver([{}], raise_gate=True)
    with pytest.raises(TargetValidationError):
        _run(reaver)


def test_explicit_pins_and_no_pixie():
    reaver = FakeReaver([{"status": "running"}])
    res = _run(reaver, pins=[12345670], try_pixie_dust=False)
    assert res.tried == 1
    assert reaver.calls[0][1]["pin"] == "12345670"
    assert res.candidates == ["12345670"]
