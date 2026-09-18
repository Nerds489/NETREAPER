# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #47: the aireplay argv bug, and the WEP strategies that were unreachable.

The WEP half of #47 was wiring, not new primitives. ``tools/aireplay.py`` already
implemented chopchop, fragmentation, caffe-latte, cfrag and interactive replay;
``wireless/wep.py`` only ever drove fakeauth + ARP replay and the CLI exposed no
way to pick anything else.

The argv bug was worse than the issue described. ``ignore_negative`` emitted a
bare ``-x``, but in aireplay-ng ``-x`` is packets-per-second and takes a NUMBER.
The real ``-x <pps>`` is appended later, so the bare one landed immediately
before the interface: aireplay-ng would have read ``wlan0mon`` as a rate and been
left with no interface. On top of that the option key never matched the config
field (``ignore_negative`` vs ``ignore_negative_ack``), so passing it as an
option did nothing at all.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import ConfigurationError
from netreaper.tools.aireplay import AireplayTool, AttackMode
from netreaper.wireless.wep import INJECTION_MODES, WepAttack

BSSID = "AA:BB:CC:DD:EE:FF"
IFACE = "wlan0mon"


# ── the argv regression the issue asks for ───────────────────────────────────


def _argv(**opts):
    return AireplayTool().build_command(
        IFACE, {"attack": AttackMode.ARPREPLAY, "bssid": BSSID, **opts}
    )


def test_ignore_negative_uses_the_long_option_not_a_bare_dash_x():
    argv = _argv(ignore_negative_ack=True)
    assert "--ignore-negative-one" in argv
    assert argv.count("-x") == 1, f"-x is packets-per-second only: {argv}"


@pytest.mark.parametrize("key", ["ignore_negative_ack", "ignore_negative"])
def test_both_option_spellings_work(key):
    """The option key read `ignore_negative` while the config field was
    `ignore_negative_ack`, so the documented name did nothing."""
    assert "--ignore-negative-one" in _argv(**{key: True})


def test_the_interface_is_always_the_last_argument():
    """The bare -x landed right before the interface, so aireplay-ng would have
    consumed the interface as a numeric rate."""
    for opts in ({}, {"ignore_negative_ack": True}, {"ignore_negative": True}):
        argv = _argv(**opts)
        assert argv[-1] == IFACE, argv


def test_the_packet_rate_still_carries_a_number():
    argv = _argv(ignore_negative_ack=True, pps=42)
    assert argv[argv.index("-x") + 1] == "42"


def test_off_by_default():
    assert "--ignore-negative-one" not in _argv()


# ── every WEP injection strategy is reachable ────────────────────────────────


class _RecordingAireplay:
    """Records which primitive the orchestrator actually reached for."""

    def __init__(self):
        self.reached: list[str] = []

    async def _mark(self, name, *a, **k):
        self.reached.append(name)
        return None

    async def fakeauth_attack(self, *a, **k):
        return await self._mark("fakeauth", *a, **k)

    async def arpreplay_attack(self, *a, **k):
        return await self._mark("arpreplay", *a, **k)

    async def chopchop_attack(self, *a, **k):
        return await self._mark("chopchop", *a, **k)

    async def fragment_attack(self, *a, **k):
        return await self._mark("fragment", *a, **k)

    async def execute(self, iface, options):
        return await self._mark(f"execute:{options['attack'].value}")


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("arpreplay", "arpreplay"),
        ("chopchop", "chopchop"),
        ("fragment", "fragment"),
        ("caffe_latte", "execute:caffe_latte"),
        ("cfrag", "execute:cfrag"),
        ("interactive", "execute:interactive"),
    ],
)
def test_each_strategy_reaches_its_own_primitive(mode, expected):
    a = _RecordingAireplay()
    injector = WepAttack(aireplay=a)._injector(mode)
    asyncio.run(injector(IFACE, BSSID, "00:11:22:33:44:55"))
    assert a.reached == [expected], f"{mode} reached {a.reached}"


def test_every_declared_mode_resolves():
    """INJECTION_MODES and the dispatch table must not drift apart."""
    w = WepAttack(aireplay=_RecordingAireplay())
    for mode in INJECTION_MODES:
        assert callable(w._injector(mode)), mode


def test_an_unknown_mode_is_refused_and_lists_the_valid_ones():
    with pytest.raises(ConfigurationError, match="unknown WEP injection mode"):
        WepAttack(aireplay=_RecordingAireplay())._injector("nonsense")


def test_the_mode_is_validated_before_any_capture_is_arranged():
    """Deferring validation to the injector meant a typo only surfaced
    mid-attack, after setup, and behind a scope denial."""

    class _Boom:
        async def capture_for_target(self, *a, **k):
            raise AssertionError("capture must not start on a bad mode")

    with pytest.raises(ConfigurationError):
        asyncio.run(
            WepAttack(airodump=_Boom(), aireplay=_RecordingAireplay()).run(
                IFACE, BSSID, 6, injection="nonsense"
            )
        )


def test_the_cli_offers_every_strategy():
    # Against the ANSI-stripped text, not the raw output. Rich styles the help
    # table and puts escape codes inside the token, so `"--injection" in out` is
    # true with colour off and false with colour on. CI has colour on. This
    # assertion was red on every CI run from the day it was written while
    # passing locally every time.
    from tests.conftest import plain
    from typer.testing import CliRunner

    from netreaper.cli import app

    out = plain(CliRunner().invoke(app, ["wifi", "wep", "--help"]).output)
    assert "--injection" in out
    for mode in INJECTION_MODES:
        assert mode in out, mode
