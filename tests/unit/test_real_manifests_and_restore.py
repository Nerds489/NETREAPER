# SPDX-License-Identifier: GPL-3.0-or-later
"""Two guarantees that mutation testing proved nothing covered.

A QA pass mutated the source and watched what went red. Two mutations came back
GREEN with all 406 tests passing:

1. Flipping ``capture_handshake``'s ``requires_confirmation`` from True to False
   in ``wireless/manifests.py``. Nothing asserted the real manifest data, so a
   declared-dangerous operation could be silently downgraded to an unconfirmed
   one and the suite would not notice.

2. Replacing ``change_mac``'s restore-and-reraise with a swallowed warning. No
   test anywhere exercised the failure path, and ``restore_mac`` was never called
   by a test at all. The test named
   ``test_missing_tool_raises_so_change_mac_restores`` only ever called
   ``_run_ip_command`` directly, so despite its name it proved nothing about the
   restore.

There is a third gap these close: the live auto-chain suite grants every test a
permissive engagement via an autouse fixture, so deleting the manifest
enforcement entirely leaves that file fully green. The enforcement test here uses
the REAL registry with NO grant, which is what ties the shipped manifest data to
the gate.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.chaining.models import ChainStep
from netreaper.chaining.plan_exec import manifest_step_runner
from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate
from netreaper.wireless import mac as mac_mod


@pytest.fixture(autouse=True)
def _no_ambient_engagement():
    get_scope_gate().clear_engagement()
    yield
    get_scope_gate().clear_engagement()


# ── the shipped manifest data itself ─────────────────────────────────────────


def _wifi_manifests():
    from netreaper.wireless.autochain import build_wifi_registry

    reg = build_wifi_registry(None)
    return reg


def test_capture_handshake_is_still_declared_dangerous():
    """A targeted deauth must keep declaring what it costs.

    Flipping either flag was a silent, undetected downgrade.
    """
    m = _wifi_manifests().get("capture_handshake")
    assert m.destructive is True, "a targeted deauth is destructive"
    assert m.requires_confirmation is True, "and it must require confirmation"


def test_passive_wifi_steps_are_not_over_declared():
    """The opposite failure: everything marked dangerous teaches people to ignore it."""
    reg = _wifi_manifests()
    for name in ("scan_networks", "crack_handshake"):
        m = reg.get(name)
        assert m.destructive is False, f"{name} does not transmit at a target"


def test_the_real_capture_handshake_manifest_is_gated_without_a_grant():
    """Ties the SHIPPED manifest to the gate, with no engagement at all.

    The auto-chain suite cannot prove this: its autouse fixture grants every
    test a permissive engagement, so the enforcement can be deleted outright and
    that file stays green.
    """
    runner = manifest_step_runner(_wifi_manifests())
    with pytest.raises(TargetValidationError, match="no active engagement"):
        asyncio.run(
            runner(ChainStep(id="s", tool="capture_handshake"), "AA:BB:CC:DD:EE:FF", {})
        )


def test_the_real_manifest_runs_once_properly_authorised():
    get_scope_gate().set_engagement(
        Engagement(
            operator="t", authorization_ref="SOW-1",
            scope=Scope(bssids={"AA:BB:CC:DD:EE:FF"}),
            max_tier=Tier.SINGLE_TARGET,
            confirmed_tiers=frozenset({Tier.SINGLE_TARGET}),
        )
    )
    runner = manifest_step_runner(_wifi_manifests())
    # The runner is planning-only in this registry; reaching it past the gate is
    # the point, so a PluginError here means the gate let it through.
    from netreaper.core.exceptions import PluginError

    with pytest.raises((PluginError, TypeError, AttributeError)):
        asyncio.run(
            runner(ChainStep(id="s", tool="capture_handshake"), "AA:BB:CC:DD:EE:FF", {})
        )


# ── change_mac's restore path ────────────────────────────────────────────────


NEW_MAC = "02:11:22:33:44:55"
ORIGINAL_MAC = "aa:bb:cc:dd:ee:ff"


class _FailingHost:
    """run_host that fails only the call setting the NEW MAC.

    Deliberately keyed on the MAC value, not on the word "address": the restore
    command contains "address" too, so a cruder fake fails the restore as well
    and cannot tell "restore never attempted" from "restore attempted and
    failed". That distinction is the whole point of these tests.
    """

    def __init__(self, fail_value: str | None = NEW_MAC):
        self.calls: list[list[str]] = []
        self._fail_value = fail_value

    async def __call__(self, cmd, **kw):
        from netreaper.core.process import ProcessResult

        self.calls.append(list(cmd))
        if self._fail_value is not None and self._fail_value in cmd:
            return ProcessResult(cmd=list(cmd), returncode=1, stderr="operation failed")
        return ProcessResult(cmd=list(cmd), returncode=0)

    def strings(self):
        return [" ".join(c) for c in self.calls]


def test_change_mac_restores_the_original_when_setting_fails(monkeypatch):
    """The mutation that swallowed this went completely undetected."""
    host = _FailingHost()
    monkeypatch.setattr(mac_mod, "run_host", host)

    async def original(_iface):
        return ORIGINAL_MAC

    monkeypatch.setattr(mac_mod, "get_current_mac", original)

    # RuntimeError, not a blind Exception: a bare `raises(Exception)` is the
    # same weak assertion this file exists to replace.
    with pytest.raises(RuntimeError, match="ip command failed"):
        asyncio.run(mac_mod.change_mac("wlan0", NEW_MAC))

    joined = host.strings()
    assert any(f"address {ORIGINAL_MAC}" in c for c in joined), (
        "the original MAC was never restored after the failure:\n" + "\n".join(joined)
    )
    assert joined[-1].endswith("up"), "the interface was left down"


def test_change_mac_reraises_it_does_not_swallow(monkeypatch):
    host = _FailingHost()
    monkeypatch.setattr(mac_mod, "run_host", host)

    async def original(_iface):
        return ORIGINAL_MAC

    monkeypatch.setattr(mac_mod, "get_current_mac", original)
    with pytest.raises(RuntimeError):
        asyncio.run(mac_mod.change_mac("wlan0", NEW_MAC))


def test_restore_mac_actually_restores(monkeypatch):
    """restore_mac was never called by any test."""
    host = _FailingHost(fail_value=None)
    monkeypatch.setattr(mac_mod, "run_host", host)

    async def permanent(_iface):
        return ORIGINAL_MAC

    monkeypatch.setattr(mac_mod, "get_permanent_mac", permanent)
    monkeypatch.setattr(mac_mod, "get_current_mac", permanent)

    got = asyncio.run(mac_mod.restore_mac("wlan0"))
    assert got == ORIGINAL_MAC
    assert any(f"address {ORIGINAL_MAC}" in c for c in host.strings())


def test_restore_mac_returns_none_when_there_is_no_permanent_mac(monkeypatch):
    monkeypatch.setattr(mac_mod, "run_host", _FailingHost(fail_value=None))

    async def none(_iface):
        return None

    monkeypatch.setattr(mac_mod, "get_permanent_mac", none)
    assert asyncio.run(mac_mod.restore_mac("wlan0")) is None
