# SPDX-License-Identifier: GPL-3.0-or-later
"""host_action gate lane, interface validation, and run_host routing (M-1)."""
from __future__ import annotations

import asyncio

import pytest

from netreaper.automation.handlers._host import run_host
from netreaper.automation.handlers.monitor import AutoMonHandler
from netreaper.core.exceptions import TargetValidationError
from netreaper.core.process import ProcessRunner
from netreaper.core.validation import require_interface, valid_interface_name
from netreaper.safety.scope import ScopeGate, Tier

# --- interface-name validation ---


@pytest.mark.parametrize(
    "name", ["wlan0", "wlan0mon", "eth0", "wlp2s0", "mon0", "br-lan", "en0.100"]
)
def test_valid_interface_names(name):
    assert valid_interface_name(name)
    assert require_interface(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "wlan0; rm -rf /",
        "wlan0 && reboot",
        "$(id)",
        "a b",
        "../wlan0",
        "wlan0\n",
        "a" * 16,  # exceeds IFNAMSIZ-1
        ".",
        "..",
    ],
)
def test_invalid_interface_names_rejected(name):
    assert not valid_interface_name(name)
    with pytest.raises(TargetValidationError):
        require_interface(name)


# --- gate host_action lane ---


def test_host_action_allowed_without_engagement():
    gate = ScopeGate()  # no engagement set
    gate.authorize([], tier=Tier.PASSIVE, destructive=True, host_action=True)


def test_destructive_without_host_action_is_denied():
    gate = ScopeGate()
    with pytest.raises(TargetValidationError):
        gate.authorize([], tier=Tier.PASSIVE, destructive=True)


def test_network_target_cannot_ride_host_lane():
    gate = ScopeGate()  # no engagement
    with pytest.raises(TargetValidationError):
        gate.authorize(["10.0.0.1"], host_action=True)


# --- ProcessRunner routes host actions through the gate ---


def test_runner_host_action_dry_run_passes_gate():
    runner = ProcessRunner(gate=ScopeGate())
    res = runner.run_sync(["ip", "link"], host_action=True, dry_run=True)
    assert res.dry_run and res.ok


def test_runner_destructive_no_target_denied_without_host_action():
    runner = ProcessRunner(gate=ScopeGate())
    with pytest.raises(TargetValidationError):
        runner.run_sync(["iptables", "-F"], destructive=True, dry_run=True)


def test_run_host_returns_none_for_missing_tool():
    res = asyncio.run(run_host(["definitely-not-a-real-binary-xyz-123"]))
    assert res is None


# --- handler validates the interface before spawning ---


def test_monitor_handler_rejects_injection_interface():
    handler = AutoMonHandler(interface="wlan0; rm -rf /")
    with pytest.raises(TargetValidationError):
        asyncio.run(handler._enable_with_iw())
