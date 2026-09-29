# SPDX-License-Identifier: GPL-3.0-or-later
"""#31/#106: the preflight modals exist and dismiss the values the runner expects.

These four dialogs were dangling references, so every interactive `ensure_*`
prompt in `preflight_runner` degraded to a notice. They are now real, and the
runner drives them through `push_screen_wait`, whose return value is whatever the
modal dismisses. These tests pin each dialog's contract via the Textual test
harness.
"""
from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, Static

from netreaper.tui.modals.preflight_modal import (
    ConfirmModal,
    InputModal,
    InterfaceSelectModal,
    PreflightModal,
)

pytestmark = pytest.mark.asyncio


class _Host(App):
    def compose(self) -> ComposeResult:
        yield Static("host")


async def _drive(modal, clicks, prime=None):
    app = _Host()
    captured: list = []
    async with app.run_test() as pilot:
        app.push_screen(modal, captured.append)
        await pilot.pause()
        if prime is not None:
            prime(app)
            await pilot.pause()
        for selector in clicks:
            await pilot.click(selector)
            await pilot.pause()
    return captured


async def test_confirm_yes_dismisses_true():
    assert await _drive(ConfirmModal("Title", "Body?"), ["#confirm-yes"]) == [True]


async def test_confirm_no_dismisses_false():
    assert await _drive(ConfirmModal("Title", "Body?"), ["#confirm-no"]) == [False]


async def test_input_submit_returns_the_typed_value():
    def type_target(app):
        app.screen.query_one("#input-field", Input).value = "10.0.0.5"

    assert await _drive(
        InputModal("Enter Target", placeholder="ip"),
        ["#input-submit"],
        prime=type_target,
    ) == ["10.0.0.5"]


async def test_input_cancel_returns_none():
    assert await _drive(InputModal("Enter Target"), ["#input-cancel"]) == [None]


async def test_input_empty_submit_is_none():
    assert await _drive(InputModal("Enter Target"), ["#input-submit"]) == [None]


async def test_interface_select_returns_the_chosen_name():
    ifaces = [
        {"name": "wlan0", "type": "wireless", "driver": "ath9k", "mac": "aa:bb"},
        {"name": "wlan1", "type": "wireless", "driver": "rt2800", "mac": "cc:dd"},
    ]
    assert await _drive(InterfaceSelectModal(ifaces), ["#iface-1"]) == ["wlan1"]


async def test_interface_select_cancel_returns_none():
    ifaces = [{"name": "wlan0"}, {"name": "wlan1"}]
    assert await _drive(InterfaceSelectModal(ifaces), ["#iface-cancel"]) == [None]


async def test_preflight_proceed_dismisses_true():
    class _R:
        unmet = "nmap not installed"

    assert await _drive(PreflightModal(_R()), ["#preflight-proceed"]) == [True]
