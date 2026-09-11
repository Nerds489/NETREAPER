# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""WPA/WPA2 4-way-handshake capture orchestration.

Composes two gated adapters: airodump-ng runs a channel-locked pcap capture
against the target BSSID (PASSIVE tier) while aireplay-ng sends a targeted
deauthentication (DESTRUCTIVE) to knock a client off so it reassociates and the
handshake is recorded. The resulting .cap is verified with the native parser in
:mod:`netreaper.wireless.eapol` before it counts as captured.

Every process spawn still passes the scope gate inside the adapters. A gate
denial (:class:`TargetValidationError`) is never swallowed here: the in-flight
capture is torn down and the error propagates.
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from netreaper.core.logging import get_logger
from netreaper.orchestration.events import Events, event_bus
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.airodump import AirodumpTool
from netreaper.wireless.eapol import Handshake, handshakes_for

logger = get_logger(__name__)


@dataclass
class HandshakeResult:
    bssid: str
    channel: int
    captured: bool = False
    cap_file: str | None = None
    client: str | None = None
    messages: list[int] = field(default_factory=list)
    deauth_packets: int = 0
    attempts: int = 0


class HandshakeCapture:
    """Capture and verify a WPA handshake for a single access point."""

    def __init__(
        self,
        airodump: AirodumpTool | None = None,
        aireplay: AireplayTool | None = None,
    ) -> None:
        self._airodump = airodump or AirodumpTool()
        self._aireplay = aireplay or AireplayTool()

    async def capture(
        self,
        interface: str,
        bssid: str,
        channel: int,
        *,
        client: str | None = None,
        output: str | None = None,
        capture_seconds: int = 20,
        deauth_count: int = 5,
        max_attempts: int = 3,
        settle_seconds: int = 3,
    ) -> HandshakeResult:
        """Capture a handshake, retrying with deauth until one is verified.

        Args:
            interface: Monitor-mode interface.
            bssid: Target access point BSSID (the scope-checked identifier).
            channel: Target channel to lock onto.
            client: Specific client to deauth; None sends a broadcast deauth.
            output: .cap prefix; a temp file is used when omitted.
            capture_seconds: Listen window per attempt.
            deauth_count: Deauth frames per attempt (0 disables deauth).
            max_attempts: How many capture+deauth rounds before giving up.
            settle_seconds: Delay before deauth so airodump is on-channel first.
        """
        prefix, cleanup = self._resolve_prefix(output)
        result = HandshakeResult(bssid=bssid, channel=channel)
        try:
            for attempt in range(1, max_attempts + 1):
                result.attempts = attempt
                cap_path = await self._one_attempt(
                    interface,
                    bssid,
                    channel,
                    client,
                    prefix,
                    capture_seconds,
                    deauth_count,
                    settle_seconds,
                    result,
                )
                found = self._verify(cap_path, bssid)
                if found is not None:
                    result.captured = True
                    result.cap_file = str(cap_path)
                    result.client = found.client
                    result.messages = sorted(found.messages)
                    event_bus.emit(
                        Events.HANDSHAKE_CAPTURED,
                        {
                            "bssid": bssid,
                            "client": found.client,
                            "channel": channel,
                            "cap_file": str(cap_path),
                            "messages": sorted(found.messages),
                        },
                    )
                    logger.info("Handshake %s captured (attempt %d)", bssid, attempt)
                    return result
                logger.info("No handshake for %s (%d/%d)", bssid, attempt, max_attempts)
            return result
        finally:
            cleanup()

    async def _one_attempt(
        self,
        interface: str,
        bssid: str,
        channel: int,
        client: str | None,
        prefix: str,
        capture_seconds: int,
        deauth_count: int,
        settle_seconds: int,
        result: HandshakeResult,
    ) -> Path:
        """Run one capture window with an interleaved deauth. Returns cap path."""
        cap_task = asyncio.create_task(
            self._airodump.capture_for_target(
                interface, bssid, channel, prefix, duration=capture_seconds
            )
        )
        try:
            if deauth_count > 0:
                # Give airodump time to settle on-channel before we transmit.
                await asyncio.sleep(min(settle_seconds, max(0, capture_seconds - 1)))
                data = await self._aireplay.deauth_attack(
                    interface, bssid, client=client, count=deauth_count
                )
                result.deauth_packets += int(data.get("packets_sent", deauth_count))
            await cap_task
        except BaseException:
            # Tear the capture down on any failure. A scope-gate denial
            # (TargetValidationError) propagates unchanged: it is never swallowed.
            cap_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cap_task
            raise
        return Path(f"{prefix}-01.cap")

    @staticmethod
    def _verify(cap_path: Path, bssid: str) -> Handshake | None:
        """Return the first complete handshake for bssid in the cap, else None."""
        if not cap_path.exists():
            return None
        for hs in handshakes_for(cap_path, bssid):
            if hs.complete:
                return hs
        return None

    @staticmethod
    def _resolve_prefix(output: str | None):
        """Return (prefix, cleanup). A temp dir is created when output is None."""
        if output:
            return output, lambda: None
        tmp = tempfile.mkdtemp(prefix="netreaper_hs_")
        prefix = str(Path(tmp) / "handshake")

        def cleanup() -> None:
            shutil.rmtree(tmp, ignore_errors=True)

        return prefix, cleanup


async def capture_handshake(
    interface: str,
    bssid: str,
    channel: int,
    *,
    client: str | None = None,
    output: str | None = None,
    capture_seconds: int = 20,
    deauth_count: int = 5,
    max_attempts: int = 3,
) -> HandshakeResult:
    """Stateless one-shot handshake capture for the CLI."""
    return await HandshakeCapture().capture(
        interface,
        bssid,
        channel,
        client=client,
        output=output,
        capture_seconds=capture_seconds,
        deauth_count=deauth_count,
        max_attempts=max_attempts,
    )
