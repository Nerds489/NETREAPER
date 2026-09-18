# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""SocketCAN tooling (can-utils), driven through the one gated spawn seam.

The automotive domain (#33) reads and decodes a vehicle bus. It does not write
to one, and that is a deliberate boundary rather than an unfinished feature.

WHY READ-ONLY. On a wireless engagement the worst outcome of a mistake is an
unauthorised host. On a vehicle bus it is a moving car: a frame written to a
live powertrain or chassis bus can affect steering, braking and throttle. No
authorisation tier makes that safe, because the risk is not "did the operator
have permission", it is "can this injure someone in the next two seconds". The
scope gate is an information-security control and it is the wrong instrument.

So: ``candump``, ``cansniffer`` and ``cantools`` are wrapped here.
``cansend``, ``cangen`` and ``canplayer`` are not, and
``tests/unit/test_new_domains.py`` fails if a writer appears in
this module. If a future engagement genuinely needs frame injection, it needs its own
design with a physical-safety review, an out-of-band interlock and a bench
target, not an extra entry in a dispatch table.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.safety.scope import Tier

logger = get_logger(__name__)

# can-utils binaries this module is permitted to drive. Read and decode only.
READ_ONLY_BINARIES = frozenset({"candump", "cansniffer", "cantools"})

# Present so the boundary is stated in code and testable, not just in prose.
# Anything here is refused by name even if someone wires a call for it.
REFUSED_WRITE_BINARIES = frozenset({"cansend", "cangen", "canplayer", "canfdtest"})

_FRAME_RE = re.compile(
    r"^\s*(?P<iface>\S+)\s+(?P<can_id>[0-9A-Fa-f]+)\s*"
    r"\[(?P<dlc>\d+)\]\s+(?P<data>[0-9A-Fa-f ]*)"
)


@dataclass
class CanFrame:
    """One decoded frame from a candump line."""

    interface: str
    can_id: str
    dlc: int
    data: str

    @property
    def arbitration_id(self) -> int:
        return int(self.can_id, 16)


@dataclass
class CanCapture:
    """The result of a bounded read of a bus."""

    interface: str
    frames: list[CanFrame] = field(default_factory=list)
    unique_ids: set[str] = field(default_factory=set)
    raw: str = ""

    @property
    def frame_count(self) -> int:
        return len(self.frames)


class CanUtilsTool:
    """Read a CAN bus. Cannot write to one; see the module docstring."""

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or get_process_runner()

    @staticmethod
    def _guard(binary: str) -> None:
        """Refuse anything that transmits, by name, at the call boundary."""
        if binary in REFUSED_WRITE_BINARIES:
            raise ValueError(
                f"{binary} transmits onto the bus and is deliberately not "
                f"available: writing frames to a live vehicle is a "
                f"physical-safety action, not a gated information-security one. "
                f"See netreaper.tools.canutils."
            )
        if binary not in READ_ONLY_BINARIES:
            raise ValueError(
                f"{binary} is not a permitted CAN binary; "
                f"allowed: {', '.join(sorted(READ_ONLY_BINARIES))}"
            )

    async def dump(
        self,
        interface: str,
        *,
        seconds: int = 10,
        max_frames: int = 0,
    ) -> CanCapture:
        """Read frames from a SocketCAN interface for a bounded window.

        host_action: the interface is ours and there is no network target to
        scope-check, so this is gated and audited as a local host operation,
        exactly like bringing a wireless interface into monitor mode.
        """
        self._guard("candump")
        cmd = ["candump", interface]
        if max_frames > 0:
            cmd = ["candump", "-n", str(max_frames), interface]

        res = await self._runner.run(
            cmd, host_action=True, tier=Tier.PASSIVE, timeout=float(seconds)
        )
        return self._parse(interface, res.stdout)

    @staticmethod
    def _parse(interface: str, output: str) -> CanCapture:
        cap = CanCapture(interface=interface, raw=output)
        for line in output.splitlines():
            m = _FRAME_RE.match(line)
            if not m:
                continue
            frame = CanFrame(
                interface=m.group("iface"),
                can_id=m.group("can_id").upper(),
                dlc=int(m.group("dlc")),
                data=m.group("data").strip(),
            )
            cap.frames.append(frame)
            cap.unique_ids.add(frame.can_id)
        return cap

    async def list_interfaces(self) -> list[str]:
        """Enumerate SocketCAN interfaces via `ip -details link show type can`."""
        res = await self._runner.run(
            ["ip", "-details", "link", "show", "type", "can"],
            host_action=True,
            tier=Tier.PASSIVE,
            timeout=15,
        )
        return re.findall(r"^\d+:\s+(\S+?):", res.stdout, re.MULTILINE)
