# SPDX-License-Identifier: GPL-3.0-or-later
"""packetforge-ng wrapper: build a packet from a recovered keystream.

This is the missing half of the WEP chopchop and fragmentation attacks. Those
two recover a PRGA keystream and write it to a ``.xor`` file; on its own that
file does nothing. packetforge-ng turns it into a real frame, classically an
ARP request, which is then replayed to generate the IVs aircrack-ng needs.

NETREAPER shipped both ends and not the middle: ``AttackMode.CHOPCHOP`` and
``AttackMode.FRAGMENT`` existed and could be driven, and aircrack-ng could read
the capture, but nothing consumed the keystream between them. The same shape as
every other defect found in this tree, a declaration with nothing connecting it
to anything.

TIERING. packetforge-ng reads a local PRGA file and writes a local pcap. It
opens no interface and puts nothing on the air, so it is ``Tier.PASSIVE``.
Rating it higher would make the scope gate demand confirmation for what is, at
the process level, a file transform.

That is not the same as saying it is unscoped. ``target_identifiers`` returns
the BSSID the frame is being forged *for*, so forging a packet aimed at an
access point outside the engagement is refused at the seam, exactly as
transmitting at it would be. The spawn is local; the intent is targeted, and
the gate binds to the intent.
"""
from __future__ import annotations

import re
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.exceptions import ConfigurationError
from netreaper.core.logging import get_logger
from netreaper.plugins.base import Capability, PluginMetadata, PluginType
from netreaper.safety.scope import Tier
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)

# The broadcast address an ARP request is forged against by default. Both the
# source and destination IP are set to it, which is the canonical form for the
# WEP ARP-replay chain: the AP rebroadcasts it and every reply is a fresh IV.
_BROADCAST_IP = "255.255.255.255"


class PacketforgeConfig(BaseModel):
    """packetforge-ng defaults."""

    dest_ip: str = _BROADCAST_IP
    source_ip: str = _BROADCAST_IP


class PacketforgeTool(BaseToolWrapper):
    """packetforge-ng wrapper: forge a frame from a recovered keystream."""

    # Local file transform. See the module docstring on tiering.
    DEFAULT_TIER = Tier.PASSIVE
    DESTRUCTIVE = False

    TOOL_BINARY: ClassVar[str] = "packetforge-ng"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="packetforge-ng",
        version="1.0.0",
        description="Forge a frame from a recovered WEP keystream",
        author="NETREAPER",
        plugin_type=PluginType.TOOL,
        capabilities=[Capability.WIRELESS_ATTACK],
        requires_root=False,
        external_tools=["packetforge-ng"],
        config_schema=PacketforgeConfig,
    )

    def __init__(
        self, packetforge_config: PacketforgeConfig | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.packetforge_config = packetforge_config or PacketforgeConfig()

    def target_identifiers(self, target: str, options: dict[str, Any]) -> list[str]:
        """The BSSID the frame is forged for, not the output path.

        ``target`` is the keystream file. Scoping on that would scope on a local
        filename, which authorises nothing meaningful.
        """
        bssid = options.get("bssid")
        return [bssid] if bssid else []

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build the packetforge-ng ARP-forge command.

        Args:
            target: Path to the PRGA keystream file (``.xor``), passed to -y.
            options:
                - bssid: Access point MAC (-a), required
                - source_mac: Source MAC (-h), required
                - output: Path to write the forged pcap (-w), required
                - dest_mac: Destination MAC (-c), defaults to broadcast
                - dest_ip: Destination IP (-k)
                - source_ip: Source IP (-l)
        """
        keystream = target or options.get("keystream")
        bssid = options.get("bssid")
        source_mac = options.get("source_mac")
        output = options.get("output")

        # Fail here rather than let packetforge-ng exit 1 on a missing operand.
        # Every one of these is mandatory for -0 and none has a sane default.
        missing = [
            name
            for name, value in (
                ("keystream", keystream),
                ("bssid", bssid),
                ("source_mac", source_mac),
                ("output", output),
            )
            if not value
        ]
        if missing:
            raise ConfigurationError(
                "packetforge-ng needs " + ", ".join(missing),
                context={"missing": missing},
            )

        cmd = ["-0", "-a", str(bssid), "-h", str(source_mac)]

        dest_mac = options.get("dest_mac")
        if dest_mac:
            cmd.extend(["-c", str(dest_mac)])

        cfg = self.packetforge_config
        dest_ip = str(options.get("dest_ip") or cfg.dest_ip)
        source_ip = str(options.get("source_ip") or cfg.source_ip)
        cmd.extend(["-k", dest_ip, "-l", source_ip])
        cmd.extend(["-y", str(keystream), "-w", str(output)])
        return cmd

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse packetforge-ng output.

        Success is a single line naming the file it wrote. Anything else,
        including the silent case, leaves ``success`` False rather than
        assuming a zero exit meant a packet exists.
        """
        result: dict[str, Any] = {
            "raw_output": output,
            "success": False,
            "packet_file": None,
            "errors": [],
        }

        for line in (output or "").splitlines():
            wrote = re.search(r"Wrote packet to:\s*(\S+)", line, re.IGNORECASE)
            if wrote:
                result["packet_file"] = wrote.group(1)
                result["success"] = True
                continue

            lowered = line.lower()
            if "error" in lowered or "failed" in lowered or "invalid" in lowered:
                result["errors"].append(line.strip())

        return result

    async def forge_arp(
        self,
        keystream: str,
        bssid: str,
        source_mac: str,
        output: str,
        **options: Any,
    ) -> dict[str, Any]:
        """Forge an ARP request from ``keystream`` and return the parsed result."""
        result = await self.execute(
            keystream,
            {
                "bssid": bssid,
                "source_mac": source_mac,
                "output": output,
                **options,
            },
        )
        data = result.data or {}
        logger.debug(
            "packetforge-ng forged=%s file=%s",
            data.get("success"),
            data.get("packet_file"),
        )
        return data
