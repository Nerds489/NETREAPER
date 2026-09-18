"""Reaver WPS attack tool wrapper with output parsing."""
from __future__ import annotations

import re
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.logging import get_logger
from netreaper.orchestration.events import Events, event_bus
from netreaper.plugins.base import Capability, PluginMetadata, PluginType
from netreaper.safety.scope import Tier
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)


class ReaverConfig(BaseModel):
    """Reaver-specific configuration."""

    delay: int = 1  # Delay between PIN attempts
    lock_delay: int = 60  # Delay when AP locks
    max_attempts: int = 0  # 0 = unlimited
    timeout: int = 5  # Receive timeout
    verbose: bool = True


class ReaverTool(BaseToolWrapper):
    """Reaver WPS attack tool wrapper."""

    DEFAULT_TIER = Tier.SINGLE_TARGET
    DESTRUCTIVE = True

    TOOL_BINARY: ClassVar[str] = "reaver"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="reaver",
        version="1.0.0",
        description="WPS PIN recovery tool",
        author="NETREAPER",
        plugin_type=PluginType.TOOL,
        capabilities=[Capability.WIRELESS_ATTACK],
        requires_root=True,
        external_tools=["reaver"],
        config_schema=ReaverConfig,
    )

    def __init__(self, reaver_config: ReaverConfig | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.reaver_config = reaver_config or ReaverConfig()

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build reaver command.

        Args:
            target: Target BSSID
            options: Command options including:
                - interface: Monitor mode interface (-i)
                - channel: Target channel (-c)
                - essid: Target ESSID (-e)
                - pixiedust: Use Pixie Dust attack (-K)
                - delay: Delay between attempts (-d)
                - lock_delay: Delay when locked (-l)
                - max_attempts: Max PIN attempts (-g)
                - timeout: Receive timeout (-t)
                - pin: Known PIN to use (-p)
                - no_nacks: Ignore NACK messages (-N)
                - dh_small: Use small DH keys (-S)
                - no_associate: Don't auto-associate (-A)
                - output: Session file (-s)
        """
        cmd = []

        # Interface (required)
        interface = options.get("interface")
        if interface:
            cmd.extend(["-i", interface])

        # Target BSSID
        cmd.extend(["-b", target])

        # Channel
        channel = options.get("channel")
        if channel:
            cmd.extend(["-c", str(channel)])

        # ESSID
        essid = options.get("essid")
        if essid:
            cmd.extend(["-e", essid])

        # Pixie Dust attack (faster, uses implementation flaw)
        if options.get("pixiedust"):
            # -K is declared no_argument in reaver-wps-fork-t6x; there is no
            # "mode 1". The stray "1" was an unused positional that reaver
            # happens to ignore, so this was wrong rather than fatal.
            cmd.append("-K")

        # Delay between attempts
        delay = options.get("delay", self.reaver_config.delay)
        cmd.extend(["-d", str(delay)])

        # Lock delay
        lock_delay = options.get("lock_delay", self.reaver_config.lock_delay)
        cmd.extend(["-l", str(lock_delay)])

        # Max attempts
        max_attempts = options.get("max_attempts", self.reaver_config.max_attempts)
        if max_attempts > 0:
            cmd.extend(["-g", str(max_attempts)])

        # Timeout
        timeout = options.get("timeout", self.reaver_config.timeout)
        cmd.extend(["-t", str(timeout)])

        # Known PIN
        pin = options.get("pin")
        if pin:
            cmd.extend(["-p", pin])

        # No NACKs
        if options.get("no_nacks"):
            cmd.append("-N")

        # Small DH keys
        if options.get("dh_small"):
            cmd.append("-S")

        # Don't auto-associate
        if options.get("no_associate"):
            cmd.append("-A")

        # Session file
        output = options.get("output")
        if output:
            cmd.extend(["-s", str(output)])

        # Verbosity
        if options.get("verbose", self.reaver_config.verbose):
            cmd.append("-vv")

        return cmd

    # ── output ───────────────────────────────────────────────────────────────
    #
    # Line classifiers, IN ORDER, and the order is load-bearing. reaver's own
    # output overlaps: "WPS PIN: 12345670" also satisfies the pixie-dust
    # substring test, and r"PSK:" is a suffix of "WPA PSK:". The original
    # expressed this with `continue` after each match; these tables express the
    # same first-match-wins rule, and reordering either of them changes what
    # comes out.
    #
    # (pattern, result key, coercion, extra fields to set on a match)
    _FIELD_RULES: ClassVar[tuple] = (
        (
            re.compile(r'WPS PIN:\s*[\'"]?(\d{8})[\'"]?', re.IGNORECASE),
            "pin",
            str,
            {"status": "success"},
        ),
        (
            re.compile(r'Pin found:\s*(\d{8})', re.IGNORECASE),
            "pin",
            str,
            {"status": "success"},
        ),
        (
            re.compile(r'WPA PSK:\s*[\'"]?(.+?)[\'"]?\s*$', re.IGNORECASE),
            "psk",
            lambda v: v.strip("'\""),
            {},
        ),
        (
            re.compile(r'PSK:\s*(.+)', re.IGNORECASE),
            "psk",
            lambda v: v.strip("'\""),
            {},
        ),
        (
            re.compile(r'(?:ESSID|AP SSID):\s*[\'"]?(.+?)[\'"]?\s*$', re.IGNORECASE),
            "ssid",
            lambda v: v.strip("'\""),
            {},
        ),
        (
            re.compile(r'(\d+\.?\d*)%\s+complete', re.IGNORECASE),
            "progress",
            float,
            {},
        ),
    )
    _ATTEMPT_RE: ClassVar = re.compile(r'Trying pin:?\s*(\d+)', re.IGNORECASE)

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse reaver output."""
        result: dict[str, Any] = {
            "raw_output": output,
            "pin": None,
            "psk": None,
            "ssid": None,
            "bssid": None,
            "progress": 0.0,
            "status": "running",
            "attempts": 0,
            "locked": False,
            "errors": [],
        }

        for line in output.strip().split('\n'):
            if not self._match_field(line, result):
                self._match_state(line, result)

        return result

    def _match_field(self, line: str, result: dict[str, Any]) -> bool:
        """A line that carries a value. True if it was consumed."""
        for pattern, key, coerce, also in self._FIELD_RULES:
            match = pattern.search(line)
            if match:
                result[key] = coerce(match.group(1))
                result.update(also)
                return True

        if self._ATTEMPT_RE.search(line):
            result["attempts"] += 1
            return True
        return False

    @staticmethod
    def _match_state(line: str, result: dict[str, Any]) -> None:
        """A line that reports progress or trouble rather than a value.

        "WARNING" is matched case-sensitively, as it was before: reaver emits it
        upper-case and lowering it would start catching the word in an SSID.

        THE PIXIE-DUST TEST LOST A DISJUNCT, AND IT WAS DEAD. It read
        ``if "WPS pin:" in line.lower() or "pin found" in line.lower()``. The
        first needle carries an upper-case "WPS" and the haystack has just been
        lower-cased, so it could never be true; found by running the old and new
        parsers side by side over the same corpus, not by reading it.

        It is removed rather than corrected, because correcting it only ever
        produces a false success. A real ``[+] WPS pin: 12345670`` is consumed
        by _FIELD_RULES above, which sets both the pin and the status. The only
        lines that reach here saying "wps pin:" are ones no pin could be
        extracted from, and marking those "success" would hand the caller
        status="success" with pin=None.
        """
        lowered = line.lower()
        if "pin found" in lowered:
            result["status"] = "success"
        elif "WARNING" in line and "locked" in lowered:
            result["locked"] = True
            result["errors"].append("AP rate limiting detected")
        elif "timeout" in lowered:
            result["errors"].append(line.strip())
        elif "authentication" in lowered and "fail" in lowered:
            result["errors"].append(line.strip())
        elif "session saved" in lowered:
            result["status"] = "saved"

    async def wps_attack(
        self,
        bssid: str,
        interface: str,
        channel: int,
        pixiedust: bool = True,
        essid: str | None = None,
    ) -> dict[str, Any]:
        """Perform WPS PIN attack.

        Args:
            bssid: Target access point BSSID
            interface: Monitor mode interface
            channel: Target channel
            pixiedust: Use Pixie Dust attack (faster)
            essid: Target network name (optional)

        Returns:
            Attack results including PIN and PSK if found
        """
        options = {
            "interface": interface,
            "channel": channel,
            "pixiedust": pixiedust,
        }

        if essid:
            options["essid"] = essid

        result = await self.execute(bssid, options)

        # Emit event if PIN found
        if result.data.get("pin"):
            event_bus.emit(Events.WPS_PIN_FOUND, {
                "bssid": bssid,
                "pin": result.data["pin"],
                "psk": result.data.get("psk"),
            })

        # Emit event if PSK found
        if result.data.get("psk"):
            event_bus.emit(Events.CREDENTIAL_CRACKED, {
                "type": "wps",
                "bssid": bssid,
                "password": result.data["psk"],
            })

        return result.data

    async def pixie_dust(
        self,
        bssid: str,
        interface: str,
        channel: int,
    ) -> dict[str, Any]:
        """Perform Pixie Dust attack (fast WPS attack).

        Args:
            bssid: Target BSSID
            interface: Monitor mode interface
            channel: Target channel

        Returns:
            Attack results
        """
        return await self.wps_attack(
            bssid=bssid,
            interface=interface,
            channel=channel,
            pixiedust=True,
        )

    async def bruteforce_pin(
        self,
        bssid: str,
        interface: str,
        channel: int,
        delay: int = 1,
    ) -> dict[str, Any]:
        """Perform WPS PIN brute force attack.

        Args:
            bssid: Target BSSID
            interface: Monitor mode interface
            channel: Target channel
            delay: Delay between attempts

        Returns:
            Attack results
        """
        options = {
            "interface": interface,
            "channel": channel,
            "pixiedust": False,
            "delay": delay,
        }

        result = await self.execute(bssid, options)
        return result.data
