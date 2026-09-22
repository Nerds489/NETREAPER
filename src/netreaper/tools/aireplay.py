"""Aireplay-ng wireless packet injection wrapper with all attack modes."""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.logging import get_logger
from netreaper.core.validation import require_interface
from netreaper.orchestration.events import Events, event_bus
from netreaper.plugins.base import Capability, PluginMetadata, PluginType
from netreaper.safety.scope import Tier
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)


class AttackMode(str, Enum):
    """Aireplay-ng attack modes."""

    DEAUTH = "deauth"  # -0: Deauthentication
    FAKEAUTH = "fakeauth"  # -1: Fake authentication
    INTERACTIVE = "interactive"  # -2: Interactive packet replay
    ARPREPLAY = "arpreplay"  # -3: ARP request replay
    CHOPCHOP = "chopchop"  # -4: KoreK chopchop attack
    FRAGMENT = "fragment"  # -5: Fragmentation attack
    CAFFE_LATTE = "caffe_latte"  # -6: Caffe-latte attack
    CFRAG = "cfrag"  # -7: Client-oriented fragmentation
    MIGMODE = "migmode"  # -8: WPA Migration Mode
    TEST = "test"  # -9: Injection test


class AireplayConfig(BaseModel):
    """Aireplay-ng specific configuration."""

    default_deauth_count: int = 10
    ignore_negative_ack: bool = False
    retry_count: int = 3
    packet_per_second: int = 10


class AireplayTool(BaseToolWrapper):
    """Aireplay-ng wireless packet injection wrapper with all attack modes."""

    DESTRUCTIVE = True

    def target_identifiers(self, target, options):
        # Scope authorises the AP (BSSID/ESSID); a client of a scoped AP is
        # covered by that AP. The interface is not a scope-relevant target.
        return [t for t in (options.get("bssid"), options.get("essid")) if t]

    def execution_tier(self, target, options):
        # A deauth bounded to one in-scope AP is SINGLE_TARGET, whether it names a
        # client or broadcasts to the AP's clients for a finite burst (the normal
        # handshake technique). Only a sustained, client-less deauth (count 0 =
        # continuous) is an AP-wide DoS and needs BROADCAST. fakeauth/arpreplay/
        # fragment/chopchop all target one AP -> single-target.
        attack = options.get("attack", "deauth")
        attack = str(getattr(attack, "value", attack)).lower()
        if (
            attack == "deauth"
            and not options.get("client")
            and options.get("count") in (0, "0")
        ):
            return Tier.BROADCAST
        return Tier.SINGLE_TARGET

    TOOL_BINARY: ClassVar[str] = "aireplay-ng"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="aireplay-ng",
        version="1.0.0",
        description="Wireless packet injection and replay attacks",
        author="NETREAPER",
        plugin_type=PluginType.TOOL,
        capabilities=[Capability.WIRELESS_ATTACK],
        requires_root=True,
        external_tools=["aireplay-ng"],
        config_schema=AireplayConfig,
    )

    # Attack mode flags
    # Which attacks name the AP with -b rather than -a. aireplay-ng's getnet()
    # reads f_bssid (-b) when called with filter=1 and r_bssid (-a) when called
    # with filter=0: the capture-filtering attacks take the former, the ones
    # that transmit at the AP take the latter. Getting it wrong is not a
    # degraded run, it is an immediate "Please specify at least a BSSID (-b) or
    # an ESSID (-e)" and exit 1, which is what --arpreplay, the DEFAULT WEP
    # injection strategy, did every single time it was invoked.
    FILTER_BSSID_ATTACKS = frozenset({
        AttackMode.ARPREPLAY,
        AttackMode.CHOPCHOP,
        AttackMode.FRAGMENT,
        AttackMode.CAFFE_LATTE,
        AttackMode.CFRAG,
        AttackMode.INTERACTIVE,
        AttackMode.MIGMODE,
    })

    # Attacks whose flag takes a value. Every other long option here is declared
    # no_argument in aireplay-ng, so appending a count produces a second
    # positional and trips its "argc - optind != 1" check: exit 1, again
    # immediately. --cfrag and --migmode were both being given one.
    VALUED_ATTACK_FLAGS = frozenset({AttackMode.DEAUTH, AttackMode.FAKEAUTH})

    ATTACK_FLAGS = {
        AttackMode.DEAUTH: "--deauth",
        AttackMode.FAKEAUTH: "--fakeauth",
        AttackMode.INTERACTIVE: "--interactive",
        AttackMode.ARPREPLAY: "--arpreplay",
        AttackMode.CHOPCHOP: "--chopchop",
        AttackMode.FRAGMENT: "--fragment",
        AttackMode.CAFFE_LATTE: "--caffe-latte",
        AttackMode.CFRAG: "--cfrag",
        AttackMode.MIGMODE: "--migmode",
        AttackMode.TEST: "--test",
    }

    # Attack modes with a builder of their own, by method name. A table rather
    # than an if/elif ladder, and looked up with [] rather than getattr's
    # default, so a name that stops resolving is an error instead of a silent
    # fall-through to --deauth. Pinned by a test.
    ATTACK_BUILDERS: ClassVar[dict["AttackMode", str]] = {
        AttackMode.DEAUTH: "_build_deauth_command",
        AttackMode.FAKEAUTH: "_build_fakeauth_command",
        AttackMode.ARPREPLAY: "_build_arpreplay_command",
        AttackMode.CHOPCHOP: "_build_chopchop_command",
        AttackMode.FRAGMENT: "_build_fragment_command",
        AttackMode.CAFFE_LATTE: "_build_caffe_latte_command",
        AttackMode.INTERACTIVE: "_build_interactive_command",
        AttackMode.TEST: "_build_test_command",
    }

    def _bssid_flag(self, attack: "AttackMode") -> str:
        return "-b" if attack in self.FILTER_BSSID_ATTACKS else "-a"

    def __init__(self, aireplay_config: AireplayConfig | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.aireplay_config = aireplay_config or AireplayConfig()

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build aireplay-ng command.

        Args:
            target: The wireless interface (e.g., wlan0mon)
            options: Command options including:
                - attack: Attack mode (AttackMode enum value or string)
                - bssid: Target access point BSSID (-a)
                - client: Target client MAC (-c)
                - source: Source MAC for fakeauth (-h)
                - count: Packet count for deauth (0 = continuous)
                - delay: Delay between packets
                - essid: ESSID for fakeauth (-e)
                - keepalive: Keepalive interval for fakeauth (-q)
                - reassoc: Reassociation timing for fakeauth (-Q)
                - read_file: Read packets from pcap file (-r)
        """
        require_interface(target)  # reject a bad/flag-like interface before argv

        attack = options.get("attack", AttackMode.DEAUTH)
        if isinstance(attack, str):
            attack = AttackMode(attack)

        cmd = self._attack_args(attack, options)
        cmd += self._common_args(attack, options)
        cmd.append(target)  # the interface is always last
        return cmd

    def _attack_args(self, attack: "AttackMode", options: dict[str, Any]) -> list[str]:
        """The attack selector and whatever that one attack needs with it."""
        builder = self.ATTACK_BUILDERS.get(attack)
        if builder is not None:
            return list(getattr(self, builder)(options))

        # Generic attack flag. Only the valued ones get a number after them.
        flag = self.ATTACK_FLAGS.get(attack, "--deauth")
        if attack in self.VALUED_ATTACK_FLAGS:
            count = options.get("count", self.aireplay_config.default_deauth_count)
            return [flag, str(count)]
        return [flag]

    def _common_args(self, attack: "AttackMode", options: dict[str, Any]) -> list[str]:
        """Options every attack mode accepts, in the order aireplay-ng expects."""
        args: list[str] = []

        # Target AP BSSID, named with the flag this attack actually reads.
        bssid = options.get("bssid")
        if bssid:
            args += [self._bssid_flag(attack), bssid]

        # Target client MAC
        client = options.get("client")
        if client:
            args += ["-c", client]

        # Source MAC (spoof).
        #
        # Accepts "source" or "source_mac". The named helpers on this class all
        # pass "source", but the lazily-dispatched strategies in wireless/wep.py
        # passed "source_mac", which nothing read: caffe-latte, cfrag and
        # interactive replay therefore emitted no -h at all and ran with no
        # source MAC set. Identical in shape to the ignore_negative /
        # ignore_negative_ack mismatch fixed below, so it is fixed the same way
        # rather than by renaming one caller and waiting for the next one.
        source = options.get("source", options.get("source_mac"))
        if source:
            args += ["-h", source]

        # Ignore a negative-one channel report from the driver.
        #
        # Two bugs here. The flag emitted was a bare "-x", but in aireplay-ng
        # "-x" is packets-per-second and takes a NUMBER; the correct option is
        # "--ignore-negative-one". Because the real "-x <pps>" is appended
        # further down, the bare one landed immediately before the interface,
        # so aireplay-ng would have parsed "wlan0mon" as a rate and been left
        # with no interface at all.
        #
        # And the option key never matched the config field: this read
        # "ignore_negative" while the config declares "ignore_negative_ack",
        # so passing ignore_negative_ack=True did nothing. Both keys are
        # accepted now, with the config field as the default.
        if options.get(
            "ignore_negative_ack",
            options.get("ignore_negative", self.aireplay_config.ignore_negative_ack),
        ):
            args.append("--ignore-negative-one")

        # Read from file
        read_file = options.get("read_file")
        if read_file:
            args += ["-r", str(read_file)]
        return args

    def _build_deauth_command(self, options: dict[str, Any]) -> list[str]:
        """Build deauthentication attack command."""
        count = options.get("count", self.aireplay_config.default_deauth_count)
        return ["--deauth", str(count)]

    @staticmethod
    def _build_fakeauth_command(options: dict[str, Any]) -> list[str]:
        """Build fake authentication attack command."""
        cmd = []

        delay = options.get("delay", 0)
        cmd.extend(["--fakeauth", str(delay)])

        # ESSID. aireplay-ng's do_attack_fake_auth() refuses outright without
        # it ("Please specify an ESSID (-e)."), and every caller defaulted it to
        # "", so the ergonomic invocation built a command that could not run.
        # Fail here, with the reason, rather than one exec later with theirs.
        essid = options.get("essid")
        if not essid:
            raise ValueError(
                "fakeauth requires an ESSID: aireplay-ng refuses --fakeauth "
                "without -e. Pass essid=... (CLI: --essid)."
            )
        cmd.extend(["-e", essid])

        # Keepalive
        keepalive = options.get("keepalive")
        if keepalive:
            cmd.extend(["-q", str(keepalive)])

        # Reassociation
        reassoc = options.get("reassoc")
        if reassoc:
            cmd.extend(["-Q", str(reassoc)])

        return cmd

    def _build_arpreplay_command(self, options: dict[str, Any]) -> list[str]:
        """Build ARP replay attack command."""
        cmd = ["--arpreplay"]

        # Packets per second
        pps = options.get("pps", self.aireplay_config.packet_per_second)
        cmd.extend(["-x", str(pps)])

        # Min/max packet size filtering
        min_size = options.get("min_size")
        if min_size:
            cmd.extend(["-m", str(min_size)])

        max_size = options.get("max_size")
        if max_size:
            cmd.extend(["-n", str(max_size)])

        return cmd

    @staticmethod
    def _build_chopchop_command(options: dict[str, Any]) -> list[str]:
        """Build KoreK chopchop attack command."""
        cmd = ["--chopchop"]

        # Frame control match
        fc = options.get("frame_control")
        if fc:
            cmd.extend(["-F", fc])

        return cmd

    @staticmethod
    def _build_fragment_command(options: dict[str, Any]) -> list[str]:
        """Build fragmentation attack command."""
        cmd = ["--fragment"]

        # Keep IV
        if options.get("keep_iv"):
            cmd.append("-k")

        return cmd

    @staticmethod
    def _build_caffe_latte_command(options: dict[str, Any]) -> list[str]:
        """Build Caffe-Latte attack command."""
        # -N was passed here as a packet count. There is no -N in aireplay-ng:
        # not in the short-option string, not in long_options[], no case 'N' in
        # the switch. It hit the unrecognised-option branch and exited 1, so
        # caffe-latte never ran once. --caffe-latte itself takes no argument.
        return ["--caffe-latte"]

    @staticmethod
    def _build_interactive_command(options: dict[str, Any]) -> list[str]:
        """Build interactive packet replay command."""
        cmd = ["--interactive"]

        # Destination MAC filter
        dest = options.get("dest_mac")
        if dest:
            cmd.extend(["-d", dest])

        # Broadcast filter
        if options.get("broadcast"):
            cmd.append("-b")

        # Replaying a packet built earlier (a forged ARP) is -r, which
        # _common_args already emits from the "read_file" option. Emitting it
        # here too would put -r in the argv twice.

        return cmd

    @staticmethod
    def _build_test_command(options: dict[str, Any]) -> list[str]:
        """Build injection test command."""
        cmd = ["--test"]

        # Broadcast probe requests
        if options.get("broadcast_probe"):
            cmd.append("-B")

        return cmd

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse aireplay-ng output."""
        result = {
            "raw_output": output,
            "success": False,
            "packets_sent": 0,
            "acks_received": 0,
            "injection_working": False,
            "auth_status": None,
            "errors": [],
        }

        lines = output.strip().split('\n')

        for line in lines:
            # Deauth packet count
            deauth_match = re.search(
                r'Sending (\d+) directed DeAuth.*(\d+) ACKs',
                line
            )
            if deauth_match:
                result["packets_sent"] = int(deauth_match.group(1))
                result["acks_received"] = int(deauth_match.group(2))
                result["success"] = True
                continue

            # Broadcast deauth
            broadcast_match = re.search(
                r'Sending DeAuth.*to broadcast',
                line
            )
            if broadcast_match:
                result["success"] = True
                result["packets_sent"] += 1
                continue

            # Injection test result
            injection_match = re.search(
                r'Injection is working!',
                line,
                re.IGNORECASE
            )
            if injection_match:
                result["injection_working"] = True
                result["success"] = True
                continue

            # Fake auth success
            auth_success = re.search(
                r'Association successful',
                line,
                re.IGNORECASE
            )
            if auth_success:
                result["auth_status"] = "associated"
                result["success"] = True
                continue

            # Auth failure
            auth_fail = re.search(
                r'(Association failed|Attack was unsuccessful)',
                line,
                re.IGNORECASE
            )
            if auth_fail:
                result["auth_status"] = "failed"
                result["errors"].append(line.strip())
                continue

            # ARP replay stats
            arp_match = re.search(
                r'Got (\d+) ARP requests.*sent (\d+) packets',
                line
            )
            if arp_match:
                result["arp_captured"] = int(arp_match.group(1))
                result["packets_sent"] = int(arp_match.group(2))
                result["success"] = True
                continue

            # Keystream and plaintext written by chopchop/fragment. Both were
            # printed on every successful run and neither was ever read, so the
            # PRGA these attacks exist to recover was announced and dropped.
            keystream_match = re.search(r'Saving keystream in (\S+)', line)
            if keystream_match:
                result["keystream_file"] = keystream_match.group(1)
                result["success"] = True
                continue

            plaintext_match = re.search(r'Saving plaintext in (\S+)', line)
            if plaintext_match:
                result["plaintext_file"] = plaintext_match.group(1)
                continue

            # General packet sent
            sent_match = re.search(r'sent (\d+) packet', line)
            if sent_match:
                result["packets_sent"] = int(sent_match.group(1))
                continue

            # Errors
            if "error" in line.lower() or "failed" in line.lower():
                result["errors"].append(line.strip())

        return result

    async def deauth_attack(
        self,
        interface: str,
        bssid: str,
        client: str | None = None,
        count: int = 10,
        continuous: bool = False,
    ) -> dict[str, Any]:
        """Perform deauthentication attack.

        Args:
            interface: Monitor mode interface
            bssid: Target access point BSSID
            client: Target client MAC (None = broadcast)
            count: Number of deauth packets (0 = continuous)
            continuous: If True, send continuously until stopped

        Returns:
            Attack results including packets sent and ACKs received
        """
        options = {
            "attack": AttackMode.DEAUTH,
            "bssid": bssid,
            "count": 0 if continuous else count,
        }

        if client:
            options["client"] = client

        result = await self.execute(interface, options)

        # Emit event
        event_bus.emit(Events.DEAUTH_SENT, {
            "bssid": bssid,
            "client": client or "broadcast",
            "count": result.data.get("packets_sent", count),
        })

        return result.data

    async def fakeauth_attack(
        self,
        interface: str,
        bssid: str,
        source_mac: str,
        essid: str,
        delay: int = 0,
        keepalive: int | None = None,
    ) -> dict[str, Any]:
        """Perform fake authentication attack.

        Args:
            interface: Monitor mode interface
            bssid: Target access point BSSID
            source_mac: Source MAC to use (your MAC)
            essid: Target network ESSID
            delay: Delay between auth attempts
            keepalive: Keepalive interval (seconds)

        Returns:
            Attack results including authentication status
        """
        options = {
            "attack": AttackMode.FAKEAUTH,
            "bssid": bssid,
            "source": source_mac,
            "essid": essid,
            "delay": delay,
        }

        if keepalive:
            options["keepalive"] = keepalive

        result = await self.execute(interface, options)
        return result.data

    async def arpreplay_attack(
        self,
        interface: str,
        bssid: str,
        source_mac: str,
        pps: int = 10,
    ) -> dict[str, Any]:
        """Perform ARP request replay attack.

        Args:
            interface: Monitor mode interface
            bssid: Target access point BSSID
            source_mac: Source MAC address
            pps: Packets per second

        Returns:
            Attack results including captured ARPs and packets sent
        """
        options = {
            "attack": AttackMode.ARPREPLAY,
            "bssid": bssid,
            "source": source_mac,
            "pps": pps,
        }

        result = await self.execute(interface, options)
        return result.data

    async def injection_test(
        self,
        interface: str,
        bssid: str | None = None,
    ) -> dict[str, Any]:
        """Test packet injection capability.

        Args:
            interface: Monitor mode interface
            bssid: Optional AP to test against

        Returns:
            Test results including injection status
        """
        options = {
            "attack": AttackMode.TEST,
            "broadcast_probe": True,
        }

        if bssid:
            options["bssid"] = bssid

        result = await self.execute(interface, options)
        return result.data

    async def fragment_attack(
        self,
        interface: str,
        bssid: str,
        source_mac: str,
    ) -> dict[str, Any]:
        """Perform fragmentation attack to obtain PRGA.

        Args:
            interface: Monitor mode interface
            bssid: Target access point BSSID
            source_mac: Source MAC address

        Returns:
            Attack results
        """
        options = {
            "attack": AttackMode.FRAGMENT,
            "bssid": bssid,
            "source": source_mac,
        }

        result = await self.execute(interface, options)
        return result.data

    async def chopchop_attack(
        self,
        interface: str,
        bssid: str,
        source_mac: str,
    ) -> dict[str, Any]:
        """Perform KoreK chopchop attack to decrypt WEP.

        Args:
            interface: Monitor mode interface
            bssid: Target access point BSSID
            source_mac: Source MAC address

        Returns:
            Attack results
        """
        options = {
            "attack": AttackMode.CHOPCHOP,
            "bssid": bssid,
            "source": source_mac,
        }

        result = await self.execute(interface, options)
        return result.data
