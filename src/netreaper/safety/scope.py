# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Engagement-scoped, deny-by-default authorisation.

Every dangerous action is bound to an active :class:`Engagement` and every
target must fall inside its :class:`Scope`. Enforcement happens at the single
process-spawn seam (:mod:`netreaper.core.process`) so no code path can attack a
target without passing this gate.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum

from netreaper.core.exceptions import TargetValidationError
from netreaper.core.logging import get_logger
from netreaper.safety.protected import is_protected_ip

logger = get_logger(__name__)


class Tier(IntEnum):
    """Blast-radius tier. Higher = more dangerous."""
    PASSIVE = 0        # read-only recon, no packets to target
    ACTIVE_SCAN = 1    # scans/probes a specific target
    SINGLE_TARGET = 2  # e.g. deauth of one client/AP
    BROADCAST = 3      # mass/broadcast: mdk4 amok, beacon/probe flood, DoS
    MITM = 4           # evil-twin, MITM, traffic interception


_BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

# Ranges that must never be targeted, checked by overlap so a wider CIDR target
# (e.g. 169.254.0.0/24 over the cloud metadata address) cannot slip past.
_PROTECTED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
        "240.0.0.0/4", "255.255.255.255/32",
        "::1/128", "::/128", "fe80::/10", "ff00::/8",
    )
]


@dataclass
class Scope:
    """What an engagement is authorised to touch. Deny-by-default: empty means
    nothing is in scope."""
    cidrs: list[str] = field(default_factory=list)
    hostnames: set[str] = field(default_factory=set)
    bssids: set[str] = field(default_factory=set)
    essids: set[str] = field(default_factory=set)
    deny: list[str] = field(default_factory=list)  # explicit out-of-scope IPs/CIDRs

    def _in_nets(self, ip: str, nets: list[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in nets:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def allows_ip(self, ip: str) -> bool:
        if self._in_nets(ip, self.deny):
            return False
        return self._in_nets(ip, self.cidrs)

    def allows_network(self, cidr: str) -> bool:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        for d in self.deny:
            try:
                if net.overlaps(ipaddress.ip_network(d, strict=False)):
                    return False
            except ValueError:
                continue
        for a in self.cidrs:
            try:
                if net.subnet_of(ipaddress.ip_network(a, strict=False)):
                    return True
            except (ValueError, TypeError):
                continue
        return False

    def allows_hostname(self, host: str) -> bool:
        return host.strip().lower() in {h.lower() for h in self.hostnames}

    def allows_bssid(self, bssid: str) -> bool:
        return bssid.strip().upper() in {b.upper() for b in self.bssids}

    def allows_essid(self, essid: str) -> bool:
        return essid in self.essids


@dataclass
class Engagement:
    """A time-boxed authorisation record."""
    operator: str
    authorization_ref: str
    scope: Scope
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=12)
    )
    # Highest blast-radius tier this engagement authorises. Broadcast/MITM must be
    # granted explicitly; the default ceiling stops at single-target.
    max_tier: Tier = Tier.SINGLE_TARGET

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.started_at <= now < self.expires_at


class ScopeGate:
    """Deny-by-default authorisation checkpoint."""

    def __init__(self) -> None:
        self._engagement: Engagement | None = None

    # --- engagement lifecycle ---
    def set_engagement(self, engagement: Engagement) -> None:
        self._engagement = engagement

    def clear_engagement(self) -> None:
        self._engagement = None

    @property
    def engagement(self) -> Engagement | None:
        return self._engagement

    # --- the gate ---
    def authorize(
        self,
        targets: list[str] | tuple[str, ...] = (),
        *,
        tier: Tier = Tier.PASSIVE,
        destructive: bool = False,
        requires_confirmation: bool = False,
        host_action: bool = False,
    ) -> None:
        """Raise :class:`TargetValidationError` unless the action is authorised.

        Target-less passive actions are always allowed. Everything else requires
        an active engagement whose scope covers every target. A ``host_action``
        is a local host/maintenance operation (bring our own interface up,
        restore NetworkManager, fetch a wordlist): it has no network target to
        scope-check, so it is allowed and audited, but it must never carry one.
        """
        targets = [t for t in targets if t]

        # Local host/maintenance action. It flows through the one seam so it gets
        # exec (never shell), timeouts, process-group teardown and this audit
        # line; it must not carry a network target, and if one slips in we fall
        # through to the full target checks rather than skipping them.
        if host_action and not targets:
            logger.info(
                "host action authorised%s (local, no network target)",
                " [destructive]" if destructive else "",
            )
            return

        # Target-less passive work (help, local status) needs no engagement.
        if not targets and tier <= Tier.PASSIVE and not destructive:
            return

        eng = self._engagement
        if eng is None:
            raise TargetValidationError(
                "deny-by-default: no active engagement; set one with an "
                "authorised scope before running against a target"
            )
        if not eng.is_active():
            raise TargetValidationError(
                "engagement has expired; re-authorise before continuing"
            )
        if tier > eng.max_tier:
            raise TargetValidationError(
                f"tier {tier.name} exceeds this engagement's ceiling "
                f"({eng.max_tier.name}); raise the engagement's max_tier to authorise it"
            )

        if not targets:
            raise TargetValidationError(
                "deny-by-default: this action has no identifiable in-scope target"
            )

        for target in targets:
            self._check_target(target, eng, tier)

    def _check_target(self, target: str, eng: Engagement, tier: Tier) -> None:
        t = target.strip()

        # Broadcast / mass targets: only at BROADCAST+ tier, never implicitly.
        if t.upper() == _BROADCAST_MAC or t in {"0.0.0.0/0", "::/0"}:
            raise TargetValidationError(
                f"refusing broadcast/everything target {t!r}: out of scope by default"
            )

        # Wireless identifiers
        if _looks_like_mac(t):
            if not eng.scope.allows_bssid(t):
                raise TargetValidationError(f"BSSID {t} is not in the engagement scope")
            return

        # IP / CIDR
        if _looks_like_ip(t):
            if "/" in t:  # a network/range target
                try:
                    net = ipaddress.ip_network(t, strict=False)
                except ValueError as e:
                    raise TargetValidationError(f"{t!r} is not a valid network/CIDR: {e}") from e
                # Refuse ANY CIDR (any width) that overlaps a protected range.
                if any(net.overlaps(pn) for pn in _PROTECTED_NETS if pn.version == net.version):
                    raise TargetValidationError(
                        f"{t} overlaps a protected/reserved range and must not be targeted"
                    )
                if net.num_addresses == 1:
                    if not eng.scope.allows_ip(str(net.network_address)):
                        raise TargetValidationError(f"{t} is not in the engagement scope")
                    return
                if not eng.scope.allows_network(t):
                    raise TargetValidationError(f"{t} is not within the engagement scope")
                return
            if is_protected_ip(t):
                raise TargetValidationError(
                    f"{t} is a protected/reserved address and must not be targeted"
                )
            if not eng.scope.allows_ip(t):
                raise TargetValidationError(f"{t} is not in the engagement scope")
            return

        # Hostname / ESSID fallthrough
        if eng.scope.allows_hostname(t) or eng.scope.allows_essid(t):
            return
        raise TargetValidationError(f"target {t!r} is not in the engagement scope")


def _looks_like_mac(s: str) -> bool:
    parts = s.replace("-", ":").split(":")
    return len(parts) == 6 and all(len(p) == 2 for p in parts)


def _looks_like_ip(s: str) -> bool:
    head = s.split("/", 1)[0]
    try:
        ipaddress.ip_address(head)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False


_GATE = ScopeGate()


def get_scope_gate() -> ScopeGate:
    """Return the process-wide scope gate singleton."""
    return _GATE


__all__ = ["Engagement", "Scope", "ScopeGate", "Tier", "get_scope_gate"]
