# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Engagement-scoped, deny-by-default authorisation.

Every dangerous action is bound to an active :class:`Engagement` and every
target must fall inside its :class:`Scope`. Enforcement happens at the single
process-spawn seam (:mod:`netreaper.core.process`) so no code path can attack a
target without passing this gate.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum

from netreaper.core.exceptions import TargetValidationError
from netreaper.core.logging import get_logger
from netreaper.safety.protected import is_protected_ip, is_protected_network

logger = get_logger(__name__)


class Tier(IntEnum):
    """Blast-radius tier. Higher = more dangerous."""
    PASSIVE = 0        # read-only recon, no packets to target
    ACTIVE_SCAN = 1    # scans/probes a specific target
    SINGLE_TARGET = 2  # e.g. deauth of one client/AP
    BROADCAST = 3      # mass/broadcast: mdk4 amok, beacon/probe flood, DoS
    MITM = 4           # evil-twin, MITM, traffic interception


_BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

# The exact phrase a T4 (MITM) authorisation must carry. Deliberately awkward to
# enter, because evil-twin and interception work should cost a sentence rather
# than a tick-box. (Do not start this comment with "# type:" — mypy reads that
# as a type comment and fails the whole file with "Invalid syntax".)
DANGEROUS_OPS_PHRASE = "I ACCEPT RESPONSIBILITY FOR INTERCEPTION"

# Tiers that can never be confirmed at a prompt mid-run. They have to be granted
# in the authorisation record before the run starts.
PRECONFIRM_REQUIRED_FROM = Tier.BROADCAST


def is_non_interactive() -> bool:
    """True when nothing can be confirmed at a prompt.

    CI, a cron job, a piped shell, or an explicit override. The T3 refusal is
    structural rather than a prompt nobody is there to answer.
    """
    override = os.environ.get("NETREAPER_NON_INTERACTIVE", "").strip().lower()
    if override in {"1", "true", "yes"}:
        return True
    try:
        return not sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return True

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
                allowed = ipaddress.ip_network(a, strict=False)
            except ValueError:
                continue
            # subnet_of requires the same address family; comparing IPv4 with
            # IPv6 raises TypeError, so narrow to the concrete type first (this
            # also makes the family check explicit rather than caught-and-skipped).
            if isinstance(net, ipaddress.IPv4Network) and isinstance(
                allowed, ipaddress.IPv4Network
            ):
                if net.subnet_of(allowed):
                    return True
            elif isinstance(net, ipaddress.IPv6Network) and isinstance(
                allowed, ipaddress.IPv6Network
            ):
                if net.subnet_of(allowed):
                    return True
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
    # Tiers this authorisation PRE-CONFIRMS. A confirmation cannot be obtained at
    # a prompt in a non-interactive run, so anything needing one has to be granted
    # here, in the authorisation record, before the run starts. The grant is
    # inside the consent digest, so it cannot be bolted on afterwards without
    # breaking verify_consent().
    confirmed_tiers: frozenset[Tier] = field(default_factory=frozenset)
    # T4 (MITM) additionally requires this exact phrase, typed deliberately. A
    # ceiling and a tick-box are not enough for evil-twin/interception work.
    dangerous_ops_phrase: str = ""
    # A tamper-evident fingerprint of the authorising fields (plan §5.2),
    # computed at construction. verify_consent() detects a later mutation of the
    # scope/operator/expiry so an altered authorisation record is caught.
    consent_hash: str = field(init=False, default="")

    def __post_init__(self) -> None:
        # An engagement whose authorisation_ref is blank records no authorisation.
        # The consent hash would still verify, and every audit line written under
        # it would claim an authority that points nowhere, so refuse it at
        # construction rather than let it reach the trail.
        if not self.authorization_ref or not self.authorization_ref.strip():
            raise ValueError(
                "authorization_ref must not be empty: an engagement has to name "
                "the authorisation it runs under"
            )
        if not self.operator or not self.operator.strip():
            raise ValueError("operator must not be empty")
        self.consent_hash = self._consent_digest()

    def _consent_digest(self) -> str:
        body = {
            "operator": self.operator,
            "authorization_ref": self.authorization_ref,
            "scope": {
                "cidrs": sorted(self.scope.cidrs),
                "hostnames": sorted(self.scope.hostnames),
                "bssids": sorted(b.upper() for b in self.scope.bssids),
                "essids": sorted(self.scope.essids),
                "deny": sorted(self.scope.deny),
            },
            "started_at": self.started_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_tier": int(self.max_tier),
            "confirmed_tiers": sorted(int(x) for x in self.confirmed_tiers),
            "dangerous_ops_phrase": self.dangerous_ops_phrase,
        }
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def verify_consent(self) -> bool:
        """True iff the authorising fields still match the consent hash."""
        return self.consent_hash == self._consent_digest()

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
        self._check_engagement_usable(eng, tier)

        # SEC-001 §3. A ceiling says what this engagement MAY reach; it is not a
        # confirmation that this particular action was intended. requires_confirmation
        # was accepted and then ignored everywhere, so it enforced nothing at all.
        self._require_confirmation(eng, tier, requires_confirmation)

        if not targets:
            raise TargetValidationError(
                "deny-by-default: this action has no identifiable in-scope target"
            )

        for target in targets:
            self._check_target(target, eng, tier)

    def _check_engagement_usable(self, eng: Engagement, tier: Tier) -> None:
        """Expiry, tamper-evidence and the ceiling. Every gated path runs these."""
        if not eng.is_active():
            raise TargetValidationError(
                "engagement has expired; re-authorise before continuing"
            )
        if not eng.verify_consent():
            raise TargetValidationError(
                "engagement consent hash does not verify — the authorisation "
                "record was altered after it was granted; re-authorise"
            )
        if tier > eng.max_tier:
            raise TargetValidationError(
                f"tier {tier.name} exceeds this engagement's ceiling "
                f"({eng.max_tier.name}); raise the engagement's max_tier to authorise it"
            )

    def require_confirmation(
        self, *, tier: Tier = Tier.PASSIVE, requires_confirmation: bool = False
    ) -> None:
        """Check the confirmation rules alone, with no target scoping.

        For callers that know an action's declared cost before they know its
        target: a plan step threads its target through the chain state, so the
        leaf gates the real target at the seam while this settles the
        confirmation question earlier, where the declaration lives.
        """
        eng = self._engagement
        if eng is None:
            raise TargetValidationError(
                "deny-by-default: no active engagement; a step declared "
                "destructive or needing confirmation cannot run without one"
            )
        # These three ran in authorize() and were skipped here, so an EXPIRED
        # engagement passed, a TAMPERED one passed, and one whose ceiling was
        # SINGLE_TARGET happily confirmed MITM. A shortcut past the gate's
        # preconditions is a hole in the gate.
        self._check_engagement_usable(eng, tier)
        self._require_confirmation(eng, tier, requires_confirmation)

    def _require_confirmation(
        self, eng: Engagement, tier: Tier, requires_confirmation: bool
    ) -> None:
        """Enforce the per-tier confirmation rules. Raises, or returns silently.

        T4 (MITM) needs the tier pre-confirmed AND the exact dangerous-ops phrase.
        T3 (BROADCAST) and above need the tier pre-confirmed; there is no prompt
        fallback, because a mass/broadcast action must never be answerable by
        whatever happens to be on stdin. T2 and anything flagged
        ``requires_confirmation`` need the tier pre-confirmed too. Nothing here
        prompts, so an attached terminal grants nothing: the earlier "an
        operator could have been asked" carve-out was auto-confirmation.
        """
        needs = requires_confirmation or tier >= Tier.SINGLE_TARGET
        if not needs:
            return

        confirmed = tier in eng.confirmed_tiers

        if tier >= Tier.MITM:
            if not confirmed:
                raise TargetValidationError(
                    f"tier {tier.name} requires explicit pre-confirmation; add "
                    f"{tier.name} to the engagement's confirmed_tiers"
                )
            if eng.dangerous_ops_phrase != DANGEROUS_OPS_PHRASE:
                raise TargetValidationError(
                    f"tier {tier.name} requires the dangerous-ops phrase on the "
                    f"engagement; it is missing or does not match"
                )
            return

        if tier >= PRECONFIRM_REQUIRED_FROM:
            if not confirmed:
                raise TargetValidationError(
                    f"tier {tier.name} is a mass/broadcast action and cannot be "
                    f"confirmed mid-run; it must be granted in the authorisation "
                    f"record (confirmed_tiers) before the engagement starts"
                )
            return

        # T2, or anything the manifest flagged. NOTHING here ever prompts, so a
        # missing grant is a refusal whether or not a terminal is attached. The
        # first cut of this let an attached TTY through on the reasoning that an
        # operator "could have been asked", which auto-confirmed exactly what
        # SEC-001 §3 says must never be auto-confirmed: nobody was asked anything.
        if confirmed:
            return
        why = (
            " and this run is non-interactive, so nobody can be asked"
            if is_non_interactive()
            else " and nothing prompts mid-run"
        )
        raise TargetValidationError(
            f"tier {tier.name} requires confirmation{why}; add {tier.name} to "
            f"the engagement's confirmed_tiers to authorise it up front"
        )

    def _check_target(self, target: str, eng: Engagement, tier: Tier) -> None:
        t = target.strip()

        # Broadcast / everything targets are refused at EVERY tier, including
        # BROADCAST and MITM. This comment used to read "only at BROADCAST+
        # tier, never implicitly", which described an allowance the code has
        # never had and invited a future reader to "fix" the code to match it.
        # Nothing in src passes these: a broadcast deauth is T3 but still names
        # the AP's BSSID (tools/aireplay.py), and the MITM paths name an ESSID.
        # A tier is a blast-radius ceiling, not a licence to stop naming a
        # target, so if a mass action ever needs one it needs its own grammar.
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
                # Both checks, because they encode the same policy in two
                # forms: the explicit range list, and the address properties
                # that the bare-IP branch already used. Without the second,
                # 200::1 was refused and 200::1/128 was allowed.
                if is_protected_network(net) or any(
                    net.overlaps(pn) for pn in _PROTECTED_NETS if pn.version == net.version
                ):
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
    """Shape AND content. It checked only the shape, so "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"
    was routed to the BSSID check instead of falling through to hostname/ESSID,
    denying a target that might legitimately be in scope as an ESSID."""
    parts = s.replace("-", ":").split(":")
    return len(parts) == 6 and all(
        len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts
    )


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
