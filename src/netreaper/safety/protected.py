# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Classification of IP targets: private, protected, or public.

Used by the scope gate and by target validation to reason about blast radius.
"""
from __future__ import annotations

import ipaddress

from netreaper.safety.validators import validate_ip


def _as_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError:
        return None


def is_protected_ip(ip: str) -> bool:
    """(Literal IP/CIDR targets only; hostnames are not DNS-resolved by the gate.)
    True for addresses that must never be targeted (loopback, link-local,
    multicast, reserved, unspecified, broadcast)."""
    addr = _as_ip(ip)
    if addr is None:
        return False
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or (isinstance(addr, ipaddress.IPv4Address)
            and addr == ipaddress.IPv4Address("255.255.255.255"))
    )


def is_protected_network(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """The network form of :func:`is_protected_ip`, using the same policy.

    The gate had two different "must never be targeted" lists: a hand-written
    tuple of ten ranges for CIDR targets, and this module's property checks for
    bare addresses. IPv6 ``is_reserved`` alone covers far more than the four
    IPv6 ranges in that tuple, so ``200::1`` was refused and ``200::1/128``,
    the identical address, was allowed. One policy, both forms.
    """
    return bool(
        net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_reserved
        or net.is_unspecified
    )


def is_public_ip(ip: str) -> bool:
    """True for globally-routable (non-private, non-protected) addresses."""
    addr = _as_ip(ip)
    if addr is None:
        return False
    return addr.is_global and not addr.is_multicast


def check_target_safety(target: str) -> tuple[bool, str]:
    """Return ``(is_dangerous, reason)`` for a target string.

    ``is_dangerous`` is True when the target is protected (must be refused) or
    public (allowed only with explicit authorisation). Private targets are safe.

    NOT AN AUTHORISATION GATE. This is a coarse address classifier and knows
    nothing about the active :class:`~netreaper.safety.Engagement`/``Scope``: a
    private target it calls "safe" may still be out of scope. Never use it as a
    pre-flight authorisation check; that is ``get_scope_gate().authorize(...)``.
    Deliberately kept off the package's public ``__all__`` so it is not mistaken
    for one.
    """
    ip = target.strip()
    try:
        ip = validate_ip(ip)
    except Exception:
        # Not a bare IP (hostname/CIDR); defer to the scope gate / validators.
        return (False, "non-ip target; scope gate decides")
    if is_protected_ip(ip):
        return (True, f"{ip} is a protected/reserved address and must not be targeted")
    if is_public_ip(ip):
        return (True, f"{ip} is a public address; explicit authorisation required")
    return (False, f"{ip} is a private address")


__all__ = ["is_protected_ip", "is_public_ip"]
