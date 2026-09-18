# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""External sources NETREAPER incorporates, declared rather than assumed.

Issue #33 opens the platform to non-wireless domains. The sources that feed them
are other people's work under other people's licences, and they are not all the
same kind of thing: some are data to consume, some are tools to wrap, some are
reference material that belongs in documentation and must never become code.

Getting that wrong has two failure modes, so both are encoded here rather than
left to whoever adds the next one:

  LICENCE. NETREAPER is GPL-3.0-or-later. A source cannot be VENDORED until its
  licence is verified compatible. The registry refuses to describe a source as
  vendored while its licence is unverified, and a test enforces it, because
  "we'll check later" is how a licence violation ships.

  PHYSICAL SAFETY. Some automotive work does not stay inside information
  security. Reading and decoding a CAN bus is analysis. Writing arbitrary frames
  to the bus of a moving vehicle, or driving its steering, throttle and brakes,
  can injure people, and no scope gate makes that a security control. Sources of
  that kind carry a safety_note and are REFERENCED only: their protocol
  knowledge is documented, their actuation capability is not built.
"""
from __future__ import annotations

from netreaper.resources.registry import (
    SOURCES,
    ExternalSource,
    Incorporation,
    Kind,
    by_domain,
    fetchable,
    get_source,
    unverified_licences,
)

__all__ = [
    "SOURCES",
    "ExternalSource",
    "Incorporation",
    "Kind",
    "by_domain",
    "fetchable",
    "get_source",
    "unverified_licences",
]
