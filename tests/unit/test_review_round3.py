# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression tests for the third review pass."""
from __future__ import annotations

import pytest

from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate


@pytest.fixture(autouse=True)
def _gate():
    g = get_scope_gate()
    g.set_engagement(
        Engagement(operator="t", authorization_ref="T",
                   scope=Scope(cidrs=["169.254.0.0/16", "10.0.0.0/8"]), max_tier=Tier.BROADCAST)
    )
    yield g
    g.clear_engagement()


# §1 HIGH: a protected range is refused at ANY CIDR width, not just /32
@pytest.mark.parametrize("cidr", ["169.254.169.254/32", "169.254.169.254/31", "169.254.0.0/24", "127.0.0.0/24"])
def test_protected_range_denied_any_width(_gate, cidr):
    with pytest.raises(TargetValidationError):
        _gate.authorize([cidr], tier=Tier.ACTIVE_SCAN)


def test_normal_cidr_still_allowed(_gate):
    _gate.authorize(["10.0.0.0/24"], tier=Tier.ACTIVE_SCAN)  # no raise


# §2 MEDIUM: a malformed CIDR is a clean TargetValidationError, not a raw ValueError
@pytest.mark.parametrize("bad", ["10.0.0.5/33", "10.0.0.5/-1", "10.0.0.5/abc", "10.0.0.5/"])
def test_malformed_cidr_is_target_validation_error(_gate, bad):
    with pytest.raises(TargetValidationError):
        _gate.authorize([bad], tier=Tier.ACTIVE_SCAN)
