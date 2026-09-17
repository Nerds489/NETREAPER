# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #46 item 2: what a manifest declares actually binds.

``ToolManifest`` carries ``destructive`` and ``requires_confirmation``, and
before this they drove exactly one thing: a ``[confirm]`` badge in
``Plan.render``. The execution tier was decided separately at the leaf adapter,
so a manifest could declare an action destructive and needing confirmation
while the step ran with no authorisation at all, and nothing forced the two to
agree.

The proof it was hollow: the whole live wifi auto-chain suite ran
``capture_handshake`` (declared ``destructive=True, requires_confirmation=True``,
a targeted deauth) with **no engagement whatsoever**, and passed.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.chaining.manifest import ManifestRegistry, ToolManifest
from netreaper.chaining.models import ChainStep
from netreaper.chaining.plan_exec import manifest_step_runner
from netreaper.core.exceptions import TargetValidationError
from netreaper.safety.scope import Engagement, Scope, Tier, get_scope_gate


async def _runner(state, target):
    return {"ran": True}


def _registry(**flags):
    reg = ManifestRegistry()
    reg.register(
        ToolManifest(
            name="capture_handshake", domain="wifi",
            provides=("wifi.handshake",), runner=_runner, **flags,
        )
    )
    return reg


def _eng(**kw):
    return Engagement(
        operator="t", authorization_ref="SOW-1",
        scope=Scope(cidrs=["10.0.0.0/24"]), max_tier=Tier.MITM, **kw
    )


def _run(reg, target="10.0.0.5"):
    return asyncio.run(
        manifest_step_runner(reg)(ChainStep(id="s", tool="capture_handshake"), target, {})
    )


@pytest.fixture(autouse=True)
def _clear():
    yield
    get_scope_gate().clear_engagement()


def test_a_declared_destructive_step_cannot_run_without_an_engagement():
    get_scope_gate().clear_engagement()
    with pytest.raises(TargetValidationError, match="no active engagement"):
        _run(_registry(destructive=True, requires_confirmation=True))


def test_a_declared_step_is_refused_without_the_confirmation_grant():
    get_scope_gate().set_engagement(_eng())
    with pytest.raises(TargetValidationError, match="requires confirmation"):
        _run(_registry(destructive=True, requires_confirmation=True))


def test_it_runs_once_the_grant_is_present():
    get_scope_gate().set_engagement(
        _eng(confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))
    )
    assert _run(_registry(destructive=True, requires_confirmation=True)) == {"ran": True}


def test_an_out_of_scope_target_is_refused_even_with_the_grant():
    get_scope_gate().set_engagement(
        _eng(confirmed_tiers=frozenset({Tier.SINGLE_TARGET}))
    )
    with pytest.raises(TargetValidationError):
        _run(_registry(destructive=True, requires_confirmation=True), target="8.8.8.8")


def test_a_targetless_step_still_settles_the_confirmation():
    """The chain threads the target through state, so the step often has none.

    The leaf still gates the real target at the seam; the declared confirmation
    must not be skipped just because the target is not known yet.
    """
    get_scope_gate().set_engagement(_eng())
    with pytest.raises(TargetValidationError, match="requires confirmation"):
        _run(_registry(destructive=True, requires_confirmation=True), target="")


def test_an_undeclared_step_is_untouched():
    """A plain manifest must not suddenly need an engagement."""
    get_scope_gate().clear_engagement()
    assert _run(_registry()) == {"ran": True}
