# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Bridge the backward-chaining planner to the existing ChainExecutor.

:func:`plan_to_chain` compiles a resolved :class:`~netreaper.chaining.manifest.Plan`
into a runnable :class:`~netreaper.chaining.models.ChainDefinition` — one
``ChainStep`` per manifest, with ``depends_on`` edges derived from each manifest's
``requires`` mapped back to the plan step that ``provides`` it.
:func:`manifest_step_runner` returns a step runner that dispatches each step to
its manifest's ``runner`` coroutine.

Together these are the "planner sits above the ChainExecutor" wiring the design
doc describes: resolve a goal into an ordered plan, compile it, and run it in
dependency order with each tool's outputs threaded into the shared state — the
ChainExecutor itself is unchanged.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from netreaper.chaining.manifest import ManifestRegistry, Plan, manifest_registry
from netreaper.chaining.models import ChainDefinition, ChainStep
from netreaper.core.exceptions import PluginError
from netreaper.safety.scope import Tier, get_scope_gate

StepRunner = Callable[[ChainStep, str, dict[str, object]], Awaitable[dict[str, object]]]


def plan_to_chain(plan: Plan, *, chain_id: str = "auto") -> ChainDefinition:
    """Compile a resolved plan into a runnable ChainDefinition.

    A step's ``depends_on`` is the set of plan steps that produce the capabilities
    it requires; a required capability with no producer in the plan was supplied
    as external available state and adds no edge.
    """
    provider: dict[str, str] = {}
    for m in plan.steps:
        for cap in m.provides:
            provider[cap] = m.name
    steps: list[ChainStep] = []
    for m in plan.steps:
        deps: list[str] = []
        for req in m.requires:
            owner = provider.get(req)
            if owner is not None and owner not in deps:
                deps.append(owner)
        steps.append(ChainStep(id=m.name, tool=m.name, depends_on=deps))
    return ChainDefinition(
        id=chain_id,
        name=f"auto: {plan.goal}",
        description=f"auto-resolved plan for {plan.goal}",
        steps=steps,
    )


def manifest_step_runner(
    registry: ManifestRegistry = manifest_registry,
) -> StepRunner:
    """A ChainExecutor step runner that dispatches each step to its manifest runner."""

    async def _run(
        step: ChainStep, target: str, state: dict[str, object]
    ) -> dict[str, object]:
        m = registry.get(step.tool)
        if m.runner is None:
            raise PluginError(
                f"no runner wired for {m.name!r}; the manifest is planning-only"
            )
        # #46 item 2: the manifest is the single source of truth for what a step
        # costs, but destructive/requires_confirmation only ever drove a
        # "[confirm]" badge in Plan.render. The leaf adapter decided its own tier
        # independently, so a manifest could declare an action destructive and
        # needing confirmation while the tool underneath ran it ungated, with
        # nothing forcing the two to agree.
        #
        # Enforce the declaration here, where the manifest and the dispatch meet.
        # The leaf still gates itself at the seam; this is the earlier, coarser
        # check that makes the manifest's own words binding.
        #
        # needs_hardware is deliberately NOT part of this gate. Unlike the two
        # flags above it is a capability prerequisite, not an authorisation: the
        # leaf fails on its own when the adapter or interface is absent, no
        # generic check can settle "hardware present" in advance the way
        # os.geteuid() settles root, and a planning-only manifest already errors
        # above. Gating on it would force an engagement onto every hardware chain
        # for no safety gain, so it stays the [hw] planning badge in
        # Plan.render. test_manifest_declaration_binds pins that it does not gate.
        if m.destructive or m.requires_confirmation:
            # Deriving the tier from `destructive` capped this at T2 and, worse,
            # checked a requires_confirmation-only manifest at PASSIVE, the one
            # tier that never needs confirming, silently skipping the very check
            # the manifest asked for. Use the manifest's own tier where it has
            # one, and never fall below SINGLE_TARGET once it has declared a cost.
            tier = getattr(m, "tier", None) or Tier.SINGLE_TARGET
            gate = get_scope_gate()
            if target:
                gate.authorize(
                    [target],
                    tier=tier,
                    destructive=m.destructive,
                    requires_confirmation=m.requires_confirmation,
                )
            else:
                # A plan step often carries no target of its own: the chain
                # threads it through the shared state and the leaf gates the
                # real one at the spawn seam. Settle the confirmation here
                # anyway, because that part does not depend on the target.
                gate.require_confirmation(
                    tier=tier, requires_confirmation=m.requires_confirmation
                )
        return await m.runner(state, target)

    return _run


__all__ = ["StepRunner", "manifest_step_runner", "plan_to_chain"]
