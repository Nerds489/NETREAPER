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
        return await m.runner(state, target)

    return _run


__all__ = ["StepRunner", "manifest_step_runner", "plan_to_chain"]
