# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Chain executor: runs a ChainDefinition's steps in dependency order.

Every step is authorised through the scope gate before it can run (via the step
runner, which ultimately spawns through ProcessRunner). Tool invocation is
delegated to an injectable ``step_runner`` so the orchestration is testable
without real tools; the backward-chaining goal planner is layered on top of this
in a later phase.
"""
from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from netreaper.chaining.models import (
    ChainDefinition,
    ChainResult,
    ChainStep,
    OnErrorBehavior,
    StepResult,
    StepStatus,
)
from netreaper.core.exceptions import PluginError

StepRunner = Callable[[ChainStep, str, dict], Awaitable[dict]]


async def _default_step_runner(step: ChainStep, target: str, state: dict) -> dict:
    raise PluginError(
        f"no tool adapter wired for step {step.id!r} (tool {step.tool!r}); "
        "inject a step_runner or register the tool's adapter"
    )


def _order(steps: list[ChainStep]) -> list[ChainStep]:
    """Topological order by depends_on (stable, cycle-guarded)."""
    by_id = {s.id: s for s in steps}
    ordered: list[ChainStep] = []
    seen: set[str] = set()
    temp: set[str] = set()

    def visit(step: ChainStep) -> None:
        if step.id in seen:
            return
        if step.id in temp:
            raise PluginError(f"dependency cycle detected at step {step.id!r}")
        temp.add(step.id)
        for dep in step.depends_on:
            if dep in by_id:
                visit(by_id[dep])
        temp.discard(step.id)
        seen.add(step.id)
        ordered.append(step)

    for s in steps:
        visit(s)
    return ordered


class ChainExecutor:
    """Executes a chain sequentially in dependency order."""

    def __init__(self, step_runner: StepRunner | None = None) -> None:
        self._run_step = step_runner or _default_step_runner

    async def execute(self, chain: ChainDefinition, target: str = "") -> ChainResult:
        started = datetime.now(UTC)
        t0 = time.monotonic()
        result = ChainResult(chain_id=chain.id, success=True, started_at=started)
        state: dict = {}

        for step in _order(chain.steps):
            # honour dependency failures
            if any(
                dep in result.steps and result.steps[dep].status is StepStatus.FAILED
                for dep in step.depends_on
            ):
                result.steps[step.id] = StepResult(
                    step_id=step.id, tool=step.tool, status=StepStatus.SKIPPED,
                    errors=["skipped: a dependency failed"],
                )
                continue

            sr = StepResult(
                step_id=step.id, tool=step.tool, status=StepStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            s0 = time.monotonic()
            try:
                data = await self._run_step(step, step.target_static or target, state)
                sr.data = data or {}
                sr.status = StepStatus.COMPLETED
                state[step.output_key or step.id] = sr.data
            except Exception as exc:
                sr.status = StepStatus.FAILED
                sr.errors.append(str(exc))
                if step.on_error is OnErrorBehavior.STOP:
                    sr.ended_at = datetime.now(UTC)
                    sr.duration = time.monotonic() - s0
                    result.steps[step.id] = sr
                    result.success = False
                    result.errors.append(f"{step.id}: {exc}")
                    break
            sr.ended_at = datetime.now(UTC)
            sr.duration = time.monotonic() - s0
            result.steps[step.id] = sr

        result.final_output = state
        result.total_duration = time.monotonic() - t0
        result.ended_at = datetime.now(UTC)
        result.success = result.success and all(
            r.status is not StepStatus.FAILED for r in result.steps.values()
        )
        return result


__all__ = ["ChainExecutor", "StepRunner"]
