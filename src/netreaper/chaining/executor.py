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

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from netreaper.chaining.models import (
    ChainDefinition,
    ChainResult,
    ChainStep,
    Condition,
    OnErrorBehavior,
    StepResult,
    StepStatus,
)
from netreaper.chaining.paths import resolve_path
from netreaper.core.exceptions import PluginError, TargetValidationError

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


def _check_condition(check: str, value: object, expected: object) -> bool:
    """Evaluate one Condition check against a resolved value.

    Mirrors the checks documented on :class:`Condition`. An unknown check name is
    a chain-authoring error and is raised, never silently treated as "skip".
    """
    if check == "exists":
        return value is not None
    if check == "value_eq":
        return value == expected
    if check == "value_ne":
        return value != expected
    if check == "has_key":
        return isinstance(value, dict) and expected in value
    if check == "contains":
        try:
            return value is not None and expected in value  # type: ignore[operator]
        except TypeError:
            return False
    if check in ("count_gt", "count_lt"):
        try:
            n = len(value)  # type: ignore[arg-type]
        except TypeError:
            return False
        return n > expected if check == "count_gt" else n < expected  # type: ignore[operator]
    raise PluginError(f"unknown chain condition check {check!r}")


def _condition_met(cond: Condition, state: dict[str, Any]) -> bool:
    """True if ``cond`` is satisfied against the accumulated chain ``state``."""
    source = state.get(cond.source_step)
    value = resolve_path(source, cond.path) if source is not None else None
    result = _check_condition(cond.check, value, cond.value)
    return (not result) if cond.negate else result


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

            # pre-run guard: a step whose condition is not met is skipped, not run
            if step.condition is not None and not _condition_met(step.condition, state):
                result.steps[step.id] = StepResult(
                    step_id=step.id, tool=step.tool, status=StepStatus.SKIPPED,
                    errors=["skipped: condition not met"],
                )
                continue

            sr = StepResult(
                step_id=step.id, tool=step.tool, status=StepStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            s0 = time.monotonic()

            data, exc = await self._run_with_retry(step, target, state)
            if exc is None:
                sr.data = data or {}
                sr.status = StepStatus.COMPLETED
                state[step.output_key or step.id] = sr.data
            elif step.on_error is OnErrorBehavior.FALLBACK and step.fallback_tool:
                fb = replace(
                    step, tool=step.fallback_tool, fallback_tool=None,
                    on_error=OnErrorBehavior.STOP, condition=None,
                )
                fb_data, fb_exc = await self._run_once(fb, target, state)
                if fb_exc is None:
                    sr.data = fb_data or {}
                    sr.status = StepStatus.COMPLETED
                    sr.errors.append(
                        f"{step.tool!r} failed ({exc}); used fallback "
                        f"{step.fallback_tool!r}"
                    )
                    state[step.output_key or step.id] = sr.data
                else:
                    sr.status = StepStatus.FAILED
                    sr.errors.append(str(exc))
                    sr.errors.append(
                        f"fallback {step.fallback_tool!r} also failed: {fb_exc}"
                    )
            elif step.on_error is OnErrorBehavior.SKIP:
                sr.status = StepStatus.SKIPPED
                sr.errors.append(f"skipped after error: {exc}")
            else:
                # STOP, RETRY exhausted, or FALLBACK with no fallback_tool set
                sr.status = StepStatus.FAILED
                sr.errors.append(str(exc))

            sr.ended_at = datetime.now(UTC)
            sr.duration = time.monotonic() - s0
            result.steps[step.id] = sr

            if sr.status is StepStatus.FAILED and step.on_error is OnErrorBehavior.STOP:
                result.success = False
                result.errors.append(f"{step.id}: {exc}")
                break

        return await self._finalise(result, state, t0)

    async def _run_once(
        self, step: ChainStep, target: str, state: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, Exception | None]:
        """Run a step once. A scope-gate denial propagates; other errors return."""
        try:
            data = await self._run_step(step, step.target_static or target, state)
            return (data, None)
        except TargetValidationError:
            raise  # a scope-gate denial is never a routine step failure
        except Exception as exc:  # a step failure is reported on the StepResult
            return (None, exc)

    async def _run_with_retry(
        self, step: ChainStep, target: str, state: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, Exception | None]:
        """Run a step, retrying only when its on_error policy is RETRY."""
        attempts = 1
        if step.on_error is OnErrorBehavior.RETRY:
            attempts = max(1, 1 + step.retry_count)
        data: dict[str, Any] | None = None
        exc: Exception | None = None
        for i in range(attempts):
            data, exc = await self._run_once(step, target, state)
            if exc is None:
                return (data, None)
            if i < attempts - 1 and step.retry_delay > 0:
                await asyncio.sleep(step.retry_delay)
        return (data, exc)

    @staticmethod
    async def _finalise(
        result: ChainResult, state: dict[str, Any], t0: float
    ) -> ChainResult:
        result.final_output = state
        result.total_duration = time.monotonic() - t0
        result.ended_at = datetime.now(UTC)
        result.success = result.success and all(
            r.status is not StepStatus.FAILED for r in result.steps.values()
        )
        return result


__all__ = ["ChainExecutor", "StepRunner"]
