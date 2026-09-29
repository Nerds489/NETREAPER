# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #106: ChainStep declares condition/retry/fallback; the executor honours them.

ChainStep exposes ``condition``, ``on_error`` (STOP/SKIP/RETRY/FALLBACK),
``retry_count``, ``retry_delay`` and ``fallback_tool``. The executor previously
read only ``on_error is STOP``, so a step configured to retry ran once, a
fallback tool was never invoked, and a skip condition never skipped. These tests
pin the implemented semantics. Defaults (STOP, no condition) keep the old
behaviour and are covered by the existing chain tests.
"""
from __future__ import annotations

import pytest

from netreaper.chaining.executor import ChainExecutor
from netreaper.chaining.models import (
    ChainDefinition,
    ChainStep,
    Condition,
    OnErrorBehavior,
    StepStatus,
)

pytestmark = pytest.mark.asyncio


def _chain(*steps: ChainStep) -> ChainDefinition:
    return ChainDefinition(id="c", name="c", description="", steps=list(steps))


async def test_retry_runs_up_to_retry_count_then_gives_up():
    calls = {"n": 0}

    async def runner(step, target, state):
        calls["n"] += 1
        raise RuntimeError("boom")

    step = ChainStep(
        id="s1", tool="flaky", on_error=OnErrorBehavior.RETRY,
        retry_count=3, retry_delay=0,
    )
    result = await ChainExecutor(runner).execute(_chain(step))

    assert calls["n"] == 4, "one initial attempt + 3 retries"
    assert result.steps["s1"].status is StepStatus.FAILED
    assert result.success is False


async def test_retry_stops_early_once_a_try_succeeds():
    calls = {"n": 0}

    async def runner(step, target, state):
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("transient")
        return {"ok": True}

    step = ChainStep(
        id="s1", tool="flaky", on_error=OnErrorBehavior.RETRY,
        retry_count=5, retry_delay=0,
    )
    result = await ChainExecutor(runner).execute(_chain(step))

    assert calls["n"] == 2
    assert result.steps["s1"].status is StepStatus.COMPLETED
    assert result.success is True


async def test_fallback_tool_runs_when_primary_fails():
    seen = []

    async def runner(step, target, state):
        seen.append(step.tool)
        if step.tool == "primary":
            raise RuntimeError("no good")
        return {"via": step.tool}

    step = ChainStep(
        id="s1", tool="primary", on_error=OnErrorBehavior.FALLBACK,
        fallback_tool="backup",
    )
    result = await ChainExecutor(runner).execute(_chain(step))

    assert seen == ["primary", "backup"]
    assert result.steps["s1"].status is StepStatus.COMPLETED
    assert result.steps["s1"].data == {"via": "backup"}
    assert result.success is True


async def test_condition_skips_a_step_whose_guard_is_not_met():
    ran = []

    async def runner(step, target, state):
        ran.append(step.tool)
        if step.id == "producer":
            return {"hosts": []}
        return {}

    producer = ChainStep(id="producer", tool="scan", output_key="scan")
    guarded = ChainStep(
        id="guarded", tool="exploit", depends_on=["producer"],
        condition=Condition(
            source_step="scan", check="count_gt", path="hosts", value=0,
        ),
    )
    result = await ChainExecutor(runner).execute(_chain(producer, guarded))

    assert ran == ["scan"], "the guarded step must not run when hosts is empty"
    assert result.steps["guarded"].status is StepStatus.SKIPPED


async def test_skip_on_error_does_not_fail_the_chain():
    async def runner(step, target, state):
        if step.id == "s1":
            raise RuntimeError("ignore me")
        return {}

    s1 = ChainStep(id="s1", tool="optional", on_error=OnErrorBehavior.SKIP)
    s2 = ChainStep(id="s2", tool="main")
    result = await ChainExecutor(runner).execute(_chain(s1, s2))

    assert result.steps["s1"].status is StepStatus.SKIPPED
    assert result.steps["s2"].status is StepStatus.COMPLETED
    assert result.success is True
