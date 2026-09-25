# SPDX-License-Identifier: GPL-3.0-or-later
"""The first non-wireless planner path: web recon (#33, slice 2).

Mirrors test_autochain: manifests declare the ordering, build_web_registry binds
them to the real adapters, and the planner resolves a goal into an ordered chain
run through the ChainExecutor. The chain is deliberately shallow but real:
fingerprint first, then path enumeration and vuln scan, which is ordinary recon
sequencing (see web/manifests.py for why fingerprint gates the other two).
"""
from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from netreaper.chaining.executor import ChainExecutor
from netreaper.chaining.manifest import MissingCapabilityError, resolve_chain
from netreaper.chaining.plan_exec import manifest_step_runner, plan_to_chain
from netreaper.cli import app
from netreaper.web.autochain import build_web_registry
from netreaper.web.manifests import WEB_MANIFESTS, register_web_manifests

runner = CliRunner()


# ── manifests and planning ────────────────────────────────────────────────────


def test_fingerprint_gates_paths_and_findings():
    reg = build_web_registry(None)
    plan = resolve_chain("web.findings", reg)
    assert [m.name for m in plan.steps] == ["fingerprint_web", "scan_web"]

    plan_paths = resolve_chain("web.paths", reg)
    assert [m.name for m in plan_paths.steps] == ["fingerprint_web", "enumerate_paths"]


def test_fingerprint_alone_is_a_one_step_plan():
    plan = resolve_chain("web.fingerprint", build_web_registry(None))
    assert [m.name for m in plan.steps] == ["fingerprint_web"]


def test_an_already_known_fingerprint_skips_the_first_step():
    reg = build_web_registry(None)
    plan = resolve_chain("web.findings", reg, available={"web.fingerprint"})
    assert [m.name for m in plan.steps] == ["scan_web"]


def test_plan_to_chain_derives_the_fingerprint_edge():
    reg = build_web_registry(None)
    chain = plan_to_chain(resolve_chain("web.findings", reg))
    deps = {s.id: s.depends_on for s in chain.steps}
    assert deps["fingerprint_web"] == []
    assert deps["scan_web"] == ["fingerprint_web"]


def test_an_unknown_goal_names_itself():
    with pytest.raises(MissingCapabilityError, match=r"web\.nonexistent"):
        resolve_chain("web.nonexistent", build_web_registry(None))


def test_the_manifest_set_declares_the_three_web_capabilities():
    provided = {c for m in WEB_MANIFESTS for c in m.provides}
    assert provided == {"web.fingerprint", "web.paths", "web.findings"}
    # None is destructive: recon reads, it does not attack.
    assert not any(m.destructive for m in WEB_MANIFESTS)


def test_the_global_registrar_registers_them():
    from netreaper.chaining.manifest import ManifestRegistry

    reg = ManifestRegistry()
    register_web_manifests(reg)
    assert reg.find_provider("web.findings") is not None


# ── the live chain, with fakes (no real tools spawned) ───────────────────────


def _fake_registry(calls: list[str], *, fail: str | None = None):
    """A registry whose runners record their order instead of spawning tools."""
    import dataclasses

    def _mk(name: str, cap: str):
        async def _run(_state, _target):
            calls.append(name)
            if fail == name:
                from netreaper.core.exceptions import PluginError

                raise PluginError(f"{name} failed")
            return {cap: f"{cap}-result"}

        return _run

    from netreaper.chaining.manifest import ManifestRegistry

    caps = {
        "fingerprint_web": "web.fingerprint",
        "enumerate_paths": "web.paths",
        "scan_web": "web.findings",
    }
    reg = ManifestRegistry()
    for m in WEB_MANIFESTS:
        reg.register(dataclasses.replace(m, runner=_mk(m.name, caps[m.name])))
    return reg


def test_the_chain_runs_fingerprint_before_findings():
    calls: list[str] = []
    reg = _fake_registry(calls)
    plan = resolve_chain("web.findings", reg)
    result = asyncio.run(
        ChainExecutor(step_runner=manifest_step_runner(reg)).execute(plan_to_chain(plan))
    )
    assert result.success is True
    assert calls == ["fingerprint_web", "scan_web"]


def test_a_failed_fingerprint_stops_the_chain_before_findings():
    calls: list[str] = []
    reg = _fake_registry(calls, fail="fingerprint_web")
    plan = resolve_chain("web.findings", reg)
    result = asyncio.run(
        ChainExecutor(step_runner=manifest_step_runner(reg)).execute(plan_to_chain(plan))
    )
    assert result.success is False
    assert calls == ["fingerprint_web"]  # scan_web never ran


# ── the CLI verb ──────────────────────────────────────────────────────────────


def test_cli_web_auto_dry_run_prints_the_plan_and_does_not_execute():
    result = runner.invoke(app, ["web", "auto", "http://example.com"])
    assert result.exit_code == 0
    assert "fingerprint_web" in result.stdout
    assert "scan_web" in result.stdout
    assert "Dry run" in result.stdout


def test_cli_web_auto_unresolvable_goal_exits_2():
    result = runner.invoke(
        app, ["web", "auto", "http://example.com", "-g", "web.nope"]
    )
    assert result.exit_code == 2


def test_cli_web_auto_paths_goal_plans_gobuster():
    result = runner.invoke(
        app, ["web", "auto", "http://example.com", "-g", "web.paths"]
    )
    assert result.exit_code == 0
    assert "enumerate_paths" in result.stdout


def test_build_web_registry_tolerates_none_for_planning():
    """`web plan`-style callers build a runnerless registry; it must still resolve."""
    reg = build_web_registry(None)
    assert reg.find_provider("web.fingerprint") is not None
