# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Capability manifests and the backward-chaining goal planner.

Implements the auto-chaining design: every tool declares what it ``provides`` and
``requires`` (capabilities namespaced by domain, e.g. ``wifi.password``), and
:func:`resolve_chain` takes a GOAL capability and walks ``requires`` → ``provides``
backward into an ordered plan, auto-including any missing prerequisite. It is
domain-agnostic — wifi, web, android and anything added later plug in with the
same manifest shape and no new planner code.

Guards the design doc left open: capability-namespacing is validated at manifest
construction; a second provider of a capability collides at registration; a
require-cycle is caught with a clear error instead of looping; and a capability
no tool provides raises :class:`MissingCapabilityError`, which names the unmet
capability so the caller sees exactly what is missing (the call raises rather
than returning a partial plan).

The planner sits ABOVE the existing :class:`~netreaper.chaining.executor.ChainExecutor`
(which is unchanged); compiling a resolved :class:`Plan` into a runnable
``ChainDefinition`` and feeding step outputs back as available state is a later slice.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from netreaper.core.exceptions import ConfigurationError, PluginError

# A manifest's optional live runner: a coroutine that executes the tool and
# returns its outputs. Left unset in the planning-only slice.
Runner = Callable[..., Awaitable[dict[str, object]]]


def _has_space(s: str) -> bool:
    return any(c.isspace() for c in s)


class MissingCapabilityError(PluginError):
    """No registered tool provides a required capability."""

    def __init__(self, capability: str) -> None:
        self.capability = capability
        super().__init__(f"no tool provides the capability {capability!r}")


@dataclass(frozen=True)
class ToolManifest:
    """What one tool provides and requires, namespaced by domain."""

    name: str
    domain: str
    provides: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    needs_hardware: bool = False
    destructive: bool = False
    requires_confirmation: bool = False
    runner: Runner | None = field(default=None, compare=False, hash=False)

    def __post_init__(self) -> None:
        if not self.name or not self.domain:
            raise ConfigurationError("a manifest needs a name and a domain")
        for cap in self.provides:
            head, _, tail = cap.partition(".")
            if head != self.domain or not tail or _has_space(cap):
                raise ConfigurationError(
                    f"{self.name}: provided capability {cap!r} must be "
                    f"'{self.domain}.<name>' with a non-empty name and no spaces"
                )
        for cap in self.requires:
            head, sep, tail = cap.partition(".")
            if not sep or not head or not tail or _has_space(cap):
                raise ConfigurationError(
                    f"{self.name}: required capability {cap!r} must be "
                    "'<domain>.<name>' with non-empty parts and no spaces"
                )


class ManifestRegistry:
    """Holds manifests and the capability → provider index (deny double-provide)."""

    def __init__(self) -> None:
        self._by_name: dict[str, ToolManifest] = {}
        self._provider: dict[str, str] = {}  # capability -> providing tool name

    def register(self, m: ToolManifest, *, replace: bool = False) -> None:
        if m.name in self._by_name and not replace:
            raise ConfigurationError(f"manifest {m.name!r} is already registered")
        # Collision: two different tools cannot provide the same capability.
        for cap in m.provides:
            owner = self._provider.get(cap)
            if owner is not None and owner != m.name:
                raise ConfigurationError(
                    f"capability {cap!r} is already provided by {owner!r}; "
                    f"{m.name!r} cannot also provide it"
                )
        # On replace, drop the old manifest's provider entries first.
        if replace and m.name in self._by_name:
            for cap in self._by_name[m.name].provides:
                if self._provider.get(cap) == m.name:
                    del self._provider[cap]
        self._by_name[m.name] = m
        for cap in m.provides:
            self._provider[cap] = m.name

    def find_provider(self, capability: str) -> ToolManifest | None:
        name = self._provider.get(capability)
        return self._by_name.get(name) if name is not None else None

    def get(self, name: str) -> ToolManifest:
        try:
            return self._by_name[name]
        except KeyError:
            raise ConfigurationError(f"no manifest named {name!r}") from None

    def all(self) -> list[ToolManifest]:
        return list(self._by_name.values())

    def clear(self) -> None:
        self._by_name.clear()
        self._provider.clear()


@dataclass(frozen=True)
class Plan:
    """An ordered, resolved plan of manifests to run for a goal."""

    goal: str
    steps: tuple[ToolManifest, ...]

    def render(self) -> str:
        """Human-readable dry-run preview of the resolved chain."""
        if not self.steps:
            return f"Goal {self.goal!r} is already satisfied — nothing to run."
        lines = [f"Plan for goal {self.goal!r} ({len(self.steps)} step(s)):"]
        for i, m in enumerate(self.steps, 1):
            flags = "".join(
                t for t, on in (
                    (" [hw]", m.needs_hardware),
                    (" [destructive]", m.destructive),
                    (" [confirm]", m.requires_confirmation),
                ) if on
            )
            lines.append(
                f"  {i}. {m.name:<24} provides {', '.join(m.provides)}{flags}"
            )
        return "\n".join(lines)


def resolve_chain(
    goal: str,
    registry: ManifestRegistry,
    available: set[str] | tuple[str, ...] | None = None,
) -> Plan:
    """Backward-chain from ``goal`` into an ordered plan.

    ``available`` is capability state already known for the target (a scan already
    run, a handshake already captured); those capabilities short-circuit and their
    producers are not re-planned. Raises :class:`MissingCapabilityError` (naming
    the capability) when nothing provides a needed capability, and ``PluginError``
    on a require-cycle.
    """
    have: set[str] = set(available or ())
    plan: list[ToolManifest] = []
    resolving: set[str] = set()  # capabilities on the current DFS path (cycle guard)

    def visit(capability: str) -> None:
        if capability in have:
            return
        if capability in resolving:
            raise PluginError(
                f"dependency cycle detected while resolving {capability!r}"
            )
        tool = registry.find_provider(capability)
        if tool is None:
            raise MissingCapabilityError(capability)
        resolving.add(capability)
        for req in tool.requires:
            visit(req)
        resolving.discard(capability)
        # `have` already ensures a tool is reached once (all its outputs enter
        # `have` on append, short-circuiting any later visit); the membership
        # check is a cheap belt-and-braces against that invariant regressing.
        if tool not in plan:
            plan.append(tool)
            # Every capability this tool produces is now available downstream.
            have.update(tool.provides)

    visit(goal)
    return Plan(goal=goal, steps=tuple(plan))


manifest_registry = ManifestRegistry()

__all__ = [
    "ManifestRegistry",
    "MissingCapabilityError",
    "Plan",
    "ToolManifest",
    "manifest_registry",
    "resolve_chain",
]
