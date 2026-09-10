# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Registry of named chain definitions."""
from __future__ import annotations

from netreaper.chaining.models import ChainDefinition
from netreaper.core.exceptions import ConfigurationError


class ChainRegistry:
    """Holds :class:`ChainDefinition` objects keyed by id."""

    def __init__(self) -> None:
        self._chains: dict[str, ChainDefinition] = {}

    def register(self, chain: ChainDefinition, *, replace: bool = False) -> None:
        if chain.id in self._chains and not replace:
            raise ConfigurationError(f"chain id {chain.id!r} is already registered")
        self._chains[chain.id] = chain

    def get(self, chain_id: str) -> ChainDefinition:
        try:
            return self._chains[chain_id]
        except KeyError:
            raise ConfigurationError(f"no chain registered with id {chain_id!r}") from None

    def has(self, chain_id: str) -> bool:
        return chain_id in self._chains

    def list_ids(self) -> list[str]:
        return sorted(self._chains)

    def all(self) -> list[ChainDefinition]:
        return list(self._chains.values())

    def clear(self) -> None:
        self._chains.clear()


chain_registry = ChainRegistry()

__all__ = ["ChainRegistry", "chain_registry"]
