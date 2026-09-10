# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Registry for AUTO-* automation handlers.

Handlers self-register at import via ``AUTO_REGISTRY.register("AUTO-X", Cls)``.
"""
from __future__ import annotations

from collections.abc import Iterator


class AutoHandlerRegistry:
    """Maps an AUTO-* label to its handler class."""

    def __init__(self) -> None:
        self._handlers: dict[str, type] = {}

    def register(self, label: str, handler_cls: type, *, replace: bool = True) -> type:
        if label in self._handlers and not replace:
            raise ValueError(f"handler {label!r} already registered")
        self._handlers[label] = handler_cls
        return handler_cls

    def get(self, label: str) -> type | None:
        return self._handlers.get(label)

    def labels(self) -> list[str]:
        return sorted(self._handlers)

    def all(self) -> dict[str, type]:
        return dict(self._handlers)

    def __iter__(self) -> Iterator[str]:
        return iter(self._handlers)

    def __len__(self) -> int:
        return len(self._handlers)


AUTO_REGISTRY = AutoHandlerRegistry()

__all__ = ["AUTO_REGISTRY", "AutoHandlerRegistry"]
