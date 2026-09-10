# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""NETREAPER - Offensive Security Framework.

Submodules are imported lazily (PEP 562): importing :mod:`netreaper` is cheap and
a broken or missing submodule never takes the whole package down with it.
"""
from __future__ import annotations

from pathlib import Path


def _read_version() -> str:
    # Single source of truth: the VERSION file at the repo/dist root.
    here = Path(__file__).resolve()
    for candidate in (here.parents[2] / "VERSION", here.parent / "VERSION"):
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    try:
        from importlib.metadata import version
        return version("netreaper")
    except Exception:
        return "0.0.0"


__version__ = _read_version()
__author__ = "Nerds489 / OFFTRACKMEDIA Studios"
__license__ = "GPL-3.0-or-later"

_LAZY = frozenset({
    "config", "core", "db", "detection", "safety", "orchestration",
    "plugins", "tools", "chaining", "sessions", "loot", "wireless",
    "automation", "export", "utils",
})


def __getattr__(name: str):
    if name in _LAZY:
        import importlib
        module = importlib.import_module(f".{name}", __name__)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return [*globals().keys(), *_LAZY]


__all__ = ["__version__", "__author__", "__license__", *sorted(_LAZY)]
