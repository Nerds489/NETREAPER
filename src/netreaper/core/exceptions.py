# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Exception hierarchy for NETREAPER.

All framework errors derive from :class:`NetreaperError` so callers can catch
the whole family with one handler while still distinguishing specific failures.
"""
from __future__ import annotations


class NetreaperError(Exception):
    """Base class for every NETREAPER error."""

    def __init__(self, message: str = "", *, context: object | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context


class ConfigurationError(NetreaperError):
    """Invalid, missing, or unreadable configuration."""


class TargetValidationError(NetreaperError):
    """A target failed validation or falls outside the authorised scope."""


class ToolNotFoundError(NetreaperError):
    """A required external tool is not installed or not on PATH."""


class SubprocessError(NetreaperError):
    """An external tool exited non-zero or could not be executed."""

    def __init__(self, message: str = "", *, returncode: int | None = None,
                 stderr: str = "", context: object | None = None) -> None:
        super().__init__(message, context=context)
        self.returncode = returncode
        self.stderr = stderr


class TimeoutError(NetreaperError):
    """An operation exceeded its time budget."""


class NetworkError(NetreaperError):
    """A network operation failed."""


class PermissionError(NetreaperError):
    """The operation requires privileges the process does not hold."""


class PluginError(NetreaperError):
    """A plugin failed to load, validate, or execute."""


__all__ = [
    "ConfigurationError",
    "NetreaperError",
    "NetworkError",
    "PermissionError",
    "PluginError",
    "SubprocessError",
    "TargetValidationError",
    "TimeoutError",
    "ToolNotFoundError",
]
