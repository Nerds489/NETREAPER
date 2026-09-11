# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Typed configuration for NETREAPER.

Layered load: packaged ``defaults.toml`` is the documented baseline, then the
user's ``~/.netreaper/config/config.toml`` overrides it key by key. The models
below are the single typed schema every consumer reads.
"""
from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from netreaper.core.logging import get_logger

logger = get_logger(__name__)

_DEFAULTS_PATH = Path(__file__).resolve().parent / "defaults.toml"
_USER_CONFIG_PATH = Path.home() / ".netreaper" / "config" / "config.toml"


class DatabaseConfig(BaseModel):
    path: str = "~/.netreaper/data/netreaper.db"
    wal_mode: bool = True
    busy_timeout: int = 5000


class LoggingConfig(BaseModel):
    level: int = 20
    file_logging: bool = True
    log_dir: str = "~/.netreaper/logs"
    max_file_size: int = 10_000_000
    backup_count: int = 5


class WirelessConfig(BaseModel):
    monitor_interface_prefix: str = "wmon"
    deauth_count: int = 10
    deauth_delay: float = 0.1
    channel_hop_interval: float = 0.5
    handshake_timeout: int = 300


class ScanningConfig(BaseModel):
    default_scan_type: str = "standard"
    default_ports: str = "1-1000"
    timing_template: int = 3
    max_concurrent_hosts: int = 10


class CredentialsConfig(BaseModel):
    default_wordlist: str = "/usr/share/wordlists/rockyou.txt"
    hashcat_workload: int = 3


class SafetyConfig(BaseModel):
    confirm_dangerous: bool = True
    warn_public_ip: bool = True
    require_authorization: bool = True
    dry_run: bool = False
    unsafe_mode: bool = False


class UIConfig(BaseModel):
    theme: str = "cyberpunk"
    show_banner: bool = True
    animation_speed: float = 1.0
    vim_bindings: bool = True


class Settings(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    wireless: WirelessConfig = Field(default_factory=WirelessConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    credentials: CredentialsConfig = Field(default_factory=CredentialsConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    output_dir: str = "~/.netreaper/output"
    non_interactive: bool = False
    debug: bool = False


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as e:
        logger.warning("ignoring unreadable/invalid config %s: %s", path, e)
        return {}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _build_settings() -> Settings:
    merged = _deep_merge(_load_toml(_DEFAULTS_PATH), _load_toml(_USER_CONFIG_PATH))
    return Settings(**merged)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return _build_settings()


def reload_settings() -> Settings:
    """Discard the cached settings and reload from disk."""
    get_settings.cache_clear()
    return get_settings()


__all__ = [
    "CredentialsConfig",
    "DatabaseConfig",
    "LoggingConfig",
    "SafetyConfig",
    "ScanningConfig",
    "Settings",
    "UIConfig",
    "WirelessConfig",
    "get_settings",
    "reload_settings",
]
