"""Core constants for NETREAPER framework."""
from enum import IntEnum
from pathlib import Path


class ExitCode(IntEnum):
    """Standard exit codes matching original Bash implementation."""

    SUCCESS = 0
    FAILURE = 1
    INVALID_ARGS = 2
    PERMISSION_DENIED = 3
    NETWORK_ERROR = 4
    TARGET_INVALID = 5
    TOOL_MISSING = 6
    CONFIG_ERROR = 7
    TIMEOUT = 8
    INTERRUPTED = 130


class LogLevel(IntEnum):
    """Logging levels."""

    DEBUG = 10
    INFO = 20
    SUCCESS = 25  # Custom level between INFO and WARNING
    WARNING = 30
    ERROR = 40
    FATAL = 50


# XDG-compliant paths
NETREAPER_HOME = Path.home() / ".netreaper"
NETREAPER_CONFIG_DIR = NETREAPER_HOME / "config"
NETREAPER_DATA_DIR = NETREAPER_HOME / "data"
NETREAPER_LOG_DIR = NETREAPER_HOME / "logs"
NETREAPER_OUTPUT_DIR = NETREAPER_HOME / "output"
NETREAPER_CACHE_DIR = NETREAPER_HOME / "cache"

# Export/reporting paths
NETREAPER_CAPTURES_DIR = NETREAPER_OUTPUT_DIR / "captures"
NETREAPER_WIFI_CAPTURES_DIR = NETREAPER_CAPTURES_DIR / "wifi"
NETREAPER_WIRED_CAPTURES_DIR = NETREAPER_CAPTURES_DIR / "wired"
NETREAPER_SCANS_DIR = NETREAPER_OUTPUT_DIR / "scans"
NETREAPER_REPORTS_DIR = NETREAPER_OUTPUT_DIR / "reports"
NETREAPER_LOOT_DIR = NETREAPER_OUTPUT_DIR / "loot"
NETREAPER_EXPORTS_DIR = NETREAPER_OUTPUT_DIR / "exports"

# Asset paths
NETREAPER_WORDLISTS_DIR = NETREAPER_DATA_DIR / "wordlists"
NETREAPER_PORTALS_DIR = NETREAPER_DATA_DIR / "portals"
NETREAPER_CERTS_DIR = NETREAPER_DATA_DIR / "certs"
NETREAPER_TEMPLATES_DIR = NETREAPER_DATA_DIR / "templates"
NETREAPER_SESSIONS_DIR = NETREAPER_DATA_DIR / "sessions"
NETREAPER_TEMP_DIR = NETREAPER_CACHE_DIR / "temp"

# Database
DB_PATH = NETREAPER_DATA_DIR / "netreaper.db"

# Concurrency limits by tool category
CONCURRENCY_LIMITS = {
    "network_scanner": 10,
    "web_scanner": 25,
    "password_cracker": 1,  # GPU exclusivity
    "traffic_capture": 5,
    "default": 10,
}

# Subprocess timeouts (seconds)
TIMEOUTS = {
    "quick_scan": 300,
    "full_scan": 3600,
    "password_crack": 86400,
    "default": 600,
}
