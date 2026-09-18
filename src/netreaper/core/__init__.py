"""Core functionality for NETREAPER framework."""
from .cleanup import CleanupRegistry, cleanup_registry, register_cleanup
from .constants import (
    CONCURRENCY_LIMITS,
    DB_PATH,
    TIMEOUTS,
    NETREAPER_CACHE_DIR,
    NETREAPER_CONFIG_DIR,
    NETREAPER_DATA_DIR,
    NETREAPER_HOME,
    NETREAPER_LOG_DIR,
    NETREAPER_OUTPUT_DIR,
    ExitCode,
    LogLevel,
)
from .exceptions import (
    ConfigurationError,
    NetworkError,
    NetreaperPermissionError,
    PluginError,
    SubprocessError,
    TargetValidationError,
    NetreaperTimeoutError,
    ToolNotFoundError,
    NetreaperError,
)
from .logging import NetreaperLogger, get_logger, setup_logging

__all__ = [
    # Constants
    "ExitCode",
    "LogLevel",
    "NETREAPER_HOME",
    "NETREAPER_CONFIG_DIR",
    "NETREAPER_DATA_DIR",
    "NETREAPER_LOG_DIR",
    "NETREAPER_OUTPUT_DIR",
    "NETREAPER_CACHE_DIR",
    "DB_PATH",
    "CONCURRENCY_LIMITS",
    "TIMEOUTS",
    # Exceptions
    "NetreaperError",
    "ConfigurationError",
    "ToolNotFoundError",
    "NetreaperPermissionError",
    "TargetValidationError",
    "NetworkError",
    "NetreaperTimeoutError",
    "PluginError",
    "SubprocessError",
    # Logging
    "NetreaperLogger",
    "setup_logging",
    "get_logger",
    # Cleanup
    "CleanupRegistry",
    "cleanup_registry",
    "register_cleanup",
]
