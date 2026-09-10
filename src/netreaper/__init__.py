"""NETREAPER - Offensive Security Framework with Modern TUI."""

__version__ = "2.0.0"
__author__ = "NETREAPER Team"
__license__ = "GPL-3.0-or-later"

from . import config, core, db, detection, safety

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "core",
    "config",
    "detection",
    "safety",
    "db",
]
