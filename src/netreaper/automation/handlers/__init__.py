# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""AUTO-* handlers for the automation framework.

Only the handlers that currently exist are exported. The install/privilege/
acquire/fallback/guide handlers were removed from the tree; their behaviour is
being folded into the ProcessRunner + ScopeGate spine and dedicated handlers
will be reintroduced if still needed.
"""
from netreaper.automation.handlers.cleanup import AutoCleanupHandler
from netreaper.automation.handlers.data import AutoDataHandler
from netreaper.automation.handlers.iface import AutoIfaceHandler
from netreaper.automation.handlers.keys import AutoKeysHandler
from netreaper.automation.handlers.monitor import AutoMonHandler
from netreaper.automation.handlers.setup import AutoSetupHandler
from netreaper.automation.handlers.update import AutoUpdateHandler
from netreaper.automation.handlers.validate import AutoValidateHandler

__all__ = [
    "AutoCleanupHandler",
    "AutoDataHandler",
    "AutoIfaceHandler",
    "AutoKeysHandler",
    "AutoMonHandler",
    "AutoSetupHandler",
    "AutoUpdateHandler",
    "AutoValidateHandler",
]
