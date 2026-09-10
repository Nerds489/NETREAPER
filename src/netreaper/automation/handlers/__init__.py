"""AUTO-* handlers for the automation framework."""

from netreaper.automation.handlers.install import AutoInstallHandler
from netreaper.automation.handlers.privilege import AutoPrivHandler
from netreaper.automation.handlers.monitor import AutoMonHandler
from netreaper.automation.handlers.iface import AutoIfaceHandler
from netreaper.automation.handlers.acquire import AutoAcquireHandler
from netreaper.automation.handlers.data import AutoDataHandler
from netreaper.automation.handlers.keys import AutoKeysHandler
from netreaper.automation.handlers.setup import AutoSetupHandler
from netreaper.automation.handlers.fallback import AutoFallbackHandler
from netreaper.automation.handlers.guide import AutoGuideHandler
from netreaper.automation.handlers.cleanup import AutoCleanupHandler
from netreaper.automation.handlers.validate import AutoValidateHandler
from netreaper.automation.handlers.update import AutoUpdateHandler

__all__ = [
    "AutoInstallHandler",
    "AutoPrivHandler",
    "AutoMonHandler",
    "AutoIfaceHandler",
    "AutoAcquireHandler",
    "AutoDataHandler",
    "AutoKeysHandler",
    "AutoSetupHandler",
    "AutoFallbackHandler",
    "AutoGuideHandler",
    "AutoCleanupHandler",
    "AutoValidateHandler",
    "AutoUpdateHandler",
]
