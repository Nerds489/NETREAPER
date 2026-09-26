"""Preflight runner helper for TUI screens."""

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, TYPE_CHECKING

from netreaper.automation.tool_requirements import get_fallback_tool, get_tool_requirements
from netreaper.core.logging import get_logger

# netreaper.automation.preflight and netreaper.automation.engine do not exist.
# They are dangling references left by the v11 Bash-to-Python rebuild: this
# module imported both at module level, so importing it raised
# ModuleNotFoundError, and that took three TUI screens (credentials, exploit,
# traffic) down with it. Four modules in the package could not be imported at
# all, which means they could not be tested, linted for real, or reached.
#
# Resolving them properly means designing PreflightChecker and PreflightResult,
# and the right time for that is the TUI rebuild (#31) when there is a UI to
# design them against. Inventing an interface now would be guessing.
#
# So the import moves to the point of use. The module imports cleanly, the
# screens import cleanly, and constructing a PreflightRunner raises a specific
# error naming exactly what is missing. An honest failure at the call site beats
# an import-time crash four modules wide.
_PREFLIGHT_MISSING = (
    "netreaper.automation.preflight.PreflightChecker and "
    "netreaper.automation.engine.PreflightResult do not exist. They are "
    "dangling references from the v11 rebuild and are part of the TUI rebuild "
    "(#31). PreflightRunner cannot be used until they are written."
)


_MODAL_MISSING = (
    "netreaper.tui.modals.preflight_modal does not exist: the modals package "
    "holds only __init__.py. It is part of the TUI rebuild (#31)."
)


def _load_modal(name: str):
    """Import one preflight modal, at the point it is actually needed.

    These imports used to sit at the TOP of six functions, ABOVE the fast paths
    that need no modal at all, so every one of them raised ModuleNotFoundError
    on every call regardless of arguments:

        ensure_interface     raised even with zero or one interface
        ensure_monitor_mode  raised even when already in monitor mode
        ensure_wordlist      raised even when rockyou.txt was already on disk
        ensure_api_key       raised even when the key was already saved
        ensure_root          raised whenever the process was not already root
        prepare_tool         raised before it had even built its ToolContext

    prepare_tool is the entry point for every tool run in the traffic, exploit
    and credentials screens, so all three screens' actions were dead. ensure_tool
    in this same file has always had it right: its import sits after the
    shutil.which check, which is why that one works.
    """
    from netreaper.tui.modals import preflight_modal

    return getattr(preflight_modal, name)


def _load_preflight_checker():
    """Import PreflightChecker on demand, or say precisely why it cannot."""
    try:
        from netreaper.automation.preflight import PreflightChecker
    except ModuleNotFoundError as e:
        raise NotImplementedError(_PREFLIGHT_MISSING) from e
    return PreflightChecker

if TYPE_CHECKING:
    from textual.app import App

logger = get_logger(__name__)


@dataclass
class ToolContext:
    """Context with all resolved values needed to run a tool."""

    tool: str
    ready: bool = False

    # Resolved values
    interface: str | None = None
    target: str | None = None
    wordlist: str | None = None
    # repr=False: core/logging.py configures RichHandler with
    # tracebacks_show_locals=True, and a plain dataclass prints every field in
    # any traceback that shows the frame. That would put the raw key on the
    # console. setup_logging() has no caller today so the path is inert, but the
    # leak should not be waiting for somebody to close that gap.
    api_key: str | None = field(default=None, repr=False)

    # What was resolved
    used_fallback: bool = False
    fallback_tool: str | None = None

    # Error info
    error: str | None = None


class PreflightRunner:
    """Helper class for running preflight checks with TUI integration."""

    def __init__(self, app: "App", session: Any = None) -> None:
        self.app = app
        self.session = session
        self._checker: Any = None

    @property
    def checker(self) -> Any:
        """Built on first use, not in __init__.

        The previous version built it in the constructor, and the constructor is
        called from on_mount() in credentials.py, traffic.py and exploit.py. So
        moving the dangling import to "the point of use" moved the crash from
        import time to screen-open time, which for three of the five screens is
        the same thing from the operator's chair: the app died on opening them.
        The real point of use is running a check, which is here.
        """
        if self._checker is None:
            self._checker = _load_preflight_checker()(self.session)
        return self._checker

    async def run_with_preflight(
        self,
        action: str,
        callback: Callable[[], Coroutine[Any, Any, Any]],
        auto_fix: bool = True,
    ) -> bool:
        """Run preflight checks and execute callback if passed.

        Args:
            action: The action name to check requirements for
            callback: Async function to call if preflight passes
            auto_fix: Whether to automatically try fixing issues

        Returns:
            True if action was executed, False if cancelled or failed
        """
        # Preflight checks REQUIREMENTS (is the tool installed, is an
        # interface up), not authorisation. The scope gate at the spawn seam is
        # the safety control and runs regardless, and tools/base.py still
        # refuses a binary that is not on PATH with a clear message. So when the
        # checker is missing, the honest behaviour is to say so plainly and let
        # the action proceed to those checks, rather than making the whole
        # screen unusable over a convenience feature that was never written.
        try:
            checker = self.checker
        except NotImplementedError:
            logger.warning("preflight unavailable; running %s unchecked", action)
            self.app.notify(
                f"Requirement pre-checks are unavailable, so {action} will run "
                f"without them. Authorisation and tool checks still apply.",
                title="Preflight not available",
                severity="warning",
                timeout=6,
            )
            await callback()
            return True

        result = await checker.check(action)

        if result.all_met:
            # All good, run the action
            await callback()
            return True

        # netreaper.tui.modals.preflight_modal does not exist either: the
        # modals package contains only __init__.py. Same dangling-reference
        # family as PreflightChecker, and the same treatment.
        try:
            from netreaper.tui.modals.preflight_modal import PreflightModal
        except ImportError:
            logger.warning("preflight modal missing; reporting unmet requirements")
            unmet = getattr(result, "unmet", None) or "requirements not met"
            self.app.notify(
                f"{action} cannot run: {unmet}",
                title="Requirements not met",
                severity="error",
                timeout=8,
            )
            return False

        proceed = await self.app.push_screen_wait(
            PreflightModal(result, self.session)
        )

        if proceed:
            # Re-check after fixes
            result = await self.checker.check(action)
            if result.all_met or result.can_proceed:
                await callback()
                return True

        return False

    async def ensure_interface(self, interface_type: str = "wireless") -> str | None:
        """Ensure an interface is selected, prompting if needed.

        Args:
            interface_type: Type of interface needed (wireless, monitor, all)

        Returns:
            Selected interface name or None if cancelled
        """
        from netreaper.automation.handlers.iface import AutoIfaceHandler

        handler = AutoIfaceHandler(required_type=interface_type)
        interfaces = await handler.get_interfaces(interface_type)

        if not interfaces:
            self.app.notify(
                f"No {interface_type} interfaces found. Please connect an adapter.",
                severity="error"
            )
            return None

        if len(interfaces) == 1:
            # Auto-select single interface
            return interfaces[0].name

        # Multiple interfaces - prompt user
        interface_data = [
            {
                "name": iface.name,
                "type": iface.type,
                "mac": iface.mac,
                "driver": iface.driver,
            }
            for iface in interfaces
        ]

        try:
            InterfaceSelectModal = _load_modal("InterfaceSelectModal")
        except ImportError:
            self.app.notify(
                f"{len(interfaces)} interfaces found and there is no picker yet "
                f"({_MODAL_MISSING}) Name one explicitly.",
                severity="warning",
            )
            return None

        selected = await self.app.push_screen_wait(
            InterfaceSelectModal(
                interface_data,
                title=f"Select {interface_type.title()} Interface"
            )
        )

        return selected

    async def ensure_monitor_mode(self, interface: str | None = None) -> str | None:
        """Ensure monitor mode is enabled on an interface.

        Args:
            interface: Specific interface to use, or None to auto-detect

        Returns:
            Monitor interface name or None if failed
        """
        from netreaper.automation.handlers.iface import AutoIfaceHandler
        from netreaper.automation.handlers.monitor import AutoMonHandler

        # Get interface if not specified
        if not interface:
            interface = await self.ensure_interface("wireless")
            if not interface:
                return None

        # Check if already in monitor mode. This used to call
        # AutoMonHandler._is_monitor_mode, which does not exist on that class:
        # the method lives on AutoIfaceHandler, so this raised AttributeError
        # every time the path ran. Never noticed because preflight_runner sits
        # at 10% coverage and ensure_interface() had no test.
        if await AutoIfaceHandler().is_monitor_mode(interface):
            return interface

        handler = AutoMonHandler(interface)

        try:
            ConfirmModal = _load_modal("ConfirmModal")
        except ImportError:
            self.app.notify(
                f"Cannot ask about enabling monitor mode: {_MODAL_MISSING} "
                f"Put {interface} into monitor mode yourself and pass it in.",
                severity="warning",
            )
            return None

        confirm = await self.app.push_screen_wait(
            ConfirmModal(
                "Enable Monitor Mode",
                f"Enable monitor mode on {interface}?\n\n"
                "This will disconnect from WiFi networks."
            )
        )

        if not confirm:
            return None

        # Enable monitor mode
        self.app.notify(f"Enabling monitor mode on {interface}...", severity="information")

        success = await handler.fix()
        if success:
            self.app.notify(
                f"Monitor mode enabled: {handler.monitor_interface}",
                severity="information"
            )
            return handler.monitor_interface
        else:
            self.app.notify("Failed to enable monitor mode", severity="error")
            return None

    async def ensure_root(self) -> bool:
        """Ensure running as root, showing message if not.

        Returns:
            True if running as root
        """
        import os

        if os.geteuid() == 0:
            return True

        # netreaper.automation.handlers.privilege does not exist either. Same
        # dangling-reference family; say so rather than raising at the operator.
        try:
            from netreaper.automation.handlers.privilege import AutoPrivHandler

            ConfirmModal = _load_modal("ConfirmModal")
        except ImportError:
            self.app.notify(
                "This needs root and there is no privilege helper yet "
                f"({_MODAL_MISSING}) Re-run NETREAPER with sudo.",
                severity="error",
            )
            return False

        handler = AutoPrivHandler()
        relaunch_cmd = handler.get_relaunch_command()

        await self.app.push_screen_wait(
            ConfirmModal(
                "Root Required",
                f"This action requires root privileges.\n\n"
                f"Please restart with:\n{relaunch_cmd}"
            )
        )

        return False

    async def ensure_target(self, target_type: str = "ip") -> str | None:
        """Ensure a target is specified, prompting if needed.

        Args:
            target_type: Type of target (ip, host, url, bssid)

        Returns:
            Target value or None if cancelled
        """
        from netreaper.automation.handlers.validate import AutoValidateHandler

        try:
            InputModal = _load_modal("InputModal")
        except ImportError:
            self.app.notify(
                f"Cannot prompt for a target: {_MODAL_MISSING} Pass one "
                f"explicitly instead.",
                severity="error",
            )
            return None

        placeholders = {
            "ip": "192.168.1.1",
            "host": "example.com",
            "url": "https://example.com",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "cidr": "192.168.1.0/24",
        }

        target = await self.app.push_screen_wait(
            InputModal(
                f"Enter Target ({target_type.upper()})",
                placeholder=placeholders.get(target_type, "")
            )
        )

        if not target:
            return None

        # Validate
        is_valid, error = AutoValidateHandler.validate_input(target_type, target)
        if not is_valid:
            self.app.notify(f"Invalid {target_type}: {error}", severity="error")
            return None

        return target

    async def ensure_tool(self, tool_name: str) -> bool:
        """Ensure a tool is installed, offering to install if missing.

        Args:
            tool_name: Name of the tool binary

        Returns:
            True if tool is available
        """
        import shutil

        if shutil.which(tool_name):
            return True

        # netreaper.automation.handlers.install does not exist either.
        try:
            from netreaper.automation.handlers.install import AutoInstallHandler

            ConfirmModal = _load_modal("ConfirmModal")
        except ImportError:
            self.app.notify(
                f"{tool_name} is not installed and there is no installer yet "
                f"({_MODAL_MISSING}) Install it with your package manager.",
                severity="error",
            )
            return False

        handler = AutoInstallHandler(tool_name)

        if not await handler.can_fix():
            self.app.notify(
                f"Cannot install {tool_name}: no package manager found",
                severity="error"
            )
            return False

        confirm = await self.app.push_screen_wait(
            ConfirmModal(
                "Install Tool",
                await handler.get_ui_prompt()
            )
        )

        if not confirm:
            return False

        self.app.notify(f"Installing {tool_name}...", severity="information")
        success = await handler.fix()

        if success:
            self.app.notify(f"{tool_name} installed successfully", severity="information")
        else:
            self.app.notify(f"Failed to install {tool_name}", severity="error")

        return success

    async def ensure_api_key(self, service: str) -> str | None:
        """Ensure an API key is configured, prompting if needed.

        Args:
            service: Service name (shodan, censys, etc.)

        Returns:
            API key or None if not configured
        """
        from netreaper.automation.handlers.keys import AutoKeysHandler

        handler = AutoKeysHandler(service)

        # Check if already configured
        existing = handler.get_key()
        if existing:
            return existing

        # Prompt for key
        url = handler.get_registration_url()
        title = f"Enter {service.title()} API Key"
        if url:
            title += f"\n(Get one at: {url})"

        try:
            InputModal = _load_modal("InputModal")
        except ImportError:
            self.app.notify(
                f"No {service} API key stored and no prompt available "
                f"({_MODAL_MISSING})",
                severity="error",
            )
            return None

        key = await self.app.push_screen_wait(
            InputModal(title, placeholder="API Key", password=True)
        )

        if key:
            handler.save_key(key)
            self.app.notify(f"{service.title()} API key saved", severity="information")
            return key

        return None

    async def ensure_wordlist(self) -> str | None:
        """Ensure a wordlist is available, downloading if needed.

        Returns:
            Path to wordlist or None
        """
        from pathlib import Path
        from netreaper.automation.handlers.data import AutoDataHandler

        # Check standard locations
        standard_paths = [
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/seclists/Passwords/rockyou.txt"),
            Path.home() / ".netreaper/wordlists/rockyou.txt",
        ]

        for path in standard_paths:
            if path.exists():
                return str(path)

        # Offer to download
        handler = AutoDataHandler("rockyou")

        if not await handler.can_fix():
            self.app.notify("Cannot download wordlist: curl/wget not found", severity="error")
            return None

        try:
            ConfirmModal = _load_modal("ConfirmModal")
        except ImportError:
            self.app.notify(
                f"No wordlist on disk and no download prompt available "
                f"({_MODAL_MISSING}) Pass --wordlist explicitly.",
                severity="error",
            )
            return None

        confirm = await self.app.push_screen_wait(
            ConfirmModal(
                "Download Wordlist",
                "No wordlist found. Download rockyou.txt (14MB)?"
            )
        )

        if not confirm:
            return None

        self.app.notify("Downloading rockyou.txt...", severity="information")
        success = await handler.fix()

        if success and handler.dest_path:
            self.app.notify("Wordlist downloaded", severity="information")
            return str(handler.dest_path)

        self.app.notify("Failed to download wordlist", severity="error")
        return None

    async def prepare_tool(
        self,
        tool_name: str,
        target: str | None = None,
        interface: str | None = None,
    ) -> ToolContext:
        """Prepare all requirements for a tool, prompting as needed.

        This is the main entry point for tool preparation. It:
        1. Checks if tool exists (offers to install or use fallback)
        2. Checks root requirement
        3. Gets/prompts for target if needed
        4. Gets/prompts for interface if needed
        5. Gets/prompts for wordlist if needed
        6. Gets/prompts for API key if needed

        Args:
            tool_name: Name of the tool to prepare
            target: Pre-provided target (optional)
            interface: Pre-provided interface (optional)

        Returns:
            ToolContext with all resolved values and ready=True if all requirements met
        """
        ctx = ToolContext(tool=tool_name)
        req = get_tool_requirements(tool_name)

        if not req:
            return await self._prepare_unrecognised_tool(ctx, tool_name)

        if not await self._resolve_binary(ctx, tool_name):
            return ctx

        # Each step returns the reason it could not be satisfied, or None. The
        # `or` chain short-circuits on the first refusal, which is the same
        # early-return sequence as before, minus seven copies of it.
        error = (
            await self._resolve_root(req)
            or await self._resolve_target(ctx, req, target)
            or await self._resolve_interface(ctx, req, interface)
            or await self._resolve_wordlist(ctx, req)
            or await self._resolve_api_key(ctx, req)
        )
        if error:
            ctx.error = error
            return ctx

        await self._warn_if_no_gpu(req, ctx.tool)
        ctx.ready = True
        return ctx

    # ── the steps ────────────────────────────────────────────────────────────

    async def _prepare_unrecognised_tool(
        self, ctx: ToolContext, tool_name: str
    ) -> ToolContext:
        """A tool with no requirements entry: it only has to exist."""
        import shutil

        if not shutil.which(tool_name) and not await self.ensure_tool(tool_name):
            ctx.error = f"Tool {tool_name} not found and could not be installed"
            return ctx
        ctx.ready = True
        return ctx

    async def _resolve_binary(self, ctx: ToolContext, tool_name: str) -> bool:
        """Find the tool, offer its fallback, or install it. False means stop.

        Sets ctx.tool to whatever will actually be run, and ctx.error when it
        gives up. A fallback is never substituted silently: without a way to
        ask, this says what is missing and lets the operator decide.
        """
        import shutil

        ctx.tool = tool_name
        if shutil.which(tool_name):
            return True

        fallback = get_fallback_tool(tool_name)
        try:
            ConfirmModal = _load_modal("ConfirmModal")
        except ImportError:
            ctx.error = f"{tool_name} is not installed" + (
                f" (a fallback to {fallback} exists but cannot be "
                f"confirmed: {_MODAL_MISSING})"
                if fallback
                else ""
            )
            self.app.notify(ctx.error, severity="error")
            return False

        if fallback:
            confirm = await self.app.push_screen_wait(
                ConfirmModal(
                    "Tool Not Found",
                    f"'{tool_name}' not found.\n\nUse '{fallback}' instead?",
                )
            )
            if confirm:
                ctx.tool = fallback
                ctx.used_fallback = True
                ctx.fallback_tool = fallback
                return True

        if not await self.ensure_tool(tool_name):
            ctx.error = f"Tool {tool_name} not available"
            return False
        return True

    async def _resolve_root(self, req) -> str | None:
        if req.needs_root and not await self.ensure_root():
            return "Root privileges required"
        return None

    async def _resolve_target(
        self, ctx: ToolContext, req, target: str | None
    ) -> str | None:
        if not req.needs_target:
            return None
        if target:
            ctx.target = target
            return None
        resolved = await self.ensure_target(req.target_type)
        if not resolved:
            return f"Target ({req.target_type}) required"
        ctx.target = resolved
        return None

    async def _resolve_interface(
        self, ctx: ToolContext, req, interface: str | None
    ) -> str | None:
        if not req.needs_interface:
            return None
        if interface:
            ctx.interface = interface
            return None
        if req.interface_type == "monitor":
            resolved = await self.ensure_monitor_mode()
            if not resolved:
                return "Monitor mode interface required"
        else:
            resolved = await self.ensure_interface(req.interface_type or "all")
            if not resolved:
                return f"Interface ({req.interface_type}) required"
        ctx.interface = resolved
        return None

    async def _resolve_wordlist(self, ctx: ToolContext, req) -> str | None:
        if not req.needs_wordlist:
            return None
        wordlist = await self.ensure_wordlist()
        if not wordlist:
            return "Wordlist required"
        ctx.wordlist = wordlist
        return None

    async def _resolve_api_key(self, ctx: ToolContext, req) -> str | None:
        if not req.needs_api_key:
            return None
        api_key = await self.ensure_api_key(req.needs_api_key)
        if not api_key:
            return f"API key for {req.needs_api_key} required"
        ctx.api_key = api_key
        return None

    async def _warn_if_no_gpu(self, req, tool: str) -> None:
        """A warning, never a refusal: hashcat on CPU is slow, not broken."""
        if not req.needs_gpu:
            return
        import subprocess

        try:
            result = subprocess.run(
                [tool, "-I"],
                check=False,  # -I failing means no GPU, not a broken call
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "No devices found" in result.stdout or result.returncode != 0:
                self.app.notify(
                    "No GPU found - performance may be slower", severity="warning"
                )
        except Exception:
            pass

    async def quick_check(self, tool_name: str) -> bool:
        """Quick check if a tool is available (install if not).

        Simpler than prepare_tool - just checks the tool exists.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is available
        """
        import shutil

        if shutil.which(tool_name):
            return True

        # Check for fallback
        fallback = get_fallback_tool(tool_name)
        if fallback and shutil.which(fallback):
            self.app.notify(
                f"Using {fallback} instead of {tool_name}",
                severity="information"
            )
            return True

        # Try to install
        return await self.ensure_tool(tool_name)
