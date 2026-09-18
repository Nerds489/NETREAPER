"""Base class for external tool wrappers."""
import asyncio
import os
import shutil
import signal
import time
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from netreaper.core.exceptions import (
    SubprocessError,
    TargetValidationError,
    ToolNotFoundError,
)
from netreaper.core.logging import get_logger
from netreaper.core.process import get_process_runner
from netreaper.orchestration.events import Events, event_bus
from netreaper.plugins.base import PluginMetadata, PluginResult, ToolPlugin
from netreaper.safety.scope import Tier

logger = get_logger(__name__)


@dataclass
class ToolExecution:
    """Represents a tool execution context."""

    tool_name: str
    command: list[str]
    target: str
    output_file: Path | None = None
    started_at: float | None = None
    ended_at: float | None = None
    exit_code: int | None = None
    cancelled: bool = False


class BaseToolWrapper(ToolPlugin):
    """Base wrapper for external security tools."""

    # Subclasses must define
    TOOL_BINARY: ClassVar[str]  # e.g., "nmap"
    METADATA: ClassVar[PluginMetadata]
    # Blast-radius tier for the scope gate; wireless/DoS adapters raise this.
    DEFAULT_TIER: ClassVar[Tier] = Tier.ACTIVE_SCAN
    DESTRUCTIVE: ClassVar[bool] = False
    # Web adapters whose target is a URL: scope-check the URL's host, not the URL.
    TARGET_IS_URL: ClassVar[bool] = False

    def target_identifiers(self, target: str, options: dict[str, Any]) -> list[str]:
        """Scope-relevant targets for this invocation. Override when the real
        target is not the first positional arg (e.g. wireless: the BSSID/client,
        not the local interface name)."""
        if not target:
            return []
        if self.TARGET_IS_URL:
            from urllib.parse import urlsplit
            host = urlsplit(target if "://" in target else f"//{target}").hostname
            return [host] if host else [target]
        return [target]

    def execution_tier(self, target: str, options: dict[str, Any]) -> Tier:
        """Blast-radius tier for this invocation (override for per-call tiers)."""
        return self.DEFAULT_TIER

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._tool_path: Path | None = None
        self._current_process: asyncio.subprocess.Process | None = None
        self._execution: ToolExecution | None = None

    @property
    def tool_name(self) -> str:
        return self.TOOL_BINARY

    async def initialize(self) -> None:
        """Verify tool is available."""
        self._tool_path = shutil.which(self.TOOL_BINARY)
        if self._tool_path is None:
            raise ToolNotFoundError(
                f"Tool not found: {self.TOOL_BINARY}",
                context={"tool": self.TOOL_BINARY},
            )
        self._tool_path = Path(self._tool_path)
        self._initialized = True
        logger.debug('Tool initialized: %s at %s', self.TOOL_BINARY, self._tool_path)

    @abstractmethod
    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build command line arguments for the tool."""
        ...

    @abstractmethod
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse tool output into structured data."""
        ...

    async def execute(self, target: str, options: dict[str, Any]) -> PluginResult:
        """Execute the tool through the gated ProcessRunner and return results.

        Every spawn passes the scope gate first (deny-by-default). Security
        denials propagate; other failures are returned as a failed result.
        """
        if not self._initialized:
            await self.initialize()

        command = self.build_command(target, options)
        full_command = [self.TOOL_BINARY, *command]

        self._execution = ToolExecution(
            tool_name=self.TOOL_BINARY,
            command=full_command,
            target=target,
        )
        event_bus.emit(
            Events.TOOL_STARTED,
            {"tool": self.TOOL_BINARY, "target": target, "command": " ".join(full_command)},
        )
        self._execution.started_at = time.time()

        try:
            result = await get_process_runner().run(
                full_command,
                targets=self.target_identifiers(target, options),
                tier=self.execution_tier(target, options),
                destructive=self.DESTRUCTIVE,
                timeout=options.get("timeout", self.config.timeout),
                dry_run=options.get("dry_run", False),
            )
        except TargetValidationError:
            # never swallow a scope-gate denial
            raise
        except (SubprocessError, ToolNotFoundError) as e:
            logger.error("Tool execution failed: %s", e)
            return PluginResult(success=False, data={}, errors=[str(e)])

        self._execution.ended_at = time.time()
        self._execution.exit_code = result.returncode
        output = result.stdout + (result.stderr or "")

        if output:
            event_bus.emit(
                Events.TOOL_OUTPUT,
                {"tool": self.TOOL_BINARY, "line": output, "level": self._classify_line(output)},
            )
        parsed = self.parse_output(output)
        event_bus.emit(
            Events.TOOL_COMPLETED,
            {
                "tool": self.TOOL_BINARY,
                "target": target,
                "exit_code": self._execution.exit_code,
                "duration": self._execution.ended_at - self._execution.started_at,
            },
        )
        return PluginResult(success=result.returncode == 0, data=parsed)

    @staticmethod
    def _classify_line(line: str) -> str:
        """Classify output line for display styling."""
        line_lower = line.lower()

        if any(w in line_lower for w in ["error", "fail", "critical"]):
            return "error"
        if any(w in line_lower for w in ["warn", "caution"]):
            return "warning"
        if any(w in line_lower for w in ["success", "found", "open", "vuln"]):
            return "success"
        return "info"

    async def cancel(self) -> None:
        """Cancel the running tool."""
        if self._current_process is not None:
            try:
                # Kill process group
                pgid = os.getpgid(self._current_process.pid)
                os.killpg(pgid, signal.SIGTERM)

                # Give it time to terminate gracefully
                await asyncio.sleep(2)

                # Force kill if still running
                if self._current_process.returncode is None:
                    os.killpg(pgid, signal.SIGKILL)

            except (ProcessLookupError, PermissionError):
                pass

            self._current_process = None

    async def cleanup(self) -> None:
        """Clean up resources."""
        await self.cancel()
