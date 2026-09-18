"""Event bus for tool coordination and UI updates."""
from collections.abc import Callable, Coroutine
from enum import Enum
from typing import Any

from pyee.asyncio import AsyncIOEventEmitter

from netreaper.core.logging import get_logger

logger = get_logger(__name__)


class Events(str, Enum):
    """Standard event types."""

    # Tool lifecycle
    TOOL_STARTED = "tool.started"
    TOOL_OUTPUT = "tool.output"
    TOOL_PROGRESS = "tool.progress"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    STOP_ALL_TOOLS = "tool.stop_all"

    # Task management
    TASK_STARTED = "task.started"
    TASK_PROGRESS = "task.progress"
    TASK_COMPLETED = "task.completed"

    # Discovery
    HOST_DISCOVERED = "discovery.host"
    SERVICE_DISCOVERED = "discovery.service"
    VULNERABILITY_FOUND = "discovery.vulnerability"

    # Wireless
    NETWORK_FOUND = "wireless.network"
    CLIENT_FOUND = "wireless.client"
    DEAUTH_SENT = "wireless.deauth_sent"
    WPS_PIN_FOUND = "wireless.wps_pin"
    HANDSHAKE_CAPTURED = "wireless.handshake"
    PMKID_CAPTURED = "wireless.pmkid"
    CREDENTIAL_CRACKED = "wireless.cracked"

    # Session
    SESSION_STARTED = "session.started"
    SESSION_UPDATED = "session.updated"
    SESSION_ENDED = "session.ended"

    # Chain execution
    CHAIN_STARTED = "chain.started"
    CHAIN_STEP_STARTED = "chain.step.started"
    CHAIN_STEP_COMPLETED = "chain.step.completed"
    CHAIN_STEP_FAILED = "chain.step.failed"
    CHAIN_STEP_SKIPPED = "chain.step.skipped"
    CHAIN_COMPLETED = "chain.completed"
    CHAIN_FAILED = "chain.failed"
    CHAIN_CANCELLED = "chain.cancelled"

    # UI
    STATUS_UPDATE = "ui.status"
    NOTIFICATION = "ui.notification"


EventHandler = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


# Event payload keys whose value is a command line or raw tool output.
_COMMAND_KEYS = ("command", "cmd", "argv", "full_command")
_OUTPUT_KEYS = ("line", "output", "stdout", "stderr")


def _redact_event(data: object) -> object:
    """Mask credentials in an event payload before it is logged or stored.

    Mirrors the audit sink: the emitter cannot be trusted to remember, so the
    boundary does it. Uses the same per-tool rules, so nmap's port list survives
    while hydra's password does not.
    """
    from netreaper.core.audit import redact_argv, redact_output, redact_text

    if not isinstance(data, dict):
        return data
    tool = str(data.get("tool", ""))
    out = dict(data)
    for key in _COMMAND_KEYS:
        val = out.get(key)
        if isinstance(val, str):
            out[key] = redact_text(val, tool)
        elif isinstance(val, (list, tuple)):
            out[key] = redact_argv([str(x) for x in val])
    for key in _OUTPUT_KEYS:
        val = out.get(key)
        if isinstance(val, str):
            # Output needs BOTH: a quoted command line (flag-shaped) and the
            # tool's own "password: x" success line (not flag-shaped at all).
            out[key] = redact_output(redact_text(val, tool))
    return out


class NetreaperEventBus(AsyncIOEventEmitter):
    """Event bus with typed events and logging."""

    def __init__(self) -> None:
        super().__init__()
        self._event_history: list[tuple[str, dict]] = []
        self._max_history = 1000

    def emit(self, event: Events | str, *args: Any, **kwargs: Any) -> None:
        """Emit an event (sync wrapper for pyee compatibility)."""
        event_name = event.value if isinstance(event, Events) else event

        # Handle pyee internal events (new_listener, etc.) which pass multiple args
        if args and not isinstance(args[0], dict):
            super().emit(event_name, *args, **kwargs)
            return

        # Handle our typed events with data dict
        data = args[0] if args else kwargs.get("data", {})
        if data is None:
            data = {}

        # Log event (skip internal pyee events)
        if not event_name.startswith("new_"):
            # Redact at THIS sink too. TOOL_STARTED carries the raw joined argv
            # and TOOL_OUTPUT carries raw stdout, which for hydra/reaver includes
            # lines like "password: <cracked>". core/logging.py pins the file
            # handler to DEBUG regardless of console level, so one --debug run
            # wrote every credential to a plaintext file in the same directory
            # as the audit trail, with none of the audit's protections.
            safe = _redact_event(data)
            logger.debug("Event: %s - %s", event_name, safe)

            # Store the redacted copy: the history feeds the UI and any dump of it.
            self._event_history.append((event_name, safe))
            if len(self._event_history) > self._max_history:
                self._event_history.pop(0)

        # Emit to listeners
        super().emit(event_name, data)

    async def emit_async(self, event: Events | str, data: dict[str, Any] | None = None) -> None:
        """Emit an event asynchronously."""
        self.emit(event, data or {})

    def on(self, event: Events | str, handler: EventHandler) -> None:
        """Register an event handler."""
        event_name = event.value if isinstance(event, Events) else event
        super().on(event_name, handler)

    def off(self, event: Events | str, handler: EventHandler) -> None:
        """Remove an event handler."""
        event_name = event.value if isinstance(event, Events) else event
        super().remove_listener(event_name, handler)

    def get_history(
        self, event: Events | str | None = None, limit: int = 100
    ) -> list[tuple[str, dict]]:
        """Get event history, optionally filtered by event type."""
        history = self._event_history[-limit:]

        if event is not None:
            event_name = event.value if isinstance(event, Events) else event
            history = [(e, d) for e, d in history if e == event_name]

        return history


# Singleton event bus
event_bus = NetreaperEventBus()
