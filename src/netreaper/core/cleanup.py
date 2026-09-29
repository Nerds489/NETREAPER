"""Resource cleanup registry for graceful shutdown."""
import asyncio
import signal
import sys
from collections.abc import Callable, Coroutine
from typing import Any

from .logging import get_logger

logger = get_logger(__name__)

CleanupFunc = Callable[[], None] | Callable[[], Coroutine[Any, Any, None]]


class CleanupRegistry:
    """Registry for cleanup functions to run on shutdown."""

    _instance: "CleanupRegistry | None" = None

    _handlers: list[tuple[int, CleanupFunc]]
    _installed: bool

    def __new__(cls) -> "CleanupRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    _shutdown_task: "asyncio.Task[None] | None"

    def __init__(self) -> None:
        # State set here rather than reaching into cls._instance from __new__,
        # which is what DeepSource flagged. Guarded, because __init__ runs on
        # every CleanupRegistry() call while __new__ returns the same object.
        if not hasattr(self, "_handlers"):
            self._handlers = []
            self._installed = False
            # Hold a reference to the scheduled cleanup task so it is not
            # garbage-collected mid-flight (asyncio keeps only a weak ref).
            self._shutdown_task = None

    def register(self, handler: CleanupFunc, priority: int = 50) -> None:
        """Register a cleanup handler with priority (lower = earlier)."""
        self._handlers.append((priority, handler))
        self._handlers.sort(key=lambda x: x[0])

        if not self._installed:
            self._install_signal_handlers()

    def unregister(self, handler: CleanupFunc) -> None:
        """Remove a cleanup handler."""
        self._handlers = [(p, h) for p, h in self._handlers if h != handler]

    def _install_signal_handlers(self) -> None:
        """Install signal handlers for graceful shutdown.

        When registration happens inside a running event loop (the TUI case),
        use ``loop.add_signal_handler`` so cleanup is scheduled *onto* that loop.
        The previous ``signal.signal`` + ``run_until_complete`` combination
        raised ``RuntimeError: This event loop is already running`` the instant a
        signal arrived during a live session, so cleanup never ran and the
        interface was left in monitor mode with iptables rules in place.
        """
        installed_async = False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            try:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, self._on_signal_async, sig)
                installed_async = True
            except (NotImplementedError, RuntimeError):
                # add_signal_handler is unavailable on this platform/thread;
                # fall back to the synchronous handler below.
                installed_async = False
        if not installed_async:
            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, self._signal_handler)
        self._installed = True

    def _on_signal_async(self, signum: int) -> None:
        """Loop-installed handler: schedule cleanup on the running loop."""
        logger.info("Received signal %s, initiating cleanup...", signum)
        self._shutdown_task = asyncio.ensure_future(self._cleanup_then_exit(signum))

    def _schedule_cleanup(self, signum: int) -> None:
        """Schedule cleanup onto the running loop, keeping a task reference."""
        self._shutdown_task = asyncio.ensure_future(self._cleanup_then_exit(signum))

    async def _cleanup_then_exit(self, signum: int) -> None:
        await self.cleanup()
        sys.exit(128 + signum)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Synchronous handler, used only when no loop was running at install.

        Never calls ``run_until_complete`` on an already-running loop. If a loop
        turns out to be running when the signal fires, cleanup is scheduled onto
        it; otherwise a fresh loop runs cleanup to completion.
        """
        logger.info("Received signal %s, initiating cleanup...", signum)
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            running.call_soon_threadsafe(self._schedule_cleanup, signum)
            return
        asyncio.run(self.cleanup())
        sys.exit(128 + signum)

    async def cleanup(self) -> None:
        """Execute all registered cleanup handlers."""
        logger.info("Running %s cleanup handlers...", len(self._handlers))

        for _priority, handler in self._handlers:
            try:
                result = handler()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error("Cleanup handler failed: %s", e)

        self._handlers.clear()
        logger.info("Cleanup complete")


# Singleton instance
cleanup_registry = CleanupRegistry()


def register_cleanup(handler: CleanupFunc, priority: int = 50) -> None:
    """Convenience function to register cleanup handler."""
    cleanup_registry.register(handler, priority)
