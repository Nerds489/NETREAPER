# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""The single process-spawn seam.

Every external tool NETREAPER runs goes through :meth:`ProcessRunner.run`, and
the scope gate is consulted *before* the subprocess is created. This is the one
chokepoint: no tier, attack phase, chain step, or one-line helper can spawn a
process without first passing authorisation, so the gate cannot be bypassed.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
import time
from dataclasses import dataclass
from typing import Any

from netreaper.core.audit import get_audit_trail
from netreaper.core.exceptions import SubprocessError, ToolNotFoundError
from netreaper.safety.scope import ScopeGate, Tier, get_scope_gate


@dataclass
class ProcessResult:
    cmd: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ProcessRunner:
    """Runs external commands behind the scope gate."""

    def __init__(self, gate: ScopeGate | None = None) -> None:
        self._gate = gate or get_scope_gate()
        self._grace = 5.0  # seconds to wait after SIGTERM before escalating to SIGKILL

    async def run(
        self,
        cmd: list[str],
        *,
        targets: list[str] | tuple[str, ...] = (),
        tier: Tier = Tier.PASSIVE,
        destructive: bool = False,
        requires_confirmation: bool = False,
        timeout: float | None = None,
        dry_run: bool = False,
        check: bool = False,
        host_action: bool = False,
    ) -> ProcessResult:
        if not cmd:
            raise ValueError("cmd must be a non-empty argument list")

        # Audit context for this spawn: operator + the engagement's consent
        # fingerprint, so every entry ties back to the authorisation it ran under.
        eng = self._gate.engagement
        operator = eng.operator if eng is not None else "-"
        consent = eng.consent_hash if eng is not None else "-"
        audit = get_audit_trail()

        def _audit(outcome: str, detail: str = "") -> None:
            audit.record(
                outcome=outcome, operator=operator, consent=consent,
                tool=cmd[0], argv=list(cmd), targets=list(targets),
                tier=tier.name, destructive=destructive,
                host_action=host_action, detail=detail,
            )

        # THE GATE — before anything is spawned. Raises TargetValidationError
        # if the action is not authorised for these targets at this tier.
        # host_action marks a local host op (no network target); it is still
        # gated and audited here so nothing spawns outside this seam. Every
        # decision — denied, dry-run, executed or spawn-error — lands in the
        # hash-chained audit trail from this one place.
        try:
            self._gate.authorize(
                targets,
                tier=tier,
                destructive=destructive,
                requires_confirmation=requires_confirmation,
                host_action=host_action,
            )
        except Exception as exc:
            _audit("denied", str(exc)[:200])
            raise

        if dry_run:
            _audit("dry-run")
            return ProcessResult(cmd=list(cmd), returncode=0, dry_run=True)

        binary = shutil.which(cmd[0])
        if binary is None:
            _audit("spawn-error", "tool not installed or not on PATH")
            raise ToolNotFoundError(f"{cmd[0]!r} is not installed or not on PATH")

        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, *cmd[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # own process group so we can kill the tree
            )
        except BaseException as exc:
            # The exec itself failed after the gate passed (fd exhaustion, ENOMEM,
            # the binary vanishing in the race after `which`, a cancel). Audit it
            # so no authorised action leaves the seam without a record.
            _audit("spawn-error", f"exec failed: {type(exc).__name__}")
            raise
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            await self._terminate_and_reap(proc)
            _audit("spawn-error", f"timed out after {timeout}s")
            raise SubprocessError(
                f"{cmd[0]} timed out after {timeout}s", returncode=None
            ) from None
        except BaseException:
            # Cancelled (an outer task aborting this run) or any other failure:
            # tear the spawned process group down (SIGTERM, then SIGKILL if it does
            # not exit) and reap it, so a denied or aborted attack tool cannot keep
            # running detached (it has its own session).
            await self._terminate_and_reap(proc)
            _audit("spawn-error", "cancelled or aborted")
            raise
        duration = time.monotonic() - started
        result = ProcessResult(
            cmd=list(cmd),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=(out or b"").decode(errors="replace"),
            stderr=(err or b"").decode(errors="replace"),
            duration=duration,
        )
        _audit("executed", f"rc={result.returncode}")
        if check and not result.ok:
            raise SubprocessError(
                f"{cmd[0]} exited {result.returncode}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result

    def run_sync(self, cmd: list[str], **kwargs: Any) -> ProcessResult:
        """Blocking convenience wrapper around :meth:`run`."""
        return asyncio.run(self.run(cmd, **kwargs))

    async def _terminate_and_reap(self, proc: asyncio.subprocess.Process) -> None:
        """Stop a spawned process group and reap it: bounded and escalating.

        SIGTERM the group, wait up to ``self._grace``, then SIGKILL if it has not
        exited, and reap it so asyncio closes the transport. Never blocks forever,
        even against a process that ignores SIGTERM.
        """
        if proc.returncode is not None:
            return
        waiter = asyncio.ensure_future(proc.wait())
        self._signal(proc, signal.SIGTERM)
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(asyncio.shield(waiter), timeout=self._grace)
        if proc.returncode is None:
            self._signal(proc, signal.SIGKILL)  # unignorable: guarantees exit
            with contextlib.suppress(BaseException):
                await waiter

    @staticmethod
    def _signal(proc: asyncio.subprocess.Process, sig: int) -> None:
        """Send a signal to the whole process group, falling back to the process."""
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except OSError:
            # Was (ProcessLookupError, PermissionError, OSError). Both of the
            # named ones are OSError subclasses, so the tuple caught exactly
            # what OSError catches while reading as though it were narrower.
            # The cases that actually reach here are the process already being
            # gone, and not owning its group.
            try:
                proc.send_signal(sig)
            except (ProcessLookupError, ValueError):
                # ValueError is NOT an OSError: asyncio raises it for a process
                # whose transport has already closed. That tuple stays.
                pass


_RUNNER = ProcessRunner()


def get_process_runner() -> ProcessRunner:
    """Return the process-wide runner singleton."""
    return _RUNNER


__all__ = ["ProcessResult", "ProcessRunner", "get_process_runner"]
