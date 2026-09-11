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
import os
import shutil
import signal
import time
from dataclasses import dataclass

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

        # THE GATE — before anything is spawned. Raises TargetValidationError
        # if the action is not authorised for these targets at this tier.
        # host_action marks a local host op (no network target); it is still
        # gated and audited here so nothing spawns outside this seam.
        self._gate.authorize(
            targets,
            tier=tier,
            destructive=destructive,
            requires_confirmation=requires_confirmation,
            host_action=host_action,
        )

        if dry_run:
            return ProcessResult(cmd=list(cmd), returncode=0, dry_run=True)

        binary = shutil.which(cmd[0])
        if binary is None:
            raise ToolNotFoundError(f"{cmd[0]!r} is not installed or not on PATH")

        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            binary, *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group so we can kill the whole tree
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            self._terminate(proc)
            raise SubprocessError(
                f"{cmd[0]} timed out after {timeout}s", returncode=None
            ) from None
        except BaseException:
            # Cancelled (an outer task aborting this run) or any other failure:
            # kill the spawned process group so a denied or aborted attack tool
            # cannot keep running detached (it has its own session).
            self._terminate(proc)
            raise
        duration = time.monotonic() - started
        result = ProcessResult(
            cmd=list(cmd),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=(out or b"").decode(errors="replace"),
            stderr=(err or b"").decode(errors="replace"),
            duration=duration,
        )
        if check and not result.ok:
            raise SubprocessError(
                f"{cmd[0]} exited {result.returncode}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result

    def run_sync(self, cmd: list[str], **kwargs) -> ProcessResult:
        """Blocking convenience wrapper around :meth:`run`."""
        return asyncio.run(self.run(cmd, **kwargs))

    @staticmethod
    def _terminate(proc: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass


_RUNNER = ProcessRunner()


def get_process_runner() -> ProcessRunner:
    """Return the process-wide runner singleton."""
    return _RUNNER


__all__ = ["ProcessResult", "ProcessRunner", "get_process_runner"]
