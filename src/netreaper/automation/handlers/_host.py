# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Run local host/maintenance commands through the one gated seam.

Automation handlers used to call ``asyncio.create_subprocess_shell`` directly,
which bypassed the scope gate, the timeout, the process-group teardown and any
audit, and interpolated interface names into shell strings. They now route every
spawn through :func:`run_host`, which calls the gated :class:`ProcessRunner` with
``host_action=True`` and exec argument arrays.
"""
from __future__ import annotations

from netreaper.core.exceptions import SubprocessError, ToolNotFoundError
from netreaper.core.process import ProcessResult, get_process_runner


async def run_host(
    cmd: list[str],
    *,
    timeout: float = 30.0,
    destructive: bool = False,
) -> ProcessResult | None:
    """Run a local host command through the gated runner.

    Returns the :class:`ProcessResult`, or ``None`` if the tool is missing or the
    spawn timed out, so best-effort restore paths do not crash. A scope refusal
    (:class:`TargetValidationError`, e.g. an invalid interface name) is never
    swallowed: it propagates to the caller.
    """
    try:
        return await get_process_runner().run(
            cmd, host_action=True, destructive=destructive, timeout=timeout
        )
    except (SubprocessError, ToolNotFoundError):
        return None
