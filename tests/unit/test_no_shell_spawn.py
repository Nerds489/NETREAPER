# SPDX-License-Identifier: GPL-3.0-or-later
"""Guard: no shell-based process spawning anywhere in the package.

M-1 (outside-perspective review): the automation handlers called
create_subprocess_shell with interpolated interface names, which bypassed the
ProcessRunner scope gate and opened a shell-injection vector. Every spawn now
goes through the gated ProcessRunner with exec argument arrays. This test keeps
shell spawns (and os.system/os.popen) out of the source tree for good.
"""
from __future__ import annotations

from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"
FORBIDDEN = ("create_subprocess_shell(", "os.system(", "os.popen(")


def test_no_shell_spawns_in_source():
    offenders = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN:
            if needle in text:
                offenders.append(f"{path.relative_to(SRC)}: {needle}")
    assert not offenders, (
        "shell spawn(s) found; route through ProcessRunner instead:\n"
        + "\n".join(offenders)
    )
