# SPDX-License-Identifier: GPL-3.0-or-later
"""Two registries describe the same tools, and they had drifted apart (D6, #31).

`detection/tools.py` answers "does this tool exist, how is it installed".
`automation/tool_requirements.py` answers "what does this tool need at run
time": root, a target, an interface. Those are different questions and both
registries earn their place, but they overlap on one column, root, and a value
declared twice is a value that can disagree with itself.

Measured before this file existed, across the 34 tools the preflight knows:

  30 agreed on root
   2 disagreed            nmap and wireshark
   2 had no catalogue row  subfinder and enum4linux-ng

The two missing rows are the more serious half. `subfinder` ships a working
adapter and a preflight entry, so it could be spawned, and with no catalogue
row it could never be installed or reported by `netreaper status`. An earlier
pass on #31 recorded that exact defect as fixed. It was not: only the adapter
side had been done. This file is the guard that would have caught that claim.

`wireshark` declared no root in the catalogue while `tshark` and `tcpdump`
beside it declared root, and the preflight declared root for all three. One row
disagreeing with its own siblings is a typo, not a policy, and it is now True.

`nmap` is different and stays disagreeing on purpose. See the test below.
"""
from __future__ import annotations

import pytest

from netreaper.automation.tool_requirements import TOOL_REQUIREMENTS
from netreaper.detection.tools import ToolRegistry

# Root is a property of the INVOCATION for these, not of the binary, so a single
# boolean cannot be right for both sides. Each entry must carry the reason.
#
# nmap: NETREAPER builds four scan types. `standard` (-T3 -sV) runs fine
# unprivileged; `stealth` (-sS), `udp` (-sU) and `full` (-A, which implies -O)
# all need root. The preflight REFUSES on needs_root rather than warning, so
# True blocks a standard scan that would have worked and False lets the other
# three reach nmap and fail there. Neither answer is right, which is the
# finding. Fixing it properly means a per-invocation requirement, the same
# shape as the manifest tier that was forwarded per-step rather than declared
# once. Until then the disagreement is pinned here so it stays visible.
PER_INVOCATION_ROOT: dict[str, str] = {
    "nmap": "3 of 4 scan types need root; `standard` does not. Needs a "
            "per-invocation requirement, not a per-tool boolean.",
}


def test_every_tool_the_preflight_knows_can_also_be_installed():
    """The subfinder defect: spawnable, and invisible to install and status."""
    missing = sorted(t for t in TOOL_REQUIREMENTS if t not in ToolRegistry.TOOL_DEFINITIONS)
    assert not missing, (
        "the preflight requires tools the catalogue cannot install or report:\n  "
        + "\n  ".join(missing)
    )


@pytest.mark.parametrize("tool", sorted(TOOL_REQUIREMENTS))
def test_the_two_registries_agree_on_root(tool):
    req = TOOL_REQUIREMENTS[tool]
    entry = ToolRegistry.TOOL_DEFINITIONS[tool]
    if tool in PER_INVOCATION_ROOT:
        pytest.skip(f"{tool}: {PER_INVOCATION_ROOT[tool]}")
    assert bool(req.needs_root) == bool(entry.requires_root), (
        f"{tool}: preflight needs_root={req.needs_root} but catalogue "
        f"requires_root={entry.requires_root}. The preflight value is the one "
        f"that gates, and it refuses rather than warns."
    )


def test_the_known_exceptions_do_not_grow_quietly():
    """A new disagreement must be argued for, not added to the skip list.

    Without this, the parametrised test above can be silenced one tool at a
    time until it asserts nothing.
    """
    actual = {
        tool
        for tool, req in TOOL_REQUIREMENTS.items()
        if bool(req.needs_root)
        != bool(ToolRegistry.TOOL_DEFINITIONS[tool].requires_root)
    }
    assert actual == set(PER_INVOCATION_ROOT), (
        f"root disagreements changed.\n"
        f"  documented: {sorted(PER_INVOCATION_ROOT)}\n"
        f"  actual:     {sorted(actual)}\n"
        f"Either fix the value or document why the tool is per-invocation."
    )


def test_the_capture_tools_agree_with_each_other():
    """wireshark declared no root while tshark and tcpdump beside it did."""
    for tool in ("wireshark", "tshark", "tcpdump"):
        assert ToolRegistry.TOOL_DEFINITIONS[tool].requires_root is True, (
            f"{tool} captures packets; its siblings all declare root"
        )
