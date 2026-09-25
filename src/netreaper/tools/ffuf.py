# SPDX-License-Identifier: GPL-3.0-or-later
"""ffuf web fuzzer wrapper.

ffuf was in the tool catalogue with no adapter and, until #91, no manifest chain
to run it: an adapter with no consumer is dead code (#84 deleted the builtin chain
registry, leaving the planner as the only consumer). This ships the adapter AND
its manifest reach path, providing `web.fuzz` -- distinct from gobuster's
`web.paths`, because the planner allows one provider per capability and the two
tools do genuinely different things (ffuf fuzzes an arbitrary FUZZ keyword,
gobuster brute-forces a path wordlist).
"""
import json
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.logging import get_logger
from netreaper.plugins.base import Capability, PluginMetadata, PluginType
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)


class FfufConfig(BaseModel):
    """ffuf-specific configuration."""

    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    threads: int = 40
    match_codes: str = "200,204,301,302,307,401,403,405"


class FfufTool(BaseToolWrapper):
    """ffuf web fuzzer wrapper."""

    TARGET_IS_URL = True

    TOOL_BINARY: ClassVar[str] = "ffuf"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="ffuf",
        version="1.0.0",
        description="Fast web fuzzer",
        author="NETREAPER",
        plugin_type=PluginType.SCANNER,
        capabilities=[
            Capability.WEB_FUZZ,
            Capability.DIR_ENUM,
            Capability.WEB_SCAN,
        ],
        requires_root=False,
        external_tools=["ffuf"],
        config_schema=FfufConfig,
    )

    def __init__(self, ffuf_config: FfufConfig | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.ffuf_config = ffuf_config or FfufConfig()

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build the ffuf command.

        ffuf fuzzes wherever the ``FUZZ`` keyword appears in the URL; if the
        target carries none, it is appended as a path so a bare URL still does
        directory fuzzing.
        """
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        wordlist = options.get("wordlist", self.ffuf_config.wordlist)
        threads = options.get("threads", self.ffuf_config.threads)
        match_codes = options.get("match_codes", self.ffuf_config.match_codes)

        cmd = ["-u", url, "-w", wordlist, "-t", str(threads), "-mc", match_codes]
        if options.get("extensions"):
            cmd.extend(["-e", options["extensions"]])
        if options.get("recursion"):
            cmd.append("-recursion")
        # Machine-readable results on stdout, no interactive banner or progress.
        cmd.extend(["-json", "-s"])
        return cmd

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse ffuf output into matched hits.

        ffuf ``-json`` emits either one object per hit or a final object with a
        ``results`` array depending on version, so both shapes are handled.
        """
        hits: list[dict[str, Any]] = []

        def _add(entry: dict[str, Any]) -> None:
            hits.append(
                {
                    "input": (entry.get("input") or {}).get("FUZZ", entry.get("input")),
                    "url": entry.get("url", ""),
                    "status": entry.get("status", 0),
                    "length": entry.get("length", 0),
                }
            )

        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and "results" in data:
                for entry in data["results"]:
                    _add(entry)
            elif isinstance(data, dict):
                _add(data)

        return {"hits": hits, "summary": {"total_hits": len(hits)}}
