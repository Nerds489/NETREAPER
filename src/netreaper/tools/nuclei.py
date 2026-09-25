# SPDX-License-Identifier: GPL-3.0-or-later
"""nuclei template-based vulnerability scanner wrapper.

Like ffuf, nuclei was a catalogue row with no adapter and no planner path. This
ships the adapter and its manifest, providing `web.templated_findings` -- distinct
from nikto's `web.findings`, because the planner allows one provider per
capability and template-driven scanning is a different technique from nikto's
built-in checks.
"""
import json
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.logging import get_logger
from netreaper.plugins.base import Capability, PluginMetadata, PluginType
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)


class NucleiConfig(BaseModel):
    """nuclei-specific configuration."""

    severity: str = ""  # e.g. "critical,high"; empty means nuclei's default set
    rate_limit: int = 150


class NucleiTool(BaseToolWrapper):
    """nuclei vulnerability scanner wrapper."""

    TARGET_IS_URL = True

    TOOL_BINARY: ClassVar[str] = "nuclei"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="nuclei",
        version="1.0.0",
        description="Template-based vulnerability scanner",
        author="NETREAPER",
        plugin_type=PluginType.SCANNER,
        capabilities=[
            Capability.VULN_SCAN,
            Capability.WEB_SCAN,
        ],
        requires_root=False,
        external_tools=["nuclei"],
        config_schema=NucleiConfig,
    )

    def __init__(self, nuclei_config: NucleiConfig | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.nuclei_config = nuclei_config or NucleiConfig()

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build the nuclei command."""
        cmd = ["-u", target]
        severity = options.get("severity", self.nuclei_config.severity)
        if severity:
            cmd.extend(["-severity", severity])
        if options.get("templates"):
            cmd.extend(["-t", options["templates"]])
        rate = options.get("rate_limit", self.nuclei_config.rate_limit)
        cmd.extend(["-rate-limit", str(rate)])
        # JSONL results on stdout, no banner/colour so the output parses cleanly.
        cmd.extend(["-jsonl", "-silent", "-nc"])
        return cmd

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse nuclei JSONL output into findings."""
        findings: list[dict[str, Any]] = []
        by_severity: dict[str, int] = {}

        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            info = data.get("info") or {}
            severity = info.get("severity", "unknown")
            findings.append(
                {
                    "template_id": data.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": severity,
                    "matched_at": data.get("matched-at", data.get("host", "")),
                }
            )
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            "findings": findings,
            "summary": {"total_findings": len(findings), "by_severity": by_severity},
        }
