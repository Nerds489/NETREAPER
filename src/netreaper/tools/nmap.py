"""Nmap network scanner wrapper."""
import os
import re
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:  # the annotation below needs the name; nothing here parses with it
    from xml.etree.ElementTree import Element

from pydantic import BaseModel

from netreaper.plugins.base import Capability, PluginMetadata, PluginResult, PluginType
from netreaper.tools.base import BaseToolWrapper

_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)


def _parse_scan_xml(path: Path) -> "Element":
    """Parse an nmap XML result, refusing any document that declares a DTD.

    ElementTree does not resolve *external* entities, so this is not XXE file
    disclosure. It does expand internal ones, and this output is a file on disk
    that is written by one call and re-read by another, so a crafted or tampered
    result can expand to exhaust memory (billion laughs).

    Both defences, because they answer different questions. defusedxml refuses
    entity expansion whatever the document says, which is the guarantee; the
    DOCTYPE check refuses the document outright, which carries the extra meaning
    that nmap never emits one, so a result file with a DTD in it was not
    produced by the scan it claims to be. Checked on the bytes rather than
    through a parser handler, because XMLParser exposes its underlying expat
    parser under different names across Python versions and a handler that
    silently fails to attach is worse than no defence at all.

    ``xml.etree.ElementTree`` is not imported at runtime at all. The return
    annotation needs the ``Element`` name, so it is imported under
    TYPE_CHECKING: a checker sees it, the interpreter never loads the module,
    and there is no stdlib XML parser in this file to reach for by mistake.
    """
    from defusedxml.ElementTree import fromstring as _safe_fromstring

    raw = path.read_bytes()
    if _DOCTYPE_RE.search(raw):
        raise ValueError(
            f"{path} declares a DTD; nmap does not emit one, so this file was "
            f"not produced by the scan it claims to be"
        )
    return _safe_fromstring(raw)


class NmapConfig(BaseModel):
    """Nmap-specific configuration."""

    timing_template: int = 3  # -T0 to -T5
    default_ports: str = "1-1000"
    service_detection: bool = True
    os_detection: bool = False
    script_scan: bool = False
    scripts: list[str] = []
    output_format: str = "xml"  # xml, normal, greppable


@dataclass
class NmapHost:
    """Parsed Nmap host result."""

    ip: str
    hostname: str | None
    state: str
    ports: list[dict]
    os_matches: list[dict]
    scripts: list[dict]


class NmapTool(BaseToolWrapper):
    """Nmap network scanner wrapper."""

    TOOL_BINARY: ClassVar[str] = "nmap"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="nmap",
        version="1.0.0",
        description="Network exploration and security auditing tool",
        author="NETREAPER",
        plugin_type=PluginType.SCANNER,
        capabilities=[
            Capability.NETWORK_SCAN,
            Capability.PORT_SCAN,
            Capability.SERVICE_ENUM,
            Capability.VULN_SCAN,
        ],
        # Root is NOT a property of nmap; it is a property of the scan. The
        # default `standard` scan is a connect scan that runs unprivileged, so
        # the base flag is False and the per-invocation truth lives in
        # needs_root() below, enforced in execute(). A blanket True here forced
        # the two registries to disagree (see test_registry_reconciliation) and
        # would have blocked a standard scan that needs no privilege.
        requires_root=False,
        external_tools=["nmap"],
        config_schema=NmapConfig,
    )

    # Scan type presets
    SCAN_TYPES = {
        "quick": ["-T4", "-F"],
        "standard": ["-T3", "-sV"],
        "full": ["-T4", "-A", "-p-"],
        "stealth": ["-T2", "-sS", "-Pn"],
        "udp": ["-sU", "--top-ports", "100"],
        "vuln": ["--script", "vuln"],
    }

    # nmap needs raw sockets (root, or CAP_NET_RAW) for the half-open and
    # protocol scans and for OS detection; a plain connect scan (-sT, the
    # unprivileged default) and -sV do not. Derived from the flags build_command
    # actually emits, so "which scans need root" cannot drift from what runs.
    _ROOT_FLAGS: ClassVar[frozenset[str]] = frozenset({
        "-sS", "-sA", "-sF", "-sX", "-sN", "-sM",
        "-sW", "-sY", "-sU", "-sO", "-O", "-A",
    })

    def needs_root(self, options: dict[str, Any] | None = None) -> bool:
        """Whether THIS invocation needs root, keyed on the scan it will build.

        Root is per-invocation, not per-tool: `standard`/`quick`/`vuln` are
        connect scans that run unprivileged, while `stealth` (-sS), `udp` (-sU)
        and `full` (-A, which implies -O) need raw sockets, as does turning on
        OS detection on any scan. Resolved from the same options and config
        defaults `build_command` uses, so it stays true to what will run.
        """
        options = options or {}
        scan_type = options.get("scan_type", "standard")
        flags: set[str] = set(self.SCAN_TYPES.get(scan_type, []))
        if options.get("os_detection", self.nmap_config.os_detection):
            flags.add("-O")
        extra = options.get("extra_args") or []
        if isinstance(extra, str):
            extra = extra.split()
        flags.update(extra)
        return bool(flags & self._ROOT_FLAGS)

    def __init__(self, nmap_config: NmapConfig | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.nmap_config = nmap_config or NmapConfig()
        self._output_file: Path | None = None

    async def execute(self, target: str, options: dict[str, Any]) -> PluginResult:
        """Refuse a privileged scan up front when unprivileged, then run.

        A scan that needs raw sockets fails inside nmap with a terse "you
        requested a scan type which requires root privileges" if it is spawned
        without them. Catching it here names the scan type and the fix, and never
        reaches the process seam. A dry run is exempt: it spawns nothing, so
        previewing a stealth plan without root is fine.
        """
        if (
            not options.get("dry_run")
            and self.needs_root(options)
            and os.geteuid() != 0
        ):
            scan_type = options.get("scan_type", "standard")
            return PluginResult(
                success=False,
                data={},
                errors=[
                    f"nmap {scan_type} scan needs root (raw sockets); re-run with "
                    f"sudo, or use --type standard for an unprivileged scan"
                ],
            )
        return await super().execute(target, options)

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build nmap command."""
        cmd = []

        # Scan type preset
        scan_type = options.get("scan_type", "standard")
        if scan_type in self.SCAN_TYPES:
            cmd.extend(self.SCAN_TYPES[scan_type])

        # Timing template
        timing = options.get("timing", self.nmap_config.timing_template)
        if f"-T{timing}" not in cmd:
            cmd.append(f"-T{timing}")

        # Port specification
        ports = options.get("ports", self.nmap_config.default_ports)
        if ports and "-p" not in " ".join(cmd):
            cmd.extend(["-p", ports])

        # Service detection
        # The -A check matters: the "full" scan-type preset already sets it, so
        # adding -sV on top would be redundant. Collapsed, not reordered.
        if (
            options.get("service_detection", self.nmap_config.service_detection)
            and "-sV" not in cmd
            and "-A" not in cmd
        ):
            cmd.append("-sV")

        # OS detection (requires root)
        if (
            options.get("os_detection", self.nmap_config.os_detection)
            and "-O" not in cmd
            and "-A" not in cmd
        ):
            cmd.append("-O")

        # Script scanning
        scripts = options.get("scripts", self.nmap_config.scripts)
        if scripts:
            cmd.extend(["--script", ",".join(scripts)])

        # Skip host discovery (-Pn)
        if options.get("skip_discovery", False) and "-Pn" not in cmd:
            cmd.append("-Pn")

        # Extra arguments from UI

        # XML output for parsing
        self._output_file = Path(NamedTemporaryFile(suffix=".xml", delete=False).name)
        cmd.extend(["-oX", str(self._output_file)])

        # Target
        cmd.append(target)

        return cmd

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse nmap XML output."""
        if self._output_file is None or not self._output_file.exists():
            return self._parse_text_output(output)

        try:
            return self._parse_xml_output()
        except Exception:
            # Fallback to text parsing
            return self._parse_text_output(output)
        finally:
            # Cleanup temp file
            if self._output_file and self._output_file.exists():
                self._output_file.unlink()

    def _parse_xml_output(self) -> dict[str, Any]:
        """Parse nmap XML output file.

        Parsed through defusedxml, with a DTD declaration refused outright on
        top of that. See _parse_scan_xml for why both.
        """
        root = _parse_scan_xml(self._output_file)

        hosts = [
            host
            for host_elem in root.findall(".//host")
            if (host := self._host_from_xml(host_elem)) is not None
        ]

        scaninfo = root.find("scaninfo")
        run_stats = root.find("runstats/finished")

        return {
            "hosts": hosts,
            "scan_info": {
                "type": scaninfo.get("type") if scaninfo is not None else None,
                "protocol": scaninfo.get("protocol") if scaninfo is not None else None,
                "elapsed": run_stats.get("elapsed") if run_stats is not None else None,
            },
            "summary": {
                "total_hosts": len(hosts),
                "up_hosts": sum(1 for h in hosts if h["state"] == "up"),
                "total_ports": sum(len(h["ports"]) for h in hosts),
                "open_ports": sum(
                    sum(1 for p in h["ports"] if p["state"] == "open") for h in hosts
                ),
            },
        }

    @classmethod
    def _host_from_xml(cls, host_elem) -> dict[str, Any] | None:
        """One <host>, or None for a host with no IPv4 address.

        Skipping the address-less host is the pre-existing behaviour and is
        deliberate: everything downstream keys on "ip".
        """
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            return None

        hostname_elem = host_elem.find(".//hostname")
        status_elem = host_elem.find("status")

        return {
            "ip": addr_elem.get("addr", ""),
            "hostname": hostname_elem.get("name") if hostname_elem is not None else None,
            "state": (
                status_elem.get("state", "unknown")
                if status_elem is not None
                else "unknown"
            ),
            "ports": [cls._port_from_xml(e) for e in host_elem.findall(".//port")],
            "os_matches": [
                {"name": e.get("name"), "accuracy": int(e.get("accuracy", 0))}
                for e in host_elem.findall(".//osmatch")
            ],
            "scripts": [
                {"id": e.get("id"), "output": e.get("output")}
                for e in host_elem.findall(".//script")
            ],
        }

    @staticmethod
    def _port_from_xml(port_elem) -> dict[str, Any]:
        """One <port>.

        "product" is only present when a <service> element is, which is how it
        was before: the key is absent rather than None on a port nmap could not
        fingerprint, and callers distinguish the two.
        """
        port_info: dict[str, Any] = {
            "port": int(port_elem.get("portid", 0)),
            "protocol": port_elem.get("protocol", "tcp"),
            "state": "unknown",
            "service": "unknown",
            "version": None,
        }

        state_elem = port_elem.find("state")
        if state_elem is not None:
            port_info["state"] = state_elem.get("state", "unknown")

        service_elem = port_elem.find("service")
        if service_elem is not None:
            port_info["service"] = service_elem.get("name", "unknown")
            port_info["version"] = service_elem.get("version")
            port_info["product"] = service_elem.get("product")

        return port_info

    @staticmethod
    def _parse_text_output(output: str) -> dict[str, Any]:
        """Fallback text output parsing."""
        hosts = []
        current_host = None

        for line in output.splitlines():
            # Host discovery
            host_match = re.match(r"Nmap scan report for (\S+)", line)
            if host_match:
                if current_host:
                    hosts.append(current_host)
                current_host = {
                    "ip": host_match.group(1),
                    "ports": [],
                }
                continue

            # Port line
            port_match = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)", line)
            if port_match and current_host:
                current_host["ports"].append(
                    {
                        "port": int(port_match.group(1)),
                        "protocol": port_match.group(2),
                        "state": port_match.group(3),
                        "service": port_match.group(4),
                    }
                )

        if current_host:
            hosts.append(current_host)

        return {"hosts": hosts}

    async def quick_scan(self, target: str) -> dict[str, Any]:
        """Perform a quick scan."""
        result = await self.execute(target, {"scan_type": "quick"})
        return result.data

    async def full_scan(self, target: str) -> dict[str, Any]:
        """Perform a comprehensive scan."""
        result = await self.execute(target, {"scan_type": "full"})
        return result.data

    async def vuln_scan(self, target: str) -> dict[str, Any]:
        """Perform vulnerability scan."""
        result = await self.execute(target, {"scan_type": "vuln"})
        return result.data
