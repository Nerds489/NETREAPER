"""SQLMap SQL injection tool wrapper."""
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.logging import get_logger
from netreaper.plugins.base import Capability, PluginMetadata, PluginType
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)


class SqlmapConfig(BaseModel):
    """SQLMap-specific configuration."""

    level: int = 1  # 1-5, higher = more tests
    risk: int = 1  # 1-3, higher = more dangerous tests
    threads: int = 1
    timeout: int = 30
    retries: int = 3
    delay: float = 0
    tamper: list[str] = []  # Tamper scripts
    technique: str = "BEUSTQ"  # B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline
    batch: bool = True  # Non-interactive mode
    output_dir: str = ""


class SqlmapTool(BaseToolWrapper):
    """SQLMap SQL injection tool wrapper."""

    TARGET_IS_URL = True

    TOOL_BINARY: ClassVar[str] = "sqlmap"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="sqlmap",
        version="1.0.0",
        description="Automatic SQL injection and database takeover tool",
        author="NETREAPER",
        plugin_type=PluginType.SCANNER,
        capabilities=[
            Capability.SQL_INJECTION,
            Capability.EXPLOITATION,
            Capability.WEB_SCAN,
        ],
        requires_root=False,
        external_tools=["sqlmap"],
        config_schema=SqlmapConfig,
    )

    # SQL injection techniques
    TECHNIQUES = {
        "B": "Boolean-based blind",
        "E": "Error-based",
        "U": "Union query-based",
        "S": "Stacked queries",
        "T": "Time-based blind",
        "Q": "Inline queries",
    }

    # Database types
    DBMS_TYPES = [
        "mysql", "postgresql", "mssql", "oracle", "sqlite",
        "access", "firebird", "maxdb", "sybase", "db2",
        "hsqldb", "informix", "h2", "monetdb", "derby",
    ]

    def __init__(self, sqlmap_config: SqlmapConfig | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.sqlmap_config = sqlmap_config or SqlmapConfig()
        self._temp_dir: TemporaryDirectory | None = None
        self._output_dir: Path | None = None

    # Argument tables. Every entry is (option key, flag); the config object
    # supplies the default for the always-emitted ones. Table-driven because
    # the shape of thirty flags is data, not control flow, and it was 25 branches
    # of control flow.
    _TUNING: ClassVar[tuple[tuple[str, str], ...]] = (
        ("level", "--level"),
        ("risk", "--risk"),
        ("threads", "--threads"),
        ("timeout", "--timeout"),
        ("retries", "--retries"),
    )
    _REQUEST: ClassVar[tuple[tuple[str, str], ...]] = (
        ("param", "-p"),
        ("data", "--data"),
        ("cookie", "--cookie"),
    )
    _ENUM_BARE: ClassVar[tuple[tuple[str, str], ...]] = (
        ("dbs", "--dbs"),
        ("tables", "--tables"),
        ("columns", "--columns"),
        ("dump", "--dump"),
        ("dump_all", "--dump-all"),
    )
    _ENUM_VALUE: ClassVar[tuple[tuple[str, str], ...]] = (
        ("database", "-D"),
        ("table", "-T"),
        ("column", "-C"),
    )

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build sqlmap command."""
        cmd = ["-u", target]
        cmd += self._tuning_args(options)
        cmd += self._request_args(options)
        cmd += self._enumeration_args(options)

        if options.get("batch", self.sqlmap_config.batch):
            cmd.append("--batch")

        # Deliberately not inside a helper called `_args`: this allocates a
        # temporary directory whose lifetime is the tool instance, and
        # parse_output reads it back. A side effect that outlives the call
        # belongs where it can be seen.
        self._temp_dir = TemporaryDirectory()
        self._output_dir = Path(self._temp_dir.name)
        cmd += ["--output-dir", str(self._output_dir)]

        cmd += self._session_args(options)
        return cmd

    def _tuning_args(self, options: dict[str, Any]) -> list[str]:
        """Detection depth, concurrency and the technique filter."""
        cfg = self.sqlmap_config
        args: list[str] = []
        for key, flag in self._TUNING:
            args += [flag, str(options.get(key, getattr(cfg, key)))]

        delay = options.get("delay", cfg.delay)
        if delay > 0:
            args += ["--delay", str(delay)]

        args += ["--technique", options.get("technique", cfg.technique)]

        tamper = options.get("tamper", cfg.tamper)
        if tamper:
            args += ["--tamper", ",".join(tamper)]
        return args

    def _request_args(self, options: dict[str, Any]) -> list[str]:
        """What to send: parameter under test, body, cookie, headers, DBMS hint."""
        args: list[str] = []
        for key, flag in self._REQUEST:
            value = options.get(key)
            if value:
                args += [flag, value]

        for header in options.get("headers") or ():
            args += ["-H", header]

        dbms = options.get("dbms")
        if dbms:
            args += ["--dbms", dbms]
        return args

    def _enumeration_args(self, options: dict[str, Any]) -> list[str]:
        """What to pull out once an injection point is confirmed."""
        args = [flag for key, flag in self._ENUM_BARE if options.get(key)]
        for key, flag in self._ENUM_VALUE:
            if options.get(key):
                args += [flag, options[key]]

        if options.get("os_shell"):
            args.append("--os-shell")
        os_cmd = options.get("os_cmd")
        if os_cmd:
            args += ["--os-cmd", os_cmd]
        return args

    def _session_args(self, options: dict[str, Any]) -> list[str]:
        """Session handling and crawl behaviour, emitted after --output-dir."""
        args: list[str] = []
        if options.get("flush_session"):
            args.append("--flush-session")
        if options.get("forms"):
            args.append("--forms")

        crawl = options.get("crawl")
        if crawl:
            args += ["--crawl", str(crawl)]

        if options.get("random_agent"):
            args.append("--random-agent")

        proxy = options.get("proxy")
        if proxy:
            args += ["--proxy", proxy]
        return args

    # ── output ───────────────────────────────────────────────────────────────

    _INJECTION_RE: ClassVar = re.compile(r"Parameter:\s+(\S+)\s+\(([^)]+)\)")
    _TABLE_CELL_RE: ClassVar = re.compile(r"\|\s+(\S+)\s+\|")
    # (result key, pattern). Each is searched independently, so the fact that
    # the "operating system" pattern also matches inside the web-server line is
    # the pre-existing behaviour and is preserved.
    _SINGLE_FIELDS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("dbms", r"back-end DBMS:\s+(.+)"),
        ("os", r"operating system:\s+(.+)"),
        ("web_server", r"web server operating system:\s+(.+)"),
    )
    _SUCCESS_INDICATORS: ClassVar[tuple[str, ...]] = (
        "injectable",
        "vulnerability",
        "exploitable",
        "confirmed",
    )

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse sqlmap output."""
        injection_points = self._parse_injection_points(output)
        lowered = output.lower()
        results: dict[str, Any] = {
            "vulnerable": bool(injection_points)
            or any(i in lowered for i in self._SUCCESS_INDICATORS),
            "injection_points": injection_points,
            "databases": self._parse_databases(output),
            "tables": self._parse_tables(output),
            "columns": [],
            "data": self._collect_dumped_csv(lowered),
            "dbms": None,
            "os": None,
            "web_server": None,
        }

        for key, pattern in self._SINGLE_FIELDS:
            match = re.search(pattern, output)
            if match:
                results[key] = match.group(1).strip()

        results["summary"] = {
            "vulnerable": results["vulnerable"],
            "injection_points": len(results["injection_points"]),
            "databases_found": len(results["databases"]),
            "tables_found": len(results["tables"]),
        }
        return results

    def _parse_injection_points(self, output: str) -> list[dict[str, str]]:
        return [
            {"parameter": m.group(1), "type": m.group(2)}
            for m in self._INJECTION_RE.finditer(output)
        ]

    @staticmethod
    def _parse_databases(output: str) -> list[str]:
        section = re.search(r"available databases.*?:\s*\n((?:\[\*\].+\n)+)", output)
        if not section:
            return []
        found = []
        for line in section.group(1).splitlines():
            match = re.search(r"\[\*\]\s+(.+)", line)
            if match:
                found.append(match.group(1).strip())
        return found

    def _parse_tables(self, output: str) -> list[str]:
        """Scan the banner-delimited table listing.

        Order-dependent and left that way: the section opens on the first line
        containing "Table" that is not an entries count, and closes on the first
        blank line after it. Changing which test runs first changes the result.
        """
        tables: list[str] = []
        in_section = False
        for line in output.splitlines():
            if "Table" in line and "entries" not in line.lower():
                in_section = True
            elif in_section:
                match = self._TABLE_CELL_RE.search(line)
                if match and match.group(1) not in ["+", "-"]:
                    tables.append(match.group(1))
                elif line.strip() == "":
                    in_section = False
        return tables

    def _collect_dumped_csv(self, lowered_output: str) -> list[dict[str, str]]:
        if not (
            ("dumped to" in lowered_output or "entries" in lowered_output)
            and self._output_dir
            and self._output_dir.exists()
        ):
            return []
        data = []
        for csv_file in self._output_dir.rglob("*.csv"):
            try:
                with open(csv_file) as f:
                    data.append({"file": csv_file.name, "content": f.read()[:5000]})
            except OSError as e:
                logger.warning(
                    'Could not read sqlmap output file %s: %s', csv_file.name, e
                )
        return data

    async def cleanup(self) -> None:
        """Clean up resources."""
        await super().cleanup()
        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

    async def test_injection(self, url: str) -> dict[str, Any]:
        """Test URL for SQL injection."""
        result = await self.execute(url, {"batch": True})
        return result.data

    async def enumerate_databases(self, url: str) -> dict[str, Any]:
        """Enumerate databases after finding injection."""
        result = await self.execute(url, {"dbs": True, "batch": True})
        return result.data

    async def dump_table(
        self,
        url: str,
        database: str,
        table: str,
    ) -> dict[str, Any]:
        """Dump specific table contents."""
        result = await self.execute(url, {
            "database": database,
            "table": table,
            "dump": True,
            "batch": True,
        })
        return result.data
