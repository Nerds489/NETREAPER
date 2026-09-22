# SPDX-License-Identifier: GPL-3.0-or-later
"""hashcat wrapper: crack the hashes this tool already knows how to produce.

NETREAPER has been emitting hashcat-format material for a long time and could
not run hashcat. `wifi pmkid` prints a mode-22000 hash, `wifi enterprise` writes
a mode-5500 file, the TUI credentials screen offers a hash-type and attack-mode
picker, `core/bootstrap.py` detects a GPU "for hashcat acceleration", and the
preflight warns that hashcat on CPU is slow. Every one of those is a declaration
pointing at an adapter that did not exist: `tui/screens/credentials.py` caught
the ImportError and told the operator to "choose John, or run hashcat directly".

Three details decide whether this wrapper is usable or merely present.

THE POTFILE. hashcat records every cracked hash in a potfile and then refuses to
show it again on a later run, printing nothing and exiting 1. Run it twice and
the second run looks like a failure against a hash you have already broken. This
wrapper passes --potfile-disable by default so a result is reported every time.
Set `potfile=True` to opt back in.

EXHAUSTED IS NOT FAILURE. hashcat exits 1 when it works through every candidate
and finds nothing. That is a finished run with a negative answer, not a broken
one, but BaseToolWrapper maps any non-zero exit to success=False, and the
credentials screen renders that as "Cracking failed" with no errors to show. So
`execute` is overridden to report an exhausted run as a success carrying
`exhausted: True` and an empty `cracked` list. The operator learns the password
was not in the wordlist, which is the actual finding.

THE LAST COLON, NOT THE FIRST. A cracked line is `<hash>:<password>`, and the
hash itself often contains colons: mode 5500 is
`user::domain:challenge:response:response`. Splitting on the first colon would
return a username as the hash and the rest of the line as the password. This
splits on the last one.

TIERING. hashcat reads a local file and burns local compute. It opens no socket
and has no network target, so it is PASSIVE with no scope identifiers, exactly
as the john wrapper beside it.
"""
from __future__ import annotations

import re
from typing import Any, ClassVar

from pydantic import BaseModel

from netreaper.core.exceptions import ConfigurationError
from netreaper.core.logging import get_logger
from netreaper.plugins.base import Capability, PluginMetadata, PluginResult, PluginType
from netreaper.safety.scope import Tier
from netreaper.tools.base import BaseToolWrapper

logger = get_logger(__name__)

# hashcat's own exit codes (src/hashcat.c). 1 is a completed run, not an error.
EXIT_CRACKED = 0
EXIT_EXHAUSTED = 1
EXIT_ABORTED = 2

# Which trailing operands each attack mode takes, in order. hashcat's usage:
#   hashcat [options] hashfile [dictionary|mask|directory]
_ATTACK_OPERANDS: dict[int, tuple[str, ...]] = {
    0: ("wordlist",),              # straight
    1: ("wordlist", "wordlist2"),  # combination, two dictionaries
    3: ("mask",),                  # brute force / mask
    6: ("wordlist", "mask"),       # hybrid wordlist + mask
    7: ("mask", "wordlist"),       # hybrid mask + wordlist
}


# Every hashcat status line contains a colon, so they must not be read as
# cracked pairs.
_STATUS_PREFIXES = (
    "Session", "Status", "Hash.", "Time.", "Speed", "Progress", "Candidates",
    "Hardware", "Guess", "Restore", "Started", "Stopped", "Kernel", "Rejected",
    "Device",
)


class HashcatConfig(BaseModel):
    """hashcat defaults."""

    workload: int | None = None   # -w, 1 low to 4 nightmare
    potfile: bool = False         # see the module docstring
    quiet: bool = True


class HashcatTool(BaseToolWrapper):
    """hashcat wrapper: local hash cracking."""

    DEFAULT_TIER = Tier.PASSIVE  # local hash cracker: no network target

    def target_identifiers(self, target: str, options: dict[str, Any]) -> list[str]:
        return []

    def execution_tier(self, target: str, options: dict[str, Any]) -> Tier:
        return Tier.PASSIVE

    TOOL_BINARY: ClassVar[str] = "hashcat"

    METADATA: ClassVar[PluginMetadata] = PluginMetadata(
        name="hashcat",
        version="1.0.0",
        description="Advanced password recovery",
        author="NETREAPER",
        plugin_type=PluginType.CRACKER,
        capabilities=[Capability.PASSWORD_CRACK],
        requires_root=False,
        external_tools=["hashcat"],
        config_schema=HashcatConfig,
    )

    # `Recovered........: 1/2 (50.00%) Digests` gives both halves at once.
    _RECOVERED_RE: ClassVar = re.compile(r"Recovered\.*:\s*(\d+)/(\d+)")

    def __init__(
        self, hashcat_config: HashcatConfig | None = None, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.hashcat_config = hashcat_config or HashcatConfig()

    def build_command(self, target: str, options: dict[str, Any]) -> list[str]:
        """Build the hashcat command.

        Args:
            target: The hash file to crack (the TUI also passes it as
                ``hash_file``; either is accepted).
            options:
                - hash_mode: -m, the hash type (22000, 5500, ...), required
                - attack_mode: -a, defaults to 0 (straight)
                - wordlist / wordlist2 / mask: trailing operands, per attack mode
                - show: short-circuit to --show, listing what is already cracked
                - outfile: -o
                - workload: -w
                - devices: -d
                - session / restore: session control
                - potfile: True to re-enable the potfile
        """
        hash_file = target or options.get("hash_file")
        if not hash_file:
            raise ConfigurationError("hashcat needs a hash file")

        mode = options.get("hash_mode")
        if mode is None:
            raise ConfigurationError(
                "hashcat needs a hash_mode (-m): 22000 for PMKID/EAPOL, "
                "5500 for NetNTLM, and so on"
            )

        # --show is a whole invocation of its own, not a flag to add to a crack
        # run: it reads the potfile and prints, so it must NOT disable it.
        if options.get("show"):
            return ["-m", str(mode), "--show", str(hash_file)]

        attack = int(options.get("attack_mode", 0))
        cmd = ["-m", str(mode), "-a", str(attack)]

        if not options.get("potfile", self.hashcat_config.potfile):
            cmd.append("--potfile-disable")
        if options.get("quiet", self.hashcat_config.quiet):
            cmd.append("--quiet")

        workload = options.get("workload", self.hashcat_config.workload)
        if workload:
            cmd += ["-w", str(workload)]
        if options.get("devices"):
            cmd += ["-d", str(options["devices"])]
        if options.get("outfile"):
            # 1,2 is hash:plain, which is what parse_output reads back.
            cmd += ["-o", str(options["outfile"]), "--outfile-format", "1,2"]
        if options.get("session"):
            cmd += ["--session", str(options["session"])]
        if options.get("increment"):
            cmd.append("--increment")

        cmd.append(str(hash_file))

        # The trailing operands depend on the attack mode, and getting them
        # wrong is not a soft failure: hashcat treats a mask as a dictionary
        # path and exits on a file it cannot open.
        expected = _ATTACK_OPERANDS.get(attack)
        if expected is None:
            raise ConfigurationError(
                f"unsupported hashcat attack mode {attack}; "
                f"supported: {', '.join(str(a) for a in sorted(_ATTACK_OPERANDS))}"
            )
        missing = [name for name in expected if not options.get(name)]
        if missing:
            raise ConfigurationError(
                f"hashcat attack mode {attack} needs {', '.join(missing)}",
                context={"attack_mode": attack, "missing": missing},
            )
        cmd += [str(options[name]) for name in expected]
        return cmd

    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse hashcat output into cracked pairs.

        A cracked line is ``<hash>:<password>``. The hash can itself contain
        colons, so the split is on the LAST one.
        """
        result: dict[str, Any] = {
            "raw_output": output,
            "cracked": [],
            "total": 0,
            "exhausted": False,
            "errors": [],
        }

        for raw in (output or "").splitlines():
            line = raw.strip()
            if not line:
                continue

            recovered = self._RECOVERED_RE.search(line)
            if recovered:
                result["total"] = int(recovered.group(2))
                continue

            lowered = line.lower()
            if lowered.startswith("exhausted") or "exhausted" in lowered.split(":")[-1]:
                result["exhausted"] = True
                continue
            if line.startswith(_STATUS_PREFIXES):
                continue
            if "error" in lowered or "no such file" in lowered:
                result["errors"].append(line)
                continue

            if ":" in line:
                hashed, password = line.rsplit(":", 1)
                if hashed:
                    result["cracked"].append({"hash": hashed, "password": password})

        if not result["total"]:
            result["total"] = len(result["cracked"])
        return result

    async def execute(self, target: str, options: dict[str, Any]) -> PluginResult:
        """Run hashcat, reporting an exhausted search as a finished run.

        hashcat exits 1 when it tries every candidate and cracks nothing.
        BaseToolWrapper maps any non-zero exit to success=False, which the
        credentials screen renders as "Cracking failed" with no errors attached,
        so a wordlist that simply did not contain the password reads as a broken
        tool. Exhausted is a result, and it is reported as one.
        """
        result = await super().execute(target, options)
        code = self._execution.exit_code if self._execution else None

        if not result.success and code == EXIT_EXHAUSTED:
            data = dict(result.data or {})
            data["exhausted"] = True
            data.setdefault("cracked", [])
            logger.info(
                "hashcat exhausted the keyspace without a match (%s candidates tried)",
                data.get("total", 0),
            )
            return PluginResult(
                success=True,
                data=data,
                warnings=["hashcat exhausted the keyspace: no password recovered"],
            )
        return result

    async def crack(
        self,
        hash_file: str,
        hash_mode: int,
        *,
        wordlist: str | None = None,
        attack_mode: int = 0,
        **options: Any,
    ) -> dict[str, Any]:
        """Crack ``hash_file`` and return the parsed result."""
        opts: dict[str, Any] = {
            "hash_mode": hash_mode,
            "attack_mode": attack_mode,
            **options,
        }
        if wordlist:
            opts["wordlist"] = wordlist
        result = await self.execute(hash_file, opts)
        return result.data or {}
