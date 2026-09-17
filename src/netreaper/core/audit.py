# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Hash-chained integrity audit trail (rebuild plan §5.5).

Every process-spawn decision — denied, dry-run, executed or spawn-error — is
appended here from the one spawn seam (:mod:`netreaper.core.process`), so an
action that reaches (or is refused at) that seam without an audit record is
structurally impossible.

Each entry stores ``sha256(previous entry hash + this entry's canonical body)``,
forming a chain: any alter, drop or reorder of a past entry that does not also
recompute every later hash is caught by :meth:`AuditTrail.verify`. This is an
UNKEYED chain — it detects accidental corruption and naive edits, not a
motivated local attacker who holds the same code and can rewrite the whole
chain. Keying it (HMAC with an out-of-band session key) and anchoring ``head``
externally is the hardening path if that threat matters; not yet done.

The trail is authoritative in memory for the session and best-effort persisted
as append-only JSONL; a persistence failure never blocks or crashes a spawn (it
is logged and the entry is kept in memory).
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from netreaper.core.constants import NETREAPER_LOG_DIR
from netreaper.core.logging import get_logger

logger = get_logger(__name__)

REDACTED = "***"

# Flags whose VALUE is a credential, per tool. Deliberately per-tool: "-p" is a
# password to hydra and a recovered WPS PIN to reaver, but a port list to nmap
# and masscan, a parameter name to sqlmap, a plugin list to whatweb and a
# pattern to gobuster. A blanket "-p is secret" rule would blank the port list
# on every scan in the trail, which is exactly the detail an audit is for.
#
# Not redacted on purpose: hydra's -P/-C (paths to credential files) and -l/-L
# (usernames). The path and the account tried are the audit's substance; the
# secret is the password itself.
SECRET_FLAGS_BY_TOOL: dict[str, frozenset[str]] = {
    "hydra": frozenset({"-p"}),
    "reaver": frozenset({"-p"}),
}

# Secret whatever the tool. Unambiguous long options, so a tool added later is
# covered without anyone remembering to extend the map above.
SECRET_FLAGS_ANY_TOOL = frozenset(
    {
        "--password", "--passwd", "--passphrase", "--pass",
        "--psk", "--pre-shared-key", "--wpa-passphrase",
        "--secret", "--token", "--auth-token",
        "--api-key", "--apikey", "--pin",
    }
)


def redact_argv(argv: list[str] | tuple[str, ...]) -> list[str]:
    """Mask credential values in an argument vector, keeping its shape.

    The flag stays, only its value becomes ``***``, so the trail still shows
    that a password was supplied and which option carried it. Handles both
    ``--password secret`` and ``--password=secret``. A trailing secret flag with
    no value is left with nothing to redact.
    """
    argv = list(argv)
    if not argv:
        return []

    tool = Path(argv[0]).name
    secret = SECRET_FLAGS_BY_TOOL.get(tool, frozenset()) | SECRET_FLAGS_ANY_TOOL

    out = [argv[0]]
    redact_next = False
    for arg in argv[1:]:
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        head = arg.split("=", 1)[0]
        if "=" in arg and head in secret:
            out.append(f"{head}={REDACTED}")
            continue
        out.append(arg)
        if arg in secret:
            redact_next = True
    return out

# The chain root: prev_hash of the first entry. 64 zeros = "no prior entry".
GENESIS = "0" * 64


def _canonical(body: dict[str, object]) -> str:
    """Deterministic serialisation of an entry body (stable key order)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class AuditEntry:
    """One immutable, hash-linked audit record."""

    seq: int
    at: str  # ISO-8601 UTC
    outcome: str  # denied | dry-run | executed | spawn-error
    operator: str
    consent: str  # the engagement's consent hash, or "-" when target-less
    tool: str
    argv: list[str]
    targets: list[str]
    tier: str
    destructive: bool
    host_action: bool
    detail: str
    prev_hash: str
    entry_hash: str


class AuditTrail:
    """Append-only, hash-chained audit log. Thread-safe."""

    def __init__(self, path: Path | None = None, *, resume: bool = True) -> None:
        self._lock = threading.Lock()
        self._entries: list[AuditEntry] = []
        self._head = GENESIS
        self._seq = 0
        self._path = path  # None => in-memory only (tests)
        # Where this process's in-memory segment joins the on-disk chain. Without
        # these, every process restarted at GENESIS/seq 0 and appended to the same
        # file, so the file held several chains stacked end to end and nothing
        # noticed. verify() checks the in-memory segment against these, and
        # verify_file() walks the whole file as one chain.
        self._start_seq = 0
        self._start_prev = GENESIS
        if path is not None and resume:
            self._resume_from_file()

    def _resume_from_file(self) -> None:
        """Adopt the on-disk chain head so this process continues it."""
        try:
            if not self._path or not self._path.exists():
                return
            last = None
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last is None:
                return
            tail = json.loads(last)
            self._head = self._start_prev = str(tail["entry_hash"])
            self._seq = self._start_seq = int(tail["seq"]) + 1
        except (OSError, ValueError, KeyError, TypeError) as e:
            # A damaged tail must not stop the session from auditing. Start a new
            # segment from GENESIS and say so: verify_file() will report the break.
            logger.warning(
                "audit trail could not be resumed (%s); starting a new segment", e
            )

    def record(
        self,
        *,
        outcome: str,
        operator: str = "-",
        consent: str = "-",
        tool: str = "",
        argv: list[str] | tuple[str, ...] = (),
        targets: list[str] | tuple[str, ...] = (),
        tier: str = "PASSIVE",
        destructive: bool = False,
        host_action: bool = False,
        detail: str = "",
    ) -> AuditEntry:
        """Append one entry, hash-linked to the current chain head."""
        with self._lock:
            seq = self._seq
            prev = self._head
            at = datetime.now(UTC).isoformat()
            # Redact at the sink, not at the call site: every caller of record()
            # gets it, so a future one cannot forget and write a password into a
            # permanent hash-chained log.
            argv_l = redact_argv(argv)
            targets_l = list(targets)
            body = {
                "seq": seq,
                "at": at,
                "outcome": outcome,
                "operator": operator,
                "consent": consent,
                "tool": tool,
                "argv": argv_l,
                "targets": targets_l,
                "tier": tier,
                "destructive": bool(destructive),
                "host_action": bool(host_action),
                "detail": detail,
                "prev_hash": prev,
            }
            entry_hash = hashlib.sha256(
                (prev + _canonical(body)).encode()
            ).hexdigest()
            entry = AuditEntry(
                seq=seq, at=at, outcome=outcome, operator=operator,
                consent=consent, tool=tool, argv=argv_l, targets=targets_l,
                tier=tier, destructive=bool(destructive),
                host_action=bool(host_action), detail=detail,
                prev_hash=prev, entry_hash=entry_hash,
            )
            self._entries.append(entry)
            self._head = entry_hash
            self._seq += 1
            # Persist under the lock so the JSONL line order always matches the
            # in-memory chain order. This serialises spawns behind the append;
            # acceptable for an audit trail, and the write is a single short line.
            self._persist(entry)
            return entry

    def verify(self) -> bool:
        """Recompute the whole chain. True iff nothing was altered/dropped/reordered."""
        with self._lock:
            prev = self._start_prev
            for i, e in enumerate(self._entries):
                body = {k: v for k, v in asdict(e).items() if k != "entry_hash"}
                if body["seq"] != self._start_seq + i or body["prev_hash"] != prev:
                    return False
                if (
                    hashlib.sha256((prev + _canonical(body)).encode()).hexdigest()
                    != e.entry_hash
                ):
                    return False
                prev = e.entry_hash
            return True

    def verify_file(self) -> bool:
        """Recompute the whole ON-DISK chain, across every session that wrote it.

        :meth:`verify` only covers what this process holds in memory, which was
        the gap: a trail could verify happily while the file it had been
        appending to was truncated, reordered or stitched from several chains.
        True iff the file is one unbroken chain from GENESIS, or there is no
        file yet.
        """
        if self._path is None or not self._path.exists():
            return True
        prev = GENESIS
        expected_seq = 0
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    body = json.loads(line)
                    entry_hash = body.pop("entry_hash", None)
                    if body.get("seq") != expected_seq or body.get("prev_hash") != prev:
                        return False
                    if (
                        hashlib.sha256((prev + _canonical(body)).encode()).hexdigest()
                        != entry_hash
                    ):
                        return False
                    prev = str(entry_hash)
                    expected_seq += 1
        except (OSError, ValueError) as e:
            logger.warning("audit trail file could not be verified: %s", e)
            return False
        return True

    def _persist(self, entry: AuditEntry) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(asdict(entry)) + "\n")
        except OSError as e:
            logger.warning("audit persist failed (%s); entry kept in memory", e)

    @property
    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    @property
    def head(self) -> str:
        return self._head


_TRAIL: AuditTrail | None = None


def get_audit_trail() -> AuditTrail:
    """Return the process-wide audit trail (JSONL-persisted under the log dir)."""
    global _TRAIL
    if _TRAIL is None:
        _TRAIL = AuditTrail(path=NETREAPER_LOG_DIR / "audit.jsonl")
    return _TRAIL


__all__ = ["GENESIS", "AuditEntry", "AuditTrail", "get_audit_trail"]
