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

import contextlib
import hashlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

try:  # POSIX only; Windows degrades to single-writer
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

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
    "mysql": frozenset({"-p"}),
    "psql": frozenset({"-W"}),
    "smbclient": frozenset({"-U", "--user"}),
    "wpa_supplicant": frozenset({"-psk"}),
}

# Short flags that may carry their value ATTACHED, with no separator at all:
# `mysql -phunter2`, `hydra -phunter2`. Splitting on "=" never sees these, so
# the value walked straight into the trail.
ATTACHED_VALUE_FLAGS = frozenset({"-p", "-P", "-w", "-k"})

# `NAME=value` arguments that carry a credential in the name rather than a
# flag: PGPASSWORD=..., MYSQL_PWD=..., API_TOKEN=... . Matched on the name so a
# variable nobody listed is still caught.
_SECRET_NAME_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|APIKEY|API_KEY|PSK|PIN)$",
    re.IGNORECASE,
)

# `-U user%password`, the smbclient/rpcclient form: the secret is the tail of an
# argument whose head is a username, so neither the flag nor the whole value can
# be masked without losing the finding.
_USER_PERCENT_RE = re.compile(r"^([^%\s]+)%(.+)$", re.DOTALL)

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


def _tool_key(name: str) -> str:
    """Normalise a tool name to the key used by SECRET_FLAGS_BY_TOOL.

    redact_argv derived this from ``Path(argv[0]).name`` while redact_text used
    the caller's string verbatim, so one entry could have argv masked and detail
    in the clear. The lookup was also exact and case-sensitive, so ``Hydra``,
    ``HYDRA`` and ``hydra.exe`` all failed open, silently, for the two tools the
    design rationale names.
    """
    stem = Path(name.strip()).name.lower()
    for suffix in (".exe", ".bin", ".py"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    return stem


def _secret_flags(tool: str) -> frozenset[str]:
    return (
        SECRET_FLAGS_BY_TOOL.get(_tool_key(tool), frozenset()) | SECRET_FLAGS_ANY_TOOL
    )


def redact_url_creds(value: str) -> str:
    """Strip userinfo credentials from anything shaped like a URL or host.

    A credential is not always behind a flag the allow-list knows: sqlmap takes
    ``-u http://user:pass@host/``, ``--proxy``, ``--cookie`` and ``--data``, and
    a target can be ``root:pw@10.0.0.5``. None of those are flag names, so they
    reached the audit and the exported report verbatim.
    """
    if "@" not in value:
        return value
    scheme, sep, rest = value.partition("://")
    if not sep:
        scheme, rest = "", value
    userinfo, at, host = rest.rpartition("@")
    if not at or not userinfo or "/" in userinfo:
        return value
    user, colon, _pw = userinfo.partition(":")
    masked = f"{user}:{REDACTED}" if colon else REDACTED
    return f"{scheme}://{masked}@{host}" if sep else f"{masked}@{host}"


# Credentials as tools REPORT them, which is not flag-shaped at all. hydra
# prints "login: root   password: hunter2", aircrack-ng prints
# "KEY FOUND! [ abcd ]", reaver prints "WPA PSK: ..." and "WPS PIN: ...".
# Flag-based redaction cannot see any of it, so a success line leaked the one
# thing worth protecting: the credential the tool just recovered.
_OUTPUT_SECRET_RE = re.compile(
    r"(?i)\b(pass(?:word|phrase|wd)?|psk|wpa[\s_-]?psk|pmk|wps[\s_-]?pin|pin|key|"
    r"secret|token)\b(\s*[:=]\s*)(\S+)"
)
_KEY_FOUND_RE = re.compile(r"(?i)(KEY FOUND!\s*\[)([^\]]*)(\])")


def redact_output(text: str) -> str:
    """Mask credentials in a tool's own output lines.

    Keeps the label so the trail still shows that a credential was recovered,
    and keeps everything else on the line (host, port, service, login), because
    that is the finding. Only the secret itself goes.
    """
    if not text:
        return text
    out = _OUTPUT_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return _KEY_FOUND_RE.sub(lambda m: f"{m.group(1)} {REDACTED} {m.group(3)}", out)


def redact_targets(targets: list[str] | tuple[str, ...]) -> list[str]:
    """targets was stored raw: ``targets=['root:hunter2@10.0.0.5']`` hit disk."""
    return [redact_url_creds(str(x)) for x in targets]


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

    secret = _secret_flags(argv[0])

    out = [argv[0]]
    redact_next = False
    prev_flag = ""
    for arg in argv[1:]:
        if redact_next:
            # Mask the consumed value, and if that value is ITSELF a secret flag
            # then stay armed: ["-p", "-p", "hunter2"] is ambiguous, so fail
            # closed and mask both rather than let the real secret walk out
            # behind a flag-shaped decoy.
            #
            # `-U admin%hunter2` is the exception: the username is half the
            # finding, so masking the whole argument throws away who was tried.
            if (m := _USER_PERCENT_RE.match(arg)) and arg not in secret:
                out.append(f"{m.group(1)}%{REDACTED}")
            else:
                out.append(REDACTED)
            redact_next = arg in secret
            continue
        head = arg.split("=", 1)[0]
        if "=" in arg and head in secret:
            out.append(f"{head}={REDACTED}")
            continue
        # NAME=value where NAME itself names a credential (PGPASSWORD=...).
        if "=" in arg and _SECRET_NAME_RE.match(head):
            out.append(f"{head}={REDACTED}")
            continue
        # A short secret flag with its value attached: -phunter2.
        attached = next(
            (f for f in secret if f in ATTACHED_VALUE_FLAGS
             and len(arg) > len(f) and arg.startswith(f)),
            None,
        )
        if attached:
            out.append(f"{attached}{REDACTED}")
            continue
        # user%password, where only the tail is the secret.
        if prev_flag in secret and (m := _USER_PERCENT_RE.match(arg)):
            out.append(f"{m.group(1)}%{REDACTED}")
            prev_flag = arg
            continue
        out.append(redact_url_creds(arg))
        if arg in secret:
            redact_next = True
        prev_flag = arg
    return out

# The chain root: prev_hash of the first entry. 64 zeros = "no prior entry".
GENESIS = "0" * 64


def redact_text(text: str, tool: str = "") -> str:
    """Mask credential values inside a free-text field.

    ``detail`` carries ``str(exc)[:200]`` from the seam, and an exception can
    quote the command that failed, so redacting argv alone still let a password
    reach the log. Tokenises on whitespace and applies the same per-tool rules.
    Imperfect for quoted arguments containing spaces; it covers the realistic
    case, which is a command line echoed into an error message.
    """
    if not text:
        return text
    secret = _secret_flags(tool)
    # Split on ANY whitespace but keep the separators, so a newline- or
    # tab-separated command (stderr folded into an exception message) cannot
    # slip a secret past a space-only tokeniser, and the text still reads as
    # it was written.
    out: list[str] = []
    redact_next = False
    for tok in re.split(r"(\s+)", text):
        if not tok or tok.isspace():
            out.append(tok)
            continue
        if redact_next:
            out.append(REDACTED)
            redact_next = tok in secret
            continue
        head = tok.split("=", 1)[0]
        # NAME=value naming a credential (MYSQL_PWD=..., PGPASSWORD=...). The
        # argv path grew this rule; free text needs it too, because a command
        # echoed into an error message carries the same form.
        if "=" in tok and _SECRET_NAME_RE.match(head):
            out.append(f"{head}={REDACTED}")
            continue
        if "=" in tok and head in secret:
            out.append(f"{head}={REDACTED}")
            continue
        out.append(redact_url_creds(tok))
        if tok in secret:
            redact_next = True
    return "".join(out)


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


def _lock_for(path: Path | None) -> contextlib.AbstractContextManager[None]:
    """No path means in-memory only (tests): nothing to serialise."""
    return _file_lock(path) if path is not None else contextlib.nullcontext()


@contextlib.contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Exclusive advisory lock over the trail file, across PROCESSES.

    record()'s threading.Lock is per INSTANCE, and get_audit_trail() builds a
    new instance per process, so two concurrent netreaper processes had zero
    mutual exclusion over one hash-chained file. Measured: 200 records from two
    writers produced 100 duplicate seq numbers, verify_file() permanently False,
    and a third process resuming later adopted one chain and silently discarded
    the other 200 recorded actions.

    A hash chain cannot tolerate interleaved writers, so the read-head-and-append
    critical section is serialised here. Advisory locks are POSIX; on a platform
    without fcntl this degrades to the previous single-writer assumption rather
    than failing, because an audit write must never block or crash a spawn.
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    fh = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = lock_path.open("a+")
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    except OSError as e:
        logger.warning("audit file lock unavailable (%s); proceeding unlocked", e)
        yield
    finally:
        if fh is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fh.close()


def _harden(path: Path) -> None:
    """Create ``path`` if absent and make it owner-only.

    os.open with O_CREAT and mode 0600 gets the permissions right at creation,
    which a chmod after the fact cannot: a chmod leaves a window in which the
    file exists with whatever the umask allowed.
    """
    try:
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(fd)
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            path.chmod(0o600)  # pre-existing file from an older version
    except OSError as e:  # pragma: no cover - permissions are best effort
        logger.debug("could not harden %s: %s", path, e)


def _anchor_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".anchor")


def _write_anchor(path: Path, count: int, head: str) -> None:
    """Record how long the chain should be, beside the chain.

    A hash chain detects any edit WITHIN the file, because every entry binds the
    previous hash. It cannot detect the file being cut short, because a prefix of
    a valid chain is itself a valid chain: verify_file() walked from GENESIS and
    returned True for a truncated log, an emptied log, and a log reduced to its
    first entry. For a trail whose purpose is that an operator cannot later deny
    what the tool did, deleting the last few entries is the attack that matters.

    This does not make the trail cryptographically tamper-proof, and nothing
    local can: the anchor is unkeyed and sits on the same disk, so whoever can
    truncate the log can rewrite the anchor. What it does is raise the bar from
    one edit to two consistent ones, and make the accidental cases (a partial
    restore, a full disk, a crash, a copy that missed the tail) loud instead of
    silent. Real protection against the operator needs an out-of-band key or a
    remote anchor, which is a design decision rather than a patch.
    """
    try:
        anchor = _anchor_path(path)
        _harden(anchor)
        anchor.write_text(
            json.dumps({"count": count, "head": head}, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as e:  # pragma: no cover - best effort, never blocks an append
        logger.warning("could not update audit anchor: %s", e)


def _read_anchor(path: Path) -> tuple[int, str] | None:
    try:
        raw = json.loads(_anchor_path(path).read_text(encoding="utf-8"))
        return int(raw["count"]), str(raw["head"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


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
        # resume=False is an explicit opt-out, used to reproduce the old
        # fork-the-chain behaviour in tests. It must also suppress the
        # per-append head sync, or the flag silently means nothing.
        self._resume = resume
        if path is not None and resume:
            self._resume_from_file()

    def _sync_head_from_file(self) -> None:
        """Adopt the on-disk head/seq. Cheap, and correct under the lock."""
        try:
            if not self._path or not self._path.exists():
                return
            for line in reversed(
                [
                    x
                    for x in self._path.read_text(encoding="utf-8").splitlines()
                    if x.strip()
                ]
            ):
                try:
                    tail = json.loads(line)
                except ValueError:
                    continue
                self._head = str(tail["entry_hash"])
                self._seq = int(tail["seq"]) + 1
                return
        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.warning("could not read the audit head before appending: %s", e)

    def _resume_from_file(self) -> None:
        """Adopt the on-disk chain head so this process continues it."""
        try:
            if not self._path or not self._path.exists():
                return
            # Walk back to the last line that actually parses. A process killed
            # mid-append leaves a torn final line; abandoning the chain for it
            # was worse than the crash, because the next session then started a
            # second chain from GENESIS in the same file and the whole thing
            # stopped verifying for good.
            lines = [
                ln for ln in self._path.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            tail = None
            torn = 0
            for ln in reversed(lines):
                try:
                    tail = json.loads(ln)
                    break
                except ValueError:
                    torn += 1
            if tail is None:
                return
            if torn:
                # Resume in memory was not enough: the torn bytes stayed on disk
                # and _persist appends without checking the file ends in a
                # newline, so the next entry was glued onto the garbage. That
                # line then stops being the LAST line, which is the only case
                # verify_file forgives, so the trail broke permanently on the
                # SECOND write after a crash. Truncate to the last intact entry
                # so the file matches the head we just adopted.
                intact = lines[: len(lines) - torn]
                try:
                    self._path.write_text(
                        ("\n".join(intact) + "\n") if intact else "", encoding="utf-8"
                    )
                except OSError as e:
                    logger.warning("could not truncate the torn audit tail: %s", e)
                logger.warning(
                    "audit trail had %d torn line(s) at the tail; truncated to the "
                    "last intact entry and resumed from it", torn
                )
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
        with self._lock, _lock_for(self._path):
            # Re-read the real head under the lock. Trusting the in-memory head
            # was what let two processes both write seq N.
            if self._path is not None and self._resume:
                self._sync_head_from_file()
            seq = self._seq
            prev = self._head
            at = datetime.now(UTC).isoformat()
            # Redact at the sink, not at the call site: every caller of record()
            # gets it, so a future one cannot forget and write a password into a
            # permanent hash-chained log.
            # One tool key for both redactors, so argv and detail can never
            # disagree about which tool this is.
            key = tool or (argv[0] if argv else "")
            argv_l = redact_argv(argv)
            targets_l = redact_targets(targets)
            # detail is free text from an exception and can quote the command
            # redact_text handles a command line quoted inside an error
            # message. redact_output handles a tool ANNOUNCING a credential it
            # recovered ("KEY FOUND! [ hunter2 ]", "password: hunter2",
            # "WPA PSK: ..."). detail carries both, and only the first was
            # applied, so every password this tool successfully cracked was
            # written to the audit trail in the clear.
            detail = redact_output(redact_text(detail, key))
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
                lines = [ln for ln in fh if ln.strip()]
            last = len(lines) - 1
            for idx, line in enumerate(lines):
                try:
                    body = json.loads(line)
                except ValueError:
                    # Only a torn FINAL line is survivable: a process killed
                    # mid-append. Anything earlier means the middle of the chain
                    # is damaged, which is not something to wave through.
                    if idx == last:
                        logger.warning("audit trail has a torn final line")
                        break
                    return False
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

        # The chain is internally consistent. Now: is it COMPLETE? A prefix of a
        # valid chain verifies as a valid chain, so without this the log could be
        # cut short, or emptied, and still pass.
        anchor = _read_anchor(self._path)
        if anchor is None:
            logger.warning(
                "audit trail has no anchor file; completeness cannot be checked "
                "(written by a version before anchoring, or the anchor was removed)"
            )
            return True
        expected_count, expected_head = anchor
        if expected_seq == expected_count and prev == expected_head:
            return True
        if expected_seq == expected_count + 1:
            # Killed between the append and the anchor update. One entry, and
            # only one, may legitimately be ahead. Deliberately not a >= slack:
            # that is how the streaming-capture guard came to permit two ungated
            # spawns.
            logger.warning("audit anchor is one entry behind; recovering")
            _write_anchor(self._path, expected_seq, prev)
            return True
        logger.error(
            "audit trail is incomplete: %d entries on disk, anchor expects %d. "
            "The log has been truncated, restored from a partial copy, or lost "
            "entries.",
            expected_seq,
            expected_count,
        )
        return False

    def _persist(self, entry: AuditEntry) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # The trail names every target, every operator and every command
            # line of an engagement. engagement_store already writes its record
            # 0600; this inherited the process umask, so the same material was
            # 0644 and readable by every account on the box. Set the mode before
            # the first append rather than after, so there is no window where
            # the file exists world-readable.
            _harden(self._path)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(asdict(entry)) + "\n")
            # Anchor AFTER the append, so the only inconsistency a crash can
            # leave is an anchor one entry behind, which verify_file tolerates
            # explicitly. Anchoring first would make a crash look like a lost
            # entry, which is the thing being detected.
            _write_anchor(self._path, entry.seq + 1, entry.entry_hash)
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
