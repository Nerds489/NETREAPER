# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #44: the real audit trail has to reach a deliverable, and the on-disk
chain has to be one chain.

Two disjoint audit systems never reconciled. The report rendered the DB
``audit_log`` table, whose INSERT omits ``session_id`` while the report's query
filters on it, so that section was always empty; and ``register_default_handlers``
had no callers, so the INSERT never ran at all. Meanwhile the hash-chained trail,
the actual tamper-evident record of what was spawned and denied against which
targets, appeared in no deliverable.

Separately, ``AuditTrail`` restarted at GENESIS in every process while appending
to the same file, so the file held several chains stacked end to end, and
``verify()`` never read the file so nothing noticed.
"""
from __future__ import annotations

import asyncio
import json

import netreaper.core.audit as audit_mod
from netreaper.core.audit import GENESIS, AuditTrail
from netreaper.export.manager import ExportManager


def _trail(tmp_path, name="audit.jsonl", **kw):
    return AuditTrail(path=tmp_path / name, **kw)


# ── the chain survives a process restart ──────────────────────────────────────


def test_a_second_session_continues_the_chain_instead_of_restarting(tmp_path):
    first = _trail(tmp_path)
    first.record(outcome="executed", tool="nmap", argv=["nmap", "10.0.0.5"])
    first.record(outcome="denied", tool="hydra", argv=["hydra"], detail="out of scope")
    head_after_first = first.head

    second = _trail(tmp_path)  # a new process, same file
    assert second.head == head_after_first, "did not adopt the on-disk head"
    second.record(outcome="executed", tool="nikto", argv=["nikto"])

    assert second.verify()        # its own segment
    assert second.verify_file()   # both sessions as one chain

    seqs = [
        json.loads(line)["seq"]
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert seqs == [0, 1, 2], f"sequence restarted instead of continuing: {seqs}"


def test_without_resume_the_file_becomes_two_chains_and_verify_file_says_so(tmp_path):
    """The old behaviour, pinned: this is the bug #44 describes."""
    first = _trail(tmp_path)
    first.record(outcome="executed", tool="nmap", argv=["nmap"])

    naive = _trail(tmp_path, resume=False)   # what every process used to do
    naive.record(outcome="executed", tool="nikto", argv=["nikto"])

    assert naive.verify(), "its own in-memory segment still looks fine"
    assert not naive.verify_file(), (
        "the file now holds two chains both starting at GENESIS/seq 0, and that "
        "has to be detectable"
    )


def test_a_fresh_trail_starts_at_genesis(tmp_path):
    t = _trail(tmp_path)
    assert t.head == GENESIS
    assert t.verify() and t.verify_file()


def test_a_damaged_tail_does_not_stop_auditing(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text('{"not": "an entry"}\n')
    t = AuditTrail(path=p)          # must not raise
    e = t.record(outcome="executed", tool="nmap", argv=["nmap"])
    assert e.seq == 0               # new segment
    assert t.verify()               # the new segment is internally sound


# ── verify_file catches what verify() cannot ──────────────────────────────────


def test_verify_file_catches_a_truncated_file(tmp_path):
    t = _trail(tmp_path)
    for i in range(4):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    assert t.verify_file()

    p = tmp_path / "audit.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")   # drop entry 1

    assert not t.verify_file()
    assert t.verify(), "memory is untouched, which is exactly why file checking matters"


def test_verify_file_catches_an_edited_entry(tmp_path):
    t = _trail(tmp_path)
    t.record(outcome="denied", tool="hydra", argv=["hydra"], targets=["10.0.0.5"])
    t.record(outcome="executed", tool="nmap", argv=["nmap"])

    p = tmp_path / "audit.jsonl"
    p.write_text(p.read_text().replace('"denied"', '"executed"'))

    assert not t.verify_file()


def test_verify_file_catches_reordering(tmp_path):
    t = _trail(tmp_path)
    for i in range(3):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    p = tmp_path / "audit.jsonl"
    lines = [x for x in p.read_text().splitlines() if x.strip()]
    p.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n")
    assert not t.verify_file()


# ── the report finally carries the real record ────────────────────────────────


def test_report_renders_the_hash_chain_not_the_empty_db_table(tmp_path, monkeypatch):
    trail = _trail(tmp_path)
    trail.record(
        outcome="executed", tool="nmap", argv=["nmap", "-p", "80", "10.0.0.5"],
        targets=["10.0.0.5"], tier="ACTIVE_SCAN",
    )
    trail.record(
        outcome="denied", tool="hydra", argv=["hydra", "-p", "hunter2"],
        targets=["8.8.8.8"], detail="out of scope",
    )
    monkeypatch.setattr(audit_mod, "_TRAIL", trail)

    data = asyncio.run(ExportManager()._gather_session_data(1))

    assert len(data["audit_trail"]) == 2
    assert [e["outcome"] for e in data["audit_trail"]] == ["executed", "denied"]
    assert data["audit_chain"]["entries"] == 2
    assert data["audit_chain"]["head"] == trail.head
    assert data["audit_chain"]["memory_verified"] is True
    assert data["audit_chain"]["file_verified"] is True


def test_the_report_states_when_the_chain_does_not_verify(tmp_path, monkeypatch):
    """A report must not present a broken chain as a good one."""
    trail = _trail(tmp_path)
    trail.record(outcome="executed", tool="nmap", argv=["nmap"])
    p = tmp_path / "audit.jsonl"
    p.write_text(p.read_text().replace('"executed"', '"denied"'))
    monkeypatch.setattr(audit_mod, "_TRAIL", trail)

    data = asyncio.run(ExportManager()._gather_session_data(1))
    assert data["audit_chain"]["file_verified"] is False


def test_the_report_still_redacts_credentials(tmp_path, monkeypatch):
    """#46's redaction must hold on the path #44 opened into the deliverable."""
    trail = _trail(tmp_path)
    trail.record(outcome="denied", tool="hydra", argv=["hydra", "-p", "hunter2"])
    monkeypatch.setattr(audit_mod, "_TRAIL", trail)

    data = asyncio.run(ExportManager()._gather_session_data(1))
    assert "hunter2" not in json.dumps(data)
    assert "***" in json.dumps(data["audit_trail"])


# ── revise pass: two defects found by attacking the first version ─────────────


def test_detail_is_redacted_too_not_just_argv(tmp_path):
    """The first version redacted argv and left `detail` open.

    The seam records ``str(exc)[:200]`` as detail, and an exception can quote the
    command that failed, so a password reached the log through the field that
    was not covered.
    """
    t = _trail(tmp_path)
    e = t.record(
        outcome="denied", tool="hydra", argv=["hydra", "-p", "hunter2"],
        detail="refused running: hydra -p hunter2 10.0.0.5",
    )
    assert "hunter2" not in e.detail
    assert "***" in e.detail
    assert "hunter2" not in (tmp_path / "audit.jsonl").read_text()


def test_detail_redaction_is_per_tool_like_argv(tmp_path):
    t = _trail(tmp_path)
    e = t.record(
        outcome="executed", tool="nmap", argv=["nmap"],
        detail="nmap -p 80,443 finished rc=0",
    )
    assert e.detail == "nmap -p 80,443 finished rc=0", (
        "-p is a port list for nmap in free text as much as in argv"
    )


def test_the_report_does_not_pretend_the_trail_is_session_scoped(tmp_path, monkeypatch):
    """The trail is process-wide and carries no session id.

    The first version dropped it into a per-session report with no caveat, so a
    report for session 1 and one for session 2 were byte-identical. Filtering is
    impossible without changing the hashed body, so the report says so instead.
    """
    trail = _trail(tmp_path)
    trail.record(outcome="executed", tool="nmap", argv=["nmap"], targets=["10.0.0.5"])
    monkeypatch.setattr(audit_mod, "_TRAIL", trail)

    one = asyncio.run(ExportManager()._gather_session_data(1))
    two = asyncio.run(ExportManager()._gather_session_data(2))

    assert one["audit_trail"] == two["audit_trail"]          # still process-wide
    assert "not filtered by session_id" in one["audit_chain"]["scope"]
    assert one["audit_chain"]["session_id"] == 1
    assert two["audit_chain"]["session_id"] == 2


def test_redaction_survives_newlines_and_tabs(tmp_path):
    """Revise pass: the first tokeniser split on spaces only.

    stderr folded into an exception message is newline-separated, so a secret
    walked straight past it.
    """
    t = _trail(tmp_path)
    for text in ("hydra\n-p\nhunter2", "hydra\t-p\thunter2", "hydra -p hunter2"):
        e = t.record(outcome="denied", tool="hydra", argv=["hydra"], detail=text)
        assert "hunter2" not in e.detail, text
        assert "***" in e.detail


def test_a_torn_final_line_does_not_destroy_the_chain(tmp_path):
    """Revise pass: a crash mid-append used to poison the trail permanently.

    Resume gave up and restarted at GENESIS, so the file gained a second chain
    and verify_file() returned False for ever after.
    """
    p = tmp_path / "audit.jsonl"
    first = AuditTrail(path=p)
    for i in range(3):
        first.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    # Killed mid-write: a partial line lands and the anchor never advances,
    # because the anchor is written after the append completes. Chopping bytes
    # off a fully anchored file is a different thing entirely (loss), and
    # test_a_truncated_trail_is_rejected below covers that.
    with p.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 3, "at": "2026-01-01T00:00:00Z", "outco')

    resumed = AuditTrail(path=p)
    assert resumed.verify_file()
    resumed.record(outcome="executed", tool="after-crash", argv=["x"])
    assert resumed.verify_file(), "the chain must continue across the crash"


def test_a_damaged_middle_is_still_rejected(tmp_path):
    """Tolerating a torn tail must not tolerate tampering."""
    p = tmp_path / "audit.jsonl"
    t = AuditTrail(path=p)
    for i in range(3):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    lines = p.read_text().splitlines()
    lines[1] = "{broken"
    p.write_text("\n".join(lines) + "\n")
    assert not AuditTrail(path=p, resume=False).verify_file()


# ── completeness: a hash chain cannot detect its own truncation ──────────────


def test_a_truncated_trail_is_rejected(tmp_path):
    """A prefix of a valid chain is a valid chain.

    Every entry binds the previous hash, so any edit WITHIN the file is caught.
    Cutting the file short is not: verify_file() walked from GENESIS and
    returned True for a log with its last entries removed, for a log reduced to
    one entry, and for an empty file. For a trail whose purpose is that an
    operator cannot later deny what the tool did, deleting the last few entries
    is the attack that matters, and it was the one that worked.
    """
    p = tmp_path / "audit.jsonl"
    t = AuditTrail(path=p)
    for i in range(5):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    assert t.verify_file()

    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-1]) + "\n")
    assert not AuditTrail(path=p).verify_file(), "truncation went undetected"


def test_an_emptied_trail_is_rejected(tmp_path):
    p = tmp_path / "audit.jsonl"
    t = AuditTrail(path=p)
    for i in range(3):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    p.write_text("")
    assert not AuditTrail(path=p).verify_file(), "an emptied trail verified"


def test_a_trail_cut_back_to_its_first_entry_is_rejected(tmp_path):
    p = tmp_path / "audit.jsonl"
    t = AuditTrail(path=p)
    for i in range(5):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    p.write_text(p.read_text().splitlines()[0] + "\n")
    assert not AuditTrail(path=p).verify_file()


def test_an_anchor_one_entry_behind_is_tolerated_exactly_once(tmp_path):
    """The only inconsistency a crash can leave, and no more than that.

    Killed between the append and the anchor update: the file is one ahead.
    Deliberately an equality, not a >=. A tolerance expressed as slack is how
    the streaming-capture guard came to permit two ungated spawns.
    """
    p = tmp_path / "audit.jsonl"
    t = AuditTrail(path=p)
    for i in range(4):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])

    anchor = p.with_suffix(p.suffix + ".anchor")
    lines = p.read_text().splitlines()

    raw = json.loads(anchor.read_text())
    raw["count"] -= 1
    raw["head"] = json.loads(lines[-2])["entry_hash"]
    anchor.write_text(json.dumps(raw, sort_keys=True))
    assert AuditTrail(path=p).verify_file(), "the real crash window must pass"

    raw["count"] -= 1
    raw["head"] = json.loads(lines[-3])["entry_hash"]
    anchor.write_text(json.dumps(raw, sort_keys=True))
    assert not AuditTrail(path=p).verify_file(), "two behind is not a crash"


def test_a_trail_written_before_anchoring_still_verifies(tmp_path):
    """A file from an older version has no anchor. It must not hard-fail."""
    p = tmp_path / "audit.jsonl"
    t = AuditTrail(path=p)
    for i in range(3):
        t.record(outcome="executed", tool=f"t{i}", argv=[f"t{i}"])
    p.with_suffix(p.suffix + ".anchor").unlink()
    assert AuditTrail(path=p).verify_file()


def test_the_anchor_is_owner_only(tmp_path):
    import stat

    p = tmp_path / "audit.jsonl"
    AuditTrail(path=p).record(outcome="executed", tool="t", argv=["t"])
    mode = stat.S_IMODE(p.with_suffix(p.suffix + ".anchor").stat().st_mode)
    assert mode == 0o600, f"anchor is {oct(mode)}; it names the trail's head"


# ── the DB audit_log section actually populates now (the query matched no
#    schema, so it silently returned nothing) ──────────────────────────────────


def test_the_export_audit_log_query_runs_against_the_real_schema(tmp_path):
    """The bug that survived because export SELECTs were never run against the
    schema in a test: the query filtered on audit_log.session_id and ordered by
    `timestamp`, neither of which exists, so it raised into a debug-logged
    try/except and the section was always empty.

    A real engine + a real audit_log row proves the query now matches the schema
    and the row reaches the export. If the column mismatch returns, `audit` is []
    and this fails.
    """
    from netreaper.db.engine import DatabaseEngine
    from netreaper.export.manager import ExportManager

    async def run():
        engine = DatabaseEngine(tmp_path / "t.db")
        await engine.initialize()
        try:
            await engine.execute(
                "INSERT INTO audit_log (level, category, message, details) "
                "VALUES (?, ?, ?, ?)",
                ("info", "vuln", "found something", "{}"),
            )
            return await ExportManager(db=engine)._gather_session_data("sess_x")
        finally:
            await engine.close()

    data = asyncio.run(run())
    assert len(data["audit_log"]) == 1, "audit_log section is empty; the query does not match the schema"
    assert data["audit_log"][0]["message"] == "found something"


def test_the_export_audit_log_is_process_wide_not_session_filtered(tmp_path):
    """audit_log has no session_id, so the section is process-wide by design
    (like the hash chain). A row is returned regardless of the session asked for."""
    from netreaper.db.engine import DatabaseEngine
    from netreaper.export.manager import ExportManager

    async def run():
        engine = DatabaseEngine(tmp_path / "t.db")
        await engine.initialize()
        try:
            await engine.execute(
                "INSERT INTO audit_log (level, category, message, details) "
                "VALUES (?, ?, ?, ?)",
                ("warning", "scan", "event", "{}"),
            )
            mgr = ExportManager(db=engine)
            # One row, two different session ids: the process-wide row shows for
            # both, because audit_log carries no session to filter on.
            return (
                await mgr._gather_session_data("sess_a"),
                await mgr._gather_session_data("sess_b"),
            )
        finally:
            await engine.close()

    a, b = asyncio.run(run())
    assert len(a["audit_log"]) == 1
    assert len(b["audit_log"]) == 1
