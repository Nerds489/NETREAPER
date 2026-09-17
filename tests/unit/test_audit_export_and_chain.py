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
