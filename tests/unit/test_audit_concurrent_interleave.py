# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #105: verify() must not go permanently false after a concurrent writer.

record() resyncs the head from disk before every append so the on-disk chain
stays a single chain across processes. The side effect was that once a *second*
process appended between two of this process's record() calls, this process's
in-memory _entries became a subsequence of the real chain (its seq numbers
jumped), and verify() walked it as one contiguous segment and returned False for
the rest of the process's life, even though nothing was tampered with.

The fix treats an external append as a segment boundary: verify() validates the
in-memory segment since the last observed external write, and verify_file()
remains the authority for the whole on-disk chain.
"""
from __future__ import annotations

import json

from netreaper.core.audit import AuditTrail


def _trail(tmp_path, **kw):
    return AuditTrail(path=tmp_path / "audit.jsonl", **kw)


def test_verify_survives_a_concurrent_writer_between_appends(tmp_path):
    a = _trail(tmp_path)
    a.record(outcome="executed", tool="nmap", argv=["nmap", "10.0.0.5"])
    assert a.verify()

    # A different process appends to the same file between A's two records.
    b = _trail(tmp_path)
    b.record(outcome="executed", tool="nikto", argv=["nikto"])

    # A records again. Under the old code this made A.verify() False forever.
    a.record(outcome="denied", tool="hydra", argv=["hydra"], detail="out of scope")

    assert a.verify(), "verify() must stay true across a legitimate interleave"
    assert a.verify_file(), "the whole on-disk chain must still verify"

    seqs = [
        json.loads(line)["seq"]
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert seqs == [0, 1, 2], f"the on-disk chain must stay one chain: {seqs}"


def test_interleave_starts_a_fresh_in_memory_segment(tmp_path):
    a = _trail(tmp_path)
    a.record(outcome="executed", tool="nmap", argv=["nmap"])

    b = _trail(tmp_path)
    b.record(outcome="executed", tool="nikto", argv=["nikto"])

    a.record(outcome="executed", tool="masscan", argv=["masscan"])

    # A's live view is the post-interleave segment: its own last append, whose
    # seq continues the on-disk chain (2), not a contiguous run from A's start.
    assert [e.seq for e in a.entries] == [2]
    assert a.verify()
