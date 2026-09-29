# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #106: session update() must not silently clobber a concurrent writer.

The old update() read a session, mutated it, then wrote ``WHERE id = :id`` with
no guard, so two callers racing on the same session each read the same row and
the last write won, discarding the other's change. update() now writes
``WHERE id = :id AND updated_at = :prev`` and, on a miss (rowcount 0), re-reads
and re-applies its own fields onto the fresh row.
"""
from __future__ import annotations

from datetime import datetime

import pytest

import netreaper.db.engine as engine_mod
from netreaper.db.engine import DatabaseEngine
from netreaper.sessions.manager import SessionManager

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def _db(tmp_path, monkeypatch):
    eng = DatabaseEngine(db_path=tmp_path / "sessions.db")
    await eng.initialize()
    monkeypatch.setattr(engine_mod, "_db_engine", eng)
    yield eng
    monkeypatch.setattr(engine_mod, "_db_engine", None)


async def test_plain_update_still_applies(_db):
    mgr = SessionManager()
    s = await mgr.create(name="engagement")
    out = await mgr.update(s.id, name="renamed")
    assert out is not None and out.name == "renamed"
    assert (await mgr.get(s.id)).name == "renamed"


async def test_update_retries_and_recovers_from_a_concurrent_writer(_db, monkeypatch):
    mgr = SessionManager()
    s = await mgr.create(name="engagement")

    # Hook the optimistic-baseline read: the first time update() reads the row's
    # updated_at, let it see the current value, then move updated_at (as another
    # writer would) so that attempt's WHERE clause misses and rowcount is 0.
    real_fetch_one = _db.fetch_one
    baseline_reads = {"n": 0}

    async def racy_fetch_one(query, params=()):
        res = await real_fetch_one(query, params)
        if query.strip().startswith("SELECT updated_at FROM sessions"):
            baseline_reads["n"] += 1
            if baseline_reads["n"] == 1:
                await _db.execute(
                    "UPDATE sessions SET updated_at = :u WHERE id = :id",
                    {"u": datetime(2000, 1, 1).isoformat(), "id": params["id"]},
                )
        return res

    monkeypatch.setattr(_db, "fetch_one", racy_fetch_one)

    out = await mgr.update(s.id, name="renamed")

    assert baseline_reads["n"] == 2, "first attempt should race and lose, then retry"
    assert out is not None and out.name == "renamed"
    # The change actually landed, rather than being silently dropped.
    monkeypatch.setattr(_db, "fetch_one", real_fetch_one)
    assert (await mgr.get(s.id)).name == "renamed"
