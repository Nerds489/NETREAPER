# SPDX-License-Identifier: GPL-3.0-or-later
"""The planner's durable capability cache (#31).

`resolve_chain` could always take an `available` set; nothing persisted one, so
`wifi auto` re-derived everything every run. This is the persistence, and its
correctness rests on two refusals that a naive "record every output" cache gets
wrong:

  a handshake is only cached while its .cap file exists, and re-checked on read,
  because the auto path deletes the capture it just made;

  ephemeral capabilities (a live monitor interface, an in-air scan list) are
  never cached, because they are properties of the run, not the target.

Only `wifi.password` and a surviving `wifi.handshake` are durable, and the store
keeps a marker, never the recovered value.
"""
from __future__ import annotations

import asyncio
import json

from netreaper.chaining import state_cache as sc


def _run(tmp_path, body):
    """Drive one async scenario against a throwaway database.

    One `asyncio.run` per test, mirroring test_db_schema: the engine's aiosqlite
    connection is bound to the loop that made it, so all work for a test lives in
    a single loop. `get_db()` reads the module global at call time, so pointing
    that global at the tmp engine is enough to redirect the cache.
    """
    async def scenario():
        from netreaper.db import engine as engine_mod

        engine = engine_mod.DatabaseEngine(tmp_path / "t.db")
        await engine.initialize()
        engine_mod._db_engine = engine
        try:
            return await body(engine)
        finally:
            await engine.close()
            engine_mod._db_engine = None

    return asyncio.run(scenario())


async def _count(engine) -> int:
    rows = await engine.fetch_all("SELECT COUNT(*) AS n FROM available_state", ())
    return rows[0]["n"]


# ── the durable happy path ────────────────────────────────────────────────────


def test_a_password_marker_round_trips(tmp_path):
    async def body(_engine):
        assert await sc.record_capability("bssid", "AA:BB", "wifi.password", "cracked")
        return await sc.available_for("bssid", "AA:BB")

    assert _run(tmp_path, body) == {"wifi.password"}


def test_the_password_value_itself_is_never_stored(tmp_path):
    """The marker is the fact; the secret belongs in the loot store, not here."""
    secret = "hunter2-the-actual-key"  # noqa: S105

    async def body(engine):
        await sc.record_capability("bssid", "AA:BB", "wifi.password", secret)
        rows = await engine.fetch_all(
            "SELECT capability, metadata FROM available_state", ()
        )
        return rows

    rows = _run(tmp_path, body)
    assert rows[0]["capability"] == "wifi.password"
    assert secret not in json.dumps(rows)


# ── the two refusals that keep it correct ─────────────────────────────────────


def test_ephemeral_capabilities_are_not_recorded(tmp_path):
    async def body(engine):
        results = [
            await sc.record_capability("bssid", "AA:BB", cap, value)
            for cap, value in (
                ("wifi.monitor_interface", "wlan0mon"),
                ("wifi.bssid_list", ["AA:BB"]),
                ("wifi.ssid_list", ["home"]),
            )
        ]
        return results, await _count(engine)

    results, count = _run(tmp_path, body)
    assert results == [False, False, False]
    assert count == 0


def test_a_handshake_needs_a_real_file_to_be_recorded(tmp_path):
    async def body(_engine):
        gone = await sc.record_capability(
            "bssid", "AA:BB", "wifi.handshake", str(tmp_path / "nope.cap")
        )
        cap = tmp_path / "real.cap"
        cap.write_bytes(b"pcap")
        here = await sc.record_capability("bssid", "AA:BB", "wifi.handshake", str(cap))
        return gone, here, await sc.available_for("bssid", "AA:BB")

    gone, here, available = _run(tmp_path, body)
    assert gone is False
    assert here is True
    assert available == {"wifi.handshake"}


def test_a_stale_handshake_is_dropped_on_read(tmp_path):
    """The whole point: a recorded handshake whose file has since gone must not
    be handed to the planner, or the cracker is fed a deleted capture."""
    async def body(_engine):
        cap = tmp_path / "h.cap"
        cap.write_bytes(b"pcap")
        await sc.record_capability("bssid", "AA:BB", "wifi.handshake", str(cap))
        before = await sc.available_for("bssid", "AA:BB")
        cap.unlink()
        after = await sc.available_for("bssid", "AA:BB")
        return before, after

    before, after = _run(tmp_path, body)
    assert before == {"wifi.handshake"}
    assert after == set()


def test_read_filters_out_a_capability_that_is_not_durable(tmp_path):
    """Defence in depth: even a row inserted by hand for an ephemeral capability
    is not offered, because the read is gated on the durability policy too."""
    async def body(engine):
        await engine.execute(
            """
            INSERT INTO available_state (target_type, target, capability)
            VALUES (?, ?, ?)
            """,
            ("bssid", "AA:BB", "wifi.monitor_interface"),
        )
        return await sc.available_for("bssid", "AA:BB")

    assert _run(tmp_path, body) == set()


# ── keying, upsert, sentinel session ──────────────────────────────────────────


def test_recording_the_same_capability_twice_is_idempotent(tmp_path):
    async def body(engine):
        await sc.record_capability("bssid", "AA:BB", "wifi.password", "k1")
        await sc.record_capability("bssid", "AA:BB", "wifi.password", "k2")
        return await _count(engine)

    assert _run(tmp_path, body) == 1


def test_the_no_session_sentinel_upserts_rather_than_duplicating(tmp_path):
    """SQLite treats NULLs as distinct in UNIQUE; the '-' sentinel is what makes
    the no-session upsert collapse instead of stacking a row per run."""
    async def body(engine):
        await sc.record_capability("bssid", "AA:BB", "wifi.password", "k")
        await sc.record_capability("bssid", "AA:BB", "wifi.password", "k")
        rows = await engine.fetch_all("SELECT session_id FROM available_state", ())
        return rows

    rows = _run(tmp_path, body)
    assert len(rows) == 1
    assert rows[0]["session_id"] == sc.NO_SESSION


def test_different_targets_do_not_collide(tmp_path):
    async def body(_engine):
        await sc.record_capability("bssid", "AA:BB", "wifi.password", "k")
        return (
            await sc.available_for("bssid", "AA:BB"),
            await sc.available_for("bssid", "CC:DD"),
        )

    mine, other = _run(tmp_path, body)
    assert mine == {"wifi.password"}
    assert other == set()


# ── record_plan_outputs: the executor's output shape ──────────────────────────


def test_record_plan_outputs_keeps_only_the_durable_ones(tmp_path):
    """final_output is {step_id: {capability: value}}. Record wifi.password,
    drop the ephemeral scan list, in one pass."""
    cap = tmp_path / "h.cap"
    cap.write_bytes(b"pcap")
    final_output = {
        "enable_monitor_mode": {"wifi.monitor_interface": "wlan0mon"},
        "scan_networks": {"wifi.bssid_list": ["AA:BB"], "wifi.ssid_list": ["home"]},
        "capture_handshake": {"wifi.handshake": str(cap)},
        "crack_handshake": {"wifi.password": "cracked"},
    }

    async def body(_engine):
        recorded = await sc.record_plan_outputs("bssid", "AA:BB", final_output)
        return recorded, await sc.available_for("bssid", "AA:BB")

    recorded, available = _run(tmp_path, body)
    assert sorted(recorded) == ["wifi.handshake", "wifi.password"]
    assert available == {"wifi.handshake", "wifi.password"}


def test_record_plan_outputs_tolerates_junk_shapes(tmp_path):
    async def body(_engine):
        recorded = await sc.record_plan_outputs(
            "bssid", "AA:BB", {"weird": "not-a-dict", "empty": {}}
        )
        return recorded

    assert _run(tmp_path, body) == []


# ── forget, and the degrade-never-raise contract ──────────────────────────────


def test_forget_clears_a_target(tmp_path):
    async def body(_engine):
        await sc.record_capability("bssid", "AA:BB", "wifi.password", "k")
        await sc.forget("bssid", "AA:BB")
        return await sc.available_for("bssid", "AA:BB")

    assert _run(tmp_path, body) == set()


def test_a_database_error_degrades_to_no_state_rather_than_raising():
    """A broken cache must never stop wifi auto from running the full chain."""
    from netreaper.db import engine as engine_mod

    class _Broken:
        async def fetch_all(self, *a, **k):
            raise RuntimeError("db down")

        async def execute(self, *a, **k):
            raise RuntimeError("db down")

    async def scenario():
        engine_mod._db_engine = _Broken()
        try:
            read = await sc.available_for("bssid", "AA:BB")
            wrote = await sc.record_capability("bssid", "AA:BB", "wifi.password", "k")
            await sc.forget("bssid", "AA:BB")  # must not raise either
            return read, wrote
        finally:
            engine_mod._db_engine = None

    read, wrote = asyncio.run(scenario())
    assert read == set()
    assert wrote is False
