-- SPDX-License-Identifier: GPL-3.0-or-later
-- NETREAPER database schema.
--
-- db/engine.py has always looked for this file and executed it on initialize().
-- It did not exist, and the lookup was guarded by `if schema_path.exists()`, so
-- initialize() created no tables at all and then logged "Database initialized".
-- Three modules were already writing to it: sessions/manager.py, loot/storage.py
-- and orchestration/handlers.py. Every one of their statements would have failed
-- with "no such table".
--
-- The columns below are not a design. They are read off the statements those
-- three modules already issue, so the schema matches the code rather than the
-- code being changed to match a new schema.

PRAGMA foreign_keys = ON;

-- sessions ------------------------------------------------------------------
-- Written by SessionManager.create, read back through Session.from_db_row,
-- which reads id, name, status, workflow_state, config, metadata, created_at,
-- updated_at and ended_at. config and metadata are JSON documents.
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    workflow_state  TEXT,
    config          TEXT NOT NULL DEFAULT '{}',
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- targets -------------------------------------------------------------------
-- add_target upserts with
--   ON CONFLICT(session_id, target_type, value) DO UPDATE SET last_scanned = ...
-- so that triple MUST carry a unique constraint or the upsert raises rather
-- than updating.
CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_type  TEXT NOT NULL,
    value        TEXT NOT NULL,
    metadata     TEXT NOT NULL DEFAULT '{}',
    first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    last_scanned TEXT,
    UNIQUE (session_id, target_type, value)
);

CREATE INDEX IF NOT EXISTS idx_targets_session ON targets(session_id);

-- loot ----------------------------------------------------------------------
-- LootStorage.store writes session_id, target_id, loot_type, encrypted_data,
-- source_tool and metadata. Reads select discovered_at as well, so it needs a
-- default rather than being supplied on insert. encrypted_data is ciphertext,
-- hence BLOB: the plaintext never reaches this table.
CREATE TABLE IF NOT EXISTS loot (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    target_id      INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    loot_type      TEXT NOT NULL,
    encrypted_data BLOB,
    source_tool    TEXT,
    metadata       TEXT,
    discovered_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_loot_session ON loot(session_id);
CREATE INDEX IF NOT EXISTS idx_loot_type ON loot(loot_type);

-- tool_executions -----------------------------------------------------------
-- log_tool_execution inserts session_id, tool_name, command, status, exit_code,
-- summary and output_file; update_tool_execution sets status, exit_code,
-- summary and ended_at by id.
CREATE TABLE IF NOT EXISTS tool_executions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    tool_name   TEXT NOT NULL,
    command     TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    exit_code   INTEGER,
    summary     TEXT,
    output_file TEXT,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_tool_exec_session ON tool_executions(session_id);

-- audit_log -----------------------------------------------------------------
-- orchestration/handlers.py inserts level, category, message and details.
--
-- This is NOT the tamper-evident audit trail. That one is a hash-chained JSONL
-- file written by core/audit.py to NETREAPER_LOG_DIR/audit.jsonl, and it stays
-- there: a chain whose integrity depends on append-only ordering does not
-- belong in a table anything can UPDATE. This is the event log the orchestrator
-- writes for reporting.
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    level      TEXT NOT NULL,
    category   TEXT NOT NULL,
    message    TEXT NOT NULL,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- available_state -----------------------------------------------------------
-- The planner's per-target capability memo, made durable (issue #31). Records
-- that a capability was OBTAINED for a target so a later `resolve_chain` can
-- skip re-deriving it: crack a network once and the next `wifi auto` short-
-- circuits instead of re-running the chain. It stores the capability MARKER,
-- never the value behind it: a recovered key belongs in the encrypted loot
-- store, not here. chaining/state_cache.py is the only reader and writer.
--
-- session_id is a scoping column with the sentinel '-' for "no session", not a
-- foreign key: SQLite treats NULL as distinct in a UNIQUE constraint, so a
-- nullable column would let the ON CONFLICT upsert stack duplicates on every
-- run, and the sentinel cannot satisfy a REFERENCES sessions(id) with
-- foreign_keys ON. There is no runtime session plumbing to cascade from yet;
-- clearing is explicit, via state_cache.forget().
CREATE TABLE IF NOT EXISTS available_state (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL DEFAULT '-',
    target_type  TEXT NOT NULL,
    target       TEXT NOT NULL,
    capability   TEXT NOT NULL,
    metadata     TEXT NOT NULL DEFAULT '{}',
    recorded_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (session_id, target_type, target, capability)
);

CREATE INDEX IF NOT EXISTS idx_available_state_lookup
    ON available_state(session_id, target_type, target);
