# SPDX-License-Identifier: GPL-3.0-or-later
"""Five tables the code wrote to, and a schema file that did not exist.

`db/engine.py` is a complete async SQLite engine: WAL, a connection lock, and
an `initialize()` that reads `schema.sql` and executes it. The file was never
written, and the read was guarded:

    schema_path = Path(__file__).parent / "schema.sql"
    if schema_path.exists():
        await db.executescript(schema_path.read_text())

So `initialize()` created no tables, committed, and logged "Database
initialized at ...". Meanwhile three modules were already issuing statements
against five tables:

    sessions/manager.py        sessions, targets, tool_executions
    loot/storage.py            loot
    orchestration/handlers.py  audit_log

Every one of them would have failed with "no such table", at a distance from
the cause and long after the log line that said it had worked.

The schema is derived from those statements rather than designed, so these
tests check the derivation holds: the tables and columns the code writes must
be the ones the schema creates, and the check reads the real source so it
cannot drift when someone adds a column to an INSERT.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"
SCHEMA = SRC / "db" / "schema.sql"

# The modules that touch the database. Writers, plus export/manager.py, which is
# read-only but whose SELECTs went unchecked here for so long that one queried
# an audit_log.session_id / timestamp the schema never had, silently returning
# nothing. Its FROM-tables are covered now; it adds no INSERTs, so the write-set
# check below is unchanged.
CONSUMERS = (
    "sessions/manager.py",
    "loot/storage.py",
    "orchestration/handlers.py",
    "chaining/state_cache.py",
    "export/manager.py",
)

_INSERT = re.compile(r"INSERT\s+INTO\s+(\w+)\s*\(([^)]*)\)", re.I | re.S)
_FROM = re.compile(r"\bFROM\s+(\w+)", re.I)
_UPDATE = re.compile(r"\bUPDATE\s+(\w+)", re.I)


# The whole statement shape, not just the opening verb. Matching the verb
# anywhere pulled in docstrings; anchoring it still matched `"""Update session
# fields."""` and `"""Update a tool execution record."""`, which reported
# tables called `session` and `a`. A real UPDATE has a SET, a real SELECT has
# a FROM, and a docstring has neither.
_SQL_VERB = re.compile(
    r"^\s*("
    r"INSERT\s+INTO\s+\w+"
    r"|UPDATE\s+\w+\s+SET"
    r"|SELECT\b[\s\S]*?\bFROM\b"
    r"|DELETE\s+FROM\s+\w+"
    r")",
    re.I,
)


def _consumer_sql() -> str:
    """Only the SQL string literals, pulled with the AST.

    Scanning the raw source matched Python's own `from x import y` as a SQL
    FROM clause and reported `__future__` as a missing table. The strings are
    the only place SQL lives, so that is the only place to look.
    """
    import ast

    out: list[str] = []
    for rel in CONSUMERS:
        tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if _SQL_VERB.search(node.value):
                    out.append(node.value)
    return "\n".join(out)


def _schema_tables() -> dict[str, set[str]]:
    """table -> column names, parsed from the CREATE TABLE statements."""
    text = SCHEMA.read_text(encoding="utf-8")
    tables: dict[str, set[str]] = {}
    for m in re.finditer(
        r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\n\);", text, re.S
    ):
        name, body = m.group(1), m.group(2)
        cols = set()
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            if not line or line.startswith("--"):
                continue
            first = line.split()[0]
            if first.upper() in {"UNIQUE", "PRIMARY", "FOREIGN", "CHECK", "CONSTRAINT"}:
                continue
            cols.add(first)
        tables[name] = cols
    return tables


def test_the_schema_file_exists_at_all():
    """The whole defect in one assertion."""
    assert SCHEMA.exists(), f"{SCHEMA} is missing; initialize() creates no tables"
    assert SCHEMA.stat().st_size > 500, "schema is too small to define five tables"


def test_every_table_the_code_writes_to_is_created():
    sql = _consumer_sql()
    referenced = {m.group(1).lower() for m in _INSERT.finditer(sql)}
    referenced |= {m.group(1).lower() for m in _FROM.finditer(sql)}
    referenced |= {m.group(1).lower() for m in _UPDATE.finditer(sql)}
    # SET is matched by the UPDATE pattern in "ON CONFLICT ... DO UPDATE SET".
    referenced.discard("set")

    created = set(_schema_tables())
    missing = sorted(referenced - created)
    assert not missing, (
        "the code writes to tables the schema does not create:\n  "
        + "\n  ".join(missing)
    )


def test_every_inserted_column_exists():
    """Adding a column to an INSERT without adding it here must fail."""
    tables = _schema_tables()
    problems = []
    for m in _INSERT.finditer(_consumer_sql()):
        table = m.group(1).lower()
        columns = [c.strip().lstrip(":") for c in m.group(2).split(",") if c.strip()]
        for col in columns:
            if not col.isidentifier():
                continue
            if col not in tables.get(table, set()):
                problems.append(f"{table}.{col}")
    assert not problems, "columns written but not defined:\n  " + "\n  ".join(sorted(problems))


def test_the_targets_upsert_has_the_unique_constraint_it_needs():
    """add_target uses ON CONFLICT(session_id, target_type, value).

    Without a matching UNIQUE constraint SQLite raises rather than upserting,
    so the constraint is load-bearing, not decoration.
    """
    text = SCHEMA.read_text(encoding="utf-8")
    assert re.search(
        r"UNIQUE\s*\(\s*session_id\s*,\s*target_type\s*,\s*value\s*\)", text
    ), "targets needs UNIQUE(session_id, target_type, value) for its ON CONFLICT"


def test_initialize_creates_the_tables_for_real(tmp_path):
    """Parsing the file proves the text. This proves SQLite accepts it."""
    from netreaper.db.engine import DatabaseEngine

    async def run() -> set[str]:
        engine = DatabaseEngine(tmp_path / "t.db")
        try:
            await engine.initialize()
            async with engine.connection() as db:
                cur = await db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                return {r[0] for r in await cur.fetchall()}
        finally:
            await engine.close()

    tables = asyncio.run(run())
    for expected in ("sessions", "targets", "loot", "tool_executions", "audit_log"):
        assert expected in tables, f"{expected} was not created"


def test_a_missing_schema_is_loud_rather_than_silent(tmp_path, monkeypatch):
    """The guard that would have caught this.

    `if schema_path.exists()` meant a missing schema produced an empty database
    and a log line claiming success. The failure then surfaced in whichever
    consumer queried first, as "no such table", far from the cause.
    """
    from netreaper.db import engine as engine_mod

    async def run() -> None:
        engine = engine_mod.DatabaseEngine(tmp_path / "t.db")
        try:
            await engine.initialize()
        finally:
            await engine.close()

    monkeypatch.setattr(engine_mod, "__file__", str(tmp_path / "nowhere" / "engine.py"))
    with pytest.raises(FileNotFoundError, match="schema"):
        asyncio.run(run())


def test_the_sql_extraction_is_not_vacuous():
    """If the filter stops finding statements, every check above goes green.

    Tightening it is how that happens. The first version matched Python's own
    `from x import y`; the second still matched docstrings beginning "Update".
    A third that matched nothing at all would have looked like success.
    """
    sql = _consumer_sql()
    tables = {m.group(1).lower() for m in _INSERT.finditer(sql)}
    assert tables == {
        "sessions",
        "targets",
        "loot",
        "tool_executions",
        "audit_log",
        "available_state",
    }, f"expected the six known writes, extracted {sorted(tables)}"
