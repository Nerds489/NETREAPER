"""Async SQLite database engine."""
import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

from netreaper.core.constants import DB_PATH
from netreaper.core.logging import get_logger

logger = get_logger(__name__)


class DatabaseEngine:
    """Async SQLite database engine with connection pooling."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._connection: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize database and run migrations."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        async with self.connection() as db:
            # Enable WAL mode
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA synchronous=NORMAL")
            await db.execute("PRAGMA foreign_keys=ON")

            # Create schema.
            #
            # This used to be guarded by `if schema_path.exists()`, and the file
            # did not exist. initialize() therefore created NO tables and logged
            # "Database initialized" anyway, while sessions/manager.py,
            # loot/storage.py and orchestration/handlers.py were all already
            # issuing statements against five tables that were never there.
            # A missing schema is not a condition to shrug at: without it every
            # consumer fails later, further away, with "no such table".
            schema_path = Path(__file__).parent / "schema.sql"
            if not schema_path.exists():
                raise FileNotFoundError(
                    f"database schema missing at {schema_path}. The engine "
                    f"cannot create the sessions, targets, loot, "
                    f"tool_executions or audit_log tables without it."
                )
            await db.executescript(schema_path.read_text())

            await db.commit()
            logger.info('Database initialized at %s', self.db_path)

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[aiosqlite.Connection]:
        """Get database connection."""
        async with self._lock:
            if self._connection is None:
                self._connection = await aiosqlite.connect(
                    self.db_path,
                    timeout=30.0,
                )
                self._connection.row_factory = aiosqlite.Row

            yield self._connection

    async def execute(
        self, query: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> aiosqlite.Cursor:
        """Execute a query."""
        async with self.connection() as db:
            cursor = await db.execute(query, params)
            await db.commit()
            return cursor

    async def fetch_one(
        self, query: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> dict[str, Any] | None:
        """Fetch single row as dict."""
        async with self.connection() as db:
            cursor = await db.execute(query, params)
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def fetch_all(
        self, query: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> list[dict[str, Any]]:
        """Fetch all rows as list of dicts."""
        async with self.connection() as db:
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None


# Singleton instance
_db_engine: DatabaseEngine | None = None


async def get_db() -> DatabaseEngine:
    """Get database engine instance."""
    global _db_engine
    if _db_engine is None:
        _db_engine = DatabaseEngine()
        await _db_engine.initialize()
    return _db_engine
