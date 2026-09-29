"""Session manager for NETREAPER."""

from __future__ import annotations

import uuid
from datetime import datetime
from functools import lru_cache
from typing import Any

from netreaper.core.logging import get_logger
from netreaper.db.engine import get_db
from netreaper.orchestration.events import Events, event_bus
from netreaper.sessions.models import (
    Session,
    SessionConfig,
    SessionMetadata,
    SessionStatus,
    SessionSummary,
)

logger = get_logger(__name__)

# How many times update() re-reads and retries when a concurrent writer moved
# the row's updated_at between our read and our write.
_MAX_UPDATE_RETRIES = 3


class SessionManager:
    """Manages session lifecycle and persistence."""

    def __init__(self) -> None:
        self._current_session: Session | None = None

    @property
    def current(self) -> Session | None:
        """Get current active session."""
        return self._current_session

    async def create(
        self,
        name: str,
        config: SessionConfig | None = None,
        metadata: SessionMetadata | None = None,
    ) -> Session:
        """Create a new session."""
        session_id = f"sess_{uuid.uuid4().hex[:12]}"

        session = Session(
            id=session_id,
            name=name,
            status=SessionStatus.ACTIVE,
            config=config or SessionConfig(),
            metadata=metadata or SessionMetadata(),
        )

        db = await get_db()
        db_dict = session.to_db_dict()

        await db.execute(
            """
            INSERT INTO sessions (id, name, status, workflow_state, config, metadata)
            VALUES (:id, :name, :status, :workflow_state, :config, :metadata)
            """,
            db_dict,
        )

        self._current_session = session

        event_bus.emit(Events.SESSION_STARTED, {
            "session_id": session_id,
            "name": name,
        })

        logger.info("Created session: %s (%s)", name, session_id)
        return session

    async def get(self, session_id: str) -> Session | None:
        """Get session by ID."""
        db = await get_db()
        row = await db.fetch_one(
            "SELECT * FROM sessions WHERE id = ?",
            (session_id,),
        )

        if not row:
            return None

        session = Session.from_db_row(row)
        session.summary = await self._get_summary(session_id)
        return session

    async def list(
        self,
        status: SessionStatus | None = None,
        limit: int = 20,
    ) -> list[Session]:
        """List sessions, optionally filtered by status."""
        db = await get_db()

        if status:
            rows = await db.fetch_all(
                """
                SELECT * FROM sessions
                WHERE status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (status.value, limit),
            )
        else:
            rows = await db.fetch_all(
                """
                SELECT * FROM sessions
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            )

        sessions = []
        for row in rows:
            session = Session.from_db_row(row)
            session.summary = await self._get_summary(session.id)
            sessions.append(session)

        return sessions

    async def update(
        self,
        session_id: str,
        name: str | None = None,
        status: SessionStatus | None = None,
        workflow_state: str | None = None,
        config: SessionConfig | None = None,
        metadata: SessionMetadata | None = None,
    ) -> Session | None:
        """Update session fields.

        Read-modify-write with optimistic concurrency: the write only lands on
        the row we read (``WHERE ... AND updated_at = :prev_updated_at``). If a
        concurrent writer changed the row in between, ``rowcount`` is 0; we
        re-read and re-apply this call's fields onto the fresh row and retry,
        rather than a blind ``WHERE id`` that would silently clobber the other
        writer's change and could leave ``_current_session`` disagreeing with the
        row on disk.
        """
        db = await get_db()

        for _attempt in range(_MAX_UPDATE_RETRIES):
            session = await self.get(session_id)
            if not session:
                return None

            # The optimistic baseline is the EXACT stored string, read raw, not
            # session.updated_at.isoformat(): a row written by the schema default
            # (CURRENT_TIMESTAMP, space-separated) does not round-trip to the same
            # text as isoformat() ('T'-separated), so a reformatted value would
            # never match the WHERE clause on the first update after create.
            row = await db.fetch_one(
                "SELECT updated_at FROM sessions WHERE id = :id", {"id": session_id}
            )
            if row is None:
                return None
            prev_updated_at = row["updated_at"]

            if name is not None:
                session.name = name
            if status is not None:
                session.status = status
                if status in (SessionStatus.COMPLETED, SessionStatus.FAILED):
                    session.ended_at = datetime.now()
            if workflow_state is not None:
                session.workflow_state = workflow_state
            if config is not None:
                session.config = config
            if metadata is not None:
                session.metadata = metadata

            session.updated_at = datetime.now()

            db_dict = session.to_db_dict()
            db_dict["prev_updated_at"] = prev_updated_at

            cursor = await db.execute(
                """
                UPDATE sessions
                SET name = :name, status = :status, workflow_state = :workflow_state,
                    config = :config, metadata = :metadata, updated_at = :updated_at,
                    ended_at = :ended_at
                WHERE id = :id AND updated_at = :prev_updated_at
                """,
                db_dict,
            )

            if cursor.rowcount and cursor.rowcount > 0:
                if self._current_session and self._current_session.id == session_id:
                    self._current_session = session
                event_bus.emit(Events.SESSION_UPDATED, {
                    "session_id": session_id,
                    "status": session.status,
                })
                return session
            # rowcount 0: a concurrent writer moved updated_at. Re-read and retry.

        logger.warning(
            "session %s update lost %d concurrency races; not applied",
            session_id, _MAX_UPDATE_RETRIES,
        )
        return await self.get(session_id)

    async def pause(self, session_id: str) -> Session | None:
        """Pause a session."""
        return await self.update(session_id, status=SessionStatus.PAUSED)

    async def resume(self, session_id: str) -> Session | None:
        """Resume a paused session."""
        session = await self.update(session_id, status=SessionStatus.ACTIVE)
        if session:
            self._current_session = session
        return session

    async def complete(self, session_id: str) -> Session | None:
        """Mark session as completed."""
        session = await self.update(session_id, status=SessionStatus.COMPLETED)
        if self._current_session and self._current_session.id == session_id:
            self._current_session = None
        return session

    async def fail(self, session_id: str) -> Session | None:
        """Mark session as failed."""
        session = await self.update(session_id, status=SessionStatus.FAILED)
        if self._current_session and self._current_session.id == session_id:
            self._current_session = None
        return session

    async def delete(self, session_id: str) -> bool:
        """Delete a session and all related data."""
        db = await get_db()

        # Cascade delete handled by foreign keys
        cursor = await db.execute(
            "DELETE FROM sessions WHERE id = ?",
            (session_id,),
        )

        if self._current_session and self._current_session.id == session_id:
            self._current_session = None

        deleted = cursor.rowcount > 0
        if deleted:
            logger.info("Deleted session: %s", session_id)

        return deleted

    @staticmethod
    async def add_target(
                session_id: str,
        target_type: str,
        value: str,
        metadata: dict[str, Any] | None = None,
    ) -> int | None:
        """Add a target to a session."""
        import json

        db = await get_db()

        try:
            cursor = await db.execute(
                """
                INSERT INTO targets (session_id, target_type, value, metadata)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id, target_type, value) DO UPDATE SET
                    last_scanned = CURRENT_TIMESTAMP
                """,
                (session_id, target_type, value, json.dumps(metadata or {})),
            )
            return cursor.lastrowid
        except Exception as e:
            logger.warning("Failed to add target: %s", e)
            return None

    @staticmethod
    async def log_tool_execution(
                session_id: str,
        tool_name: str,
        command: str,
        status: str = "running",
        exit_code: int | None = None,
        summary: str | None = None,
        output_file: str | None = None,
    ) -> int | None:
        """Log a tool execution."""
        db = await get_db()

        try:
            cursor = await db.execute(
                """
                INSERT INTO tool_executions
                (session_id, tool_name, command, status, exit_code, summary, output_file)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, tool_name, command, status, exit_code, summary, output_file),
            )
            return cursor.lastrowid
        except Exception as e:
            logger.warning("Failed to log tool execution: %s", e)
            return None

    @staticmethod
    async def update_tool_execution(
                execution_id: int,
        status: str,
        exit_code: int | None = None,
        summary: str | None = None,
    ) -> None:
        """Update a tool execution record."""
        db = await get_db()

        await db.execute(
            """
            UPDATE tool_executions
            SET status = ?, exit_code = ?, summary = ?, ended_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, exit_code, summary, execution_id),
        )

    @staticmethod
    async def _get_summary(session_id: str) -> SessionSummary:
        """Get summary statistics for a session."""
        db = await get_db()

        # Target count
        target_row = await db.fetch_one(
            "SELECT COUNT(*) as count FROM targets WHERE session_id = ?",
            (session_id,),
        )

        # Tool executions
        exec_row = await db.fetch_one(
            "SELECT COUNT(*) as count FROM tool_executions WHERE session_id = ?",
            (session_id,),
        )

        # Loot count
        loot_row = await db.fetch_one(
            "SELECT COUNT(*) as count FROM loot WHERE session_id = ?",
            (session_id,),
        )

        # Credentials specifically
        cred_row = await db.fetch_one(
            "SELECT COUNT(*) as count FROM loot WHERE session_id = ? AND loot_type = 'credential'",
            (session_id,),
        )

        return SessionSummary(
            target_count=target_row["count"] if target_row else 0,
            tool_executions=exec_row["count"] if exec_row else 0,
            loot_count=loot_row["count"] if loot_row else 0,
            credentials_found=cred_row["count"] if cred_row else 0,
        )

    async def get_recent(self, limit: int = 5) -> list[Session]:
        """Get most recent sessions."""
        return await self.list(limit=limit)

    async def get_active(self) -> list[Session]:
        """Get all active sessions."""
        return await self.list(status=SessionStatus.ACTIVE)

    def set_current(self, session: Session) -> None:
        """Set the current active session."""
        self._current_session = session

    def clear_current(self) -> None:
        """Clear the current session."""
        self._current_session = None


# Singleton instance
@lru_cache(maxsize=1)
def get_session_manager() -> SessionManager:
    """Get session manager instance.

    See get_system_info in detection/distro.py: same lazy singleton, same
    reason for lru_cache over a module-level `global`, and cache_clear() is a
    seam rather than a private name to rebind.
    """
    return SessionManager()
