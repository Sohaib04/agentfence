import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from app.audit.models import AuditEvent, TaskRecord


class AuditStore:
    """Thread-safe SQLite store for durable task states and immutable audit records."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        self._shared_conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
            self._shared_conn.execute("PRAGMA foreign_keys = ON;")
        else:
            parent = Path(self.db_path).parent
            parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a database connection within an active transaction and manage closing."""
        with self._lock:
            if self._shared_conn is not None:
                with self._shared_conn:
                    yield self._shared_conn
            else:
                conn = sqlite3.connect(self.db_path, timeout=30.0)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA journal_mode = WAL;")
                try:
                    with conn:
                        yield conn
                finally:
                    conn.close()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    arguments TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    result TEXT,
                    error TEXT,
                    duration_seconds REAL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_task ON audit_events(task_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(timestamp);"
            )
            conn.commit()

    def save_task(self, task: TaskRecord) -> None:
        """Insert or replace a task record."""
        args_json = json.dumps(task.arguments)
        res_json = json.dumps(task.result) if task.result is not None else None

        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tasks (
                    task_id, created_at, updated_at, tool, arguments,
                    decision, reason, policy_version, status,
                    exit_code, result, error, duration_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    task.task_id,
                    task.created_at,
                    task.updated_at,
                    task.tool,
                    args_json,
                    task.decision,
                    task.reason,
                    task.policy_version,
                    task.status,
                    task.exit_code,
                    res_json,
                    task.error,
                    task.duration_seconds,
                ),
            )
            conn.commit()

    def get_task(self, task_id: str) -> TaskRecord | None:
        """Retrieve a task record by ID."""
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?;", (task_id,)).fetchone()

            if not row:
                return None

            return self._row_to_task(row)

    def list_tasks(self, limit: int = 50, offset: int = 0) -> list[TaskRecord]:
        """List tasks ordered by created_at descending."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?;",
                (limit, offset),
            ).fetchall()

            return [self._row_to_task(r) for r in rows]

    def record_event(self, event: AuditEvent) -> int:
        """Persist an audit event and return its generated ID."""
        details_json = json.dumps(event.details)

        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_events (
                    timestamp, task_id, event_type, tool, decision, reason, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.timestamp,
                    event.task_id,
                    event.event_type,
                    event.tool,
                    event.decision,
                    event.reason,
                    details_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def list_events(self, limit: int = 50, offset: int = 0) -> list[AuditEvent]:
        """List audit events ordered by ID descending."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?;",
                (limit, offset),
            ).fetchall()

            events: list[AuditEvent] = []
            for r in rows:
                details = json.loads(r["details"]) if r["details"] else {}
                events.append(
                    AuditEvent(
                        id=r["id"],
                        timestamp=r["timestamp"],
                        task_id=r["task_id"],
                        event_type=r["event_type"],
                        tool=r["tool"],
                        decision=r["decision"],
                        reason=r["reason"],
                        details=details,
                    )
                )
            return events

    def _row_to_task(self, row: sqlite3.Row) -> TaskRecord:
        """Deserialize a SQLite row into a TaskRecord."""
        args_data: dict[str, Any] = json.loads(row["arguments"]) if row["arguments"] else {}
        res_data: dict[str, Any] | None = json.loads(row["result"]) if row["result"] else None

        return TaskRecord(
            task_id=row["task_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            tool=row["tool"],
            arguments=args_data,
            decision=row["decision"],
            reason=row["reason"],
            policy_version=row["policy_version"],
            status=row["status"],
            exit_code=row["exit_code"],
            result=res_data,
            error=row["error"],
            duration_seconds=row["duration_seconds"],
        )
