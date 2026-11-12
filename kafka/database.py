"""Local scan history in SQLite.

Only parameterised SQL is used. Nothing sensitive is stored: no response bodies, cookie
values, credentials or query strings. ``findings_json`` holds the findings (which are
already sanitised and contain no secrets). Schema upgrades are applied automatically.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from kafka.config import database_path
from kafka.models import SEVERITY_ORDER, ScanResult
from kafka.util import format_utc

SCHEMA_VERSION = 2
_V1_COLUMNS = frozenset(
    {"id", "target", "started_at", "status_code", "tool_version", "findings_json"}
)

_CREATE_META = "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
_CREATE_SCANS = (
    "CREATE TABLE IF NOT EXISTS scans ("
    "id INTEGER PRIMARY KEY, "
    "target TEXT NOT NULL, "
    "started_at TEXT NOT NULL, "
    "status_code INTEGER, "
    "tool_version TEXT NOT NULL, "
    "findings_json TEXT NOT NULL, "
    "status TEXT NOT NULL DEFAULT 'completed')"
)
_ADD_STATUS = "ALTER TABLE scans ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"


class DatabaseError(Exception):
    """The history database could not be used. The message is safe to show."""


@dataclass(frozen=True)
class ScanRecord:
    """One row of scan history."""

    id: int
    target: str
    started_at: str
    status_code: int | None
    tool_version: str
    status: str
    counts: dict[str, int] | None  # None if the stored findings could not be read


def _count_findings(findings_json: str) -> dict[str, int] | None:
    try:
        items = json.loads(findings_json)
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for item in items:
            counts[item["severity"]] += 1
    except (ValueError, TypeError, KeyError):
        return None
    return counts


def _migrate(conn: sqlite3.Connection) -> None:
    """Create the schema, or upgrade a database created by an older KAFKA version."""
    conn.execute(_CREATE_META)
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = ?", ("schema_version",)
    ).fetchone()
    has_scans = (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = ? AND name = ?", ("table", "scans")
        ).fetchone()
        is not None
    )
    if row is not None:
        try:
            version = int(row[0])
        except ValueError as exc:
            raise DatabaseError("The history database has an unreadable schema version.") from exc
    else:
        version = 1 if has_scans else 0
    if version > SCHEMA_VERSION:
        raise DatabaseError(
            "The history database was created by a newer KAFKA version. Upgrade KAFKA to use it."
        )
    if not has_scans:
        conn.execute(_CREATE_SCANS)
    else:
        columns = {info[1] for info in conn.execute("PRAGMA table_info(scans)")}
        if not _V1_COLUMNS <= columns:
            raise DatabaseError("The history database has an unexpected structure.")
        if "status" not in columns:
            conn.execute(_ADD_STATUS)
    if version != SCHEMA_VERSION:
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
    conn.commit()


class Database:
    """Access to the local history database (created on first use)."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else database_path()

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=5.0)
        except (OSError, sqlite3.Error) as exc:
            raise DatabaseError("The history database could not be opened.") from exc
        try:
            _migrate(conn)
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise DatabaseError(f"History database error ({type(exc).__name__}).") from exc
        finally:
            conn.close()
        try:
            os.chmod(self.path, 0o600)  # best effort; a no-op on some platforms
        except OSError:
            pass

    def add_scan(self, result: ScanResult) -> int:
        """Store a scan (findings only) and return its row id."""
        payload = json.dumps([finding.to_dict() for finding in result.findings], ensure_ascii=False)
        with self._session() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (target, started_at, status_code, tool_version, "
                "findings_json, status) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.target,
                    format_utc(result.started_at),
                    result.status_code,
                    result.tool_version,
                    payload,
                    result.status,
                ),
            )
            return int(cursor.lastrowid or 0)

    def recent(self, limit: int = 20) -> list[ScanRecord]:
        """Most recent scans first."""
        limit = max(1, min(int(limit), 1000))
        with self._session() as conn:
            rows = conn.execute(
                "SELECT id, target, started_at, status_code, tool_version, findings_json, status "
                "FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            ScanRecord(
                id=row[0],
                target=row[1],
                started_at=row[2],
                status_code=row[3],
                tool_version=row[4],
                status=row[6],
                counts=_count_findings(row[5]),
            )
            for row in rows
        ]

    def count(self) -> int:
        with self._session() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
