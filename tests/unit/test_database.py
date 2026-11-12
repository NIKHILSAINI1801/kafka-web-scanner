import json
import os
import sqlite3
import sys

import pytest

from kafka.database import SCHEMA_VERSION, Database, DatabaseError
from tests.helpers import make_finding, make_result

LEGACY_V1_DDL = (
    "CREATE TABLE scans(id INTEGER PRIMARY KEY, target TEXT NOT NULL, started_at TEXT NOT NULL, "
    "status_code INTEGER, tool_version TEXT NOT NULL, findings_json TEXT NOT NULL)"
)


def test_missing_database_is_created_on_first_use(tmp_path):
    path = tmp_path / "nested" / "dir" / "history.db"
    assert not path.exists()
    db = Database(path)
    assert db.recent() == []
    assert path.exists()


def test_add_and_list_most_recent_first(tmp_path):
    db = Database(tmp_path / "h.db")
    first = db.add_scan(make_result([make_finding(severity="HIGH")], target="https://a.test/"))
    second = db.add_scan(
        make_result([make_finding(severity="LOW")], target="https://b.test/", status_code=404)
    )
    records = db.recent()
    assert [r.id for r in records] == [second, first]
    assert records[0].target == "https://b.test/" and records[0].status_code == 404
    assert records[1].counts["HIGH"] == 1 and records[0].counts["LOW"] == 1
    assert db.count() == 2


def test_recent_respects_and_clamps_limit(tmp_path):
    db = Database(tmp_path / "h.db")
    for _ in range(5):
        db.add_scan(make_result())
    assert len(db.recent(2)) == 2
    assert len(db.recent(0)) == 1  # clamped to at least 1
    assert len(db.recent(10_000)) == 5


def test_blocked_scan_without_status_code_is_stored(tmp_path):
    db = Database(tmp_path / "h.db")
    db.add_scan(make_result(status="blocked", status_code=None))
    record = db.recent()[0]
    assert record.status == "blocked" and record.status_code is None


def test_sql_injection_in_target_is_stored_literally(tmp_path):
    db = Database(tmp_path / "h.db")
    nasty = "https://x.test/'); DROP TABLE scans;--"
    db.add_scan(make_result(target=nasty))
    db.add_scan(make_result())
    assert db.count() == 2
    assert any(r.target == nasty for r in db.recent())


def test_findings_are_stored_as_json_without_extra_data(tmp_path):
    db = Database(tmp_path / "h.db")
    db.add_scan(make_result([make_finding(evidence="Server: nginx")]))
    with sqlite3.connect(tmp_path / "h.db") as conn:
        (payload,) = conn.execute("SELECT findings_json FROM scans").fetchone()
    stored = json.loads(payload)
    assert stored[0]["evidence"] == "Server: nginx"
    assert set(stored[0]) == {
        "id",
        "scanner",
        "title",
        "severity",
        "confidence",
        "description",
        "evidence",
        "recommendation",
    }


def test_legacy_v1_database_is_upgraded_in_place(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute(LEGACY_V1_DDL)
        conn.execute(
            "INSERT INTO scans (target, started_at, status_code, tool_version, findings_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("https://old.test/", "2025-01-01T00:00:00Z", 200, "0.9.0", "[]"),
        )
    db = Database(path)
    records = db.recent()
    assert len(records) == 1 and records[0].target == "https://old.test/"
    assert records[0].status == "completed"  # default for pre-upgrade rows
    db.add_scan(make_result(status="partial"))
    assert db.recent()[0].status == "partial"
    with sqlite3.connect(path) as conn:
        (version,) = conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
    assert version == str(SCHEMA_VERSION)


def test_database_from_a_newer_kafka_is_refused(tmp_path):
    path = tmp_path / "new.db"
    Database(path).recent()
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
            (str(SCHEMA_VERSION + 1),),
        )
    with pytest.raises(DatabaseError, match="newer"):
        Database(path).recent()


def test_unexpected_table_structure_is_refused(tmp_path):
    path = tmp_path / "odd.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, something TEXT)")
    with pytest.raises(DatabaseError, match="unexpected structure"):
        Database(path).recent()


def test_corrupt_database_file_gives_a_clean_error(tmp_path):
    path = tmp_path / "bad.db"
    path.write_bytes(b"this is definitely not an sqlite database" * 50)
    with pytest.raises(DatabaseError) as excinfo:
        Database(path).recent()
    assert "Traceback" not in str(excinfo.value)


def test_unreadable_findings_json_does_not_break_history(tmp_path):
    path = tmp_path / "h.db"
    db = Database(path)
    db.add_scan(make_result())
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE scans SET findings_json = ?", ("{not json",))
    assert db.recent()[0].counts is None


def test_unwritable_location_gives_a_clean_error(tmp_path):
    blocker = tmp_path / "a_file"
    blocker.write_text("x")
    with pytest.raises(DatabaseError):
        Database(blocker / "sub" / "h.db").recent()


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permissions only")
def test_database_file_is_private_to_the_user(tmp_path):
    path = tmp_path / "h.db"
    Database(path).add_scan(make_result())
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_default_path_follows_kafka_home(tmp_path):
    db = Database()
    assert str(db.path).startswith(str(tmp_path))
    assert db.path.name == "history.db"
