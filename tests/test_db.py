"""SQLite schema tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from xentry.db import MIGRATIONS, DatabaseError, init_db, migrate

# The newest migration on disk. Hard-coding this number meant every
# migration broke six unrelated tests, which teaches editing the
# assertion instead of reading it.
LATEST_MIGRATION = max(int(p.name.split("_", 1)[0]) for p in MIGRATIONS.glob("*.sql"))


def test_migration_creates_schema(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "xentry.db")
    try:
        version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        assert version == LATEST_MIGRATION
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"jobs", "attempts", "job_steps", "nonces", "link_checks", "job_outcomes"} <= tables
        assert migrate(conn) == LATEST_MIGRATION
    finally:
        conn.close()


def test_foreign_keys_and_checks_are_enforced(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "xentry.db")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO attempts(id, job_id, attempt_no, attempt_dir) VALUES (?,?,?,?)",
                ("a1", "missing-job", 0, "/tmp"),
            )
        conn.execute(
            "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir) VALUES (?,?,?,?,?)",
            ("j1", "php2shell", "https://example.com/poc", "now", "/tmp/j1"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir, outcome) "
                "VALUES (?,?,?,?,?,?)",
                ("j2", "php2shell", "https://example.com/poc", "now", "/tmp/j2", "bad"),
            )
    finally:
        conn.close()


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "xentry.db")
    conn.execute("CREATE TABLE schema_version(version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version(version) VALUES (99)")
    conn.commit()
    with pytest.raises(DatabaseError):
        migrate(conn)
    conn.close()
