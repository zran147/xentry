"""Migration, backup, and newer-schema tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from xentry.db import DatabaseError, init_db, migrate


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
        assert migrate(conn) == 1
    finally:
        conn.close()
    reopened = sqlite3.connect(db_path)
    try:
        assert reopened.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
    finally:
        reopened.close()


def test_backup_restore_preserves_jobs(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    conn.execute(
        "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir) VALUES (?,?,?,?,?)",
        ("job-1", "php2shell", "https://example.com/poc", "now", "/tmp/job-1"),
    )
    conn.commit()
    backup_path = tmp_path / "backup.db"
    backup = sqlite3.connect(backup_path)
    try:
        conn.backup(backup)
    finally:
        backup.close()
        conn.close()
    restored = sqlite3.connect(backup_path)
    try:
        row = restored.execute("SELECT target_id FROM jobs WHERE id='job-1'").fetchone()
        assert row == ("php2shell",)
    finally:
        restored.close()


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "xentry.db")
    conn.execute("CREATE TABLE schema_version(version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version(version) VALUES (99)")
    conn.commit()
    with pytest.raises(DatabaseError):
        migrate(conn)
    conn.close()
