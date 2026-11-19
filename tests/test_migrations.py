"""Migration, backup, and newer-schema tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from xentry.db import MIGRATIONS, DatabaseError, init_db, migrate

# The newest migration on disk. Hard-coding this number meant every
# migration broke six unrelated tests, which teaches editing the
# assertion instead of reading it.
LATEST_MIGRATION = max(int(p.name.split("_", 1)[0]) for p in MIGRATIONS.glob("*.sql"))


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == LATEST_MIGRATION
        assert migrate(conn) == LATEST_MIGRATION
    finally:
        conn.close()
    reopened = sqlite3.connect(db_path)
    try:
        assert reopened.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == LATEST_MIGRATION
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


def test_artifact_kinds_migration_preserves_rows(tmp_path: Path) -> None:
    """002 rebuilds artifacts; existing rows survive and new kinds are allowed."""
    db_path = tmp_path / "xentry.db"
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    only_v1 = tmp_path / "m1"
    only_v1.mkdir()
    (only_v1 / "001_initial.sql").write_text(
        (migrations / "001_initial.sql").read_text(encoding="utf-8"), encoding="utf-8"
    )

    conn = init_db(db_path, migrations_dir=only_v1)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 1
        conn.execute(
            "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir) VALUES (?,?,?,?,?)",
            ("job-1", "php2shell", "https://example.com/poc", "now", "/tmp/job-1"),
        )
        conn.execute(
            "INSERT INTO attempts(id, job_id, attempt_no, attempt_dir, started_at) "
            "VALUES (?,?,?,?,?)",
            ("att-1", "job-1", 0, "/tmp/job-1/attempt-0", "now"),
        )
        conn.execute(
            "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
            "VALUES (?,?,?,?,?,?,?)",
            ("art-1", "job-1", "att-1", "evidence", "/tmp/cve.html", "a" * 64, 11),
        )
        conn.commit()
        # the old schema refuses the new kinds
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
                "VALUES (?,?,?,?,?,?,?)",
                ("art-2", "job-1", "att-1", "held_vms", "/tmp/held.json", "b" * 64, 2),
            )
        conn.rollback()
    finally:
        conn.close()

    upgraded = init_db(db_path, migrations_dir=migrations)
    try:
        assert upgraded.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == LATEST_MIGRATION
        row = upgraded.execute("SELECT * FROM artifacts WHERE id='art-1'").fetchone()
        assert row is not None
        assert row["kind"] == "evidence"
        assert row["sha256"] == "a" * 64
        assert row["bytes"] == 11
        for kind in (
            "held_vms",
            "setup_script",
            "llm_extract_prompt",
            "llm_extract_response",
            "llm_validate_prompt",
            "llm_validate_response",
        ):
            upgraded.execute(
                "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
                "VALUES (?,?,?,?,?,?,?)",
                (f"new-{kind}", "job-1", "att-1", kind, f"/tmp/{kind}", "c" * 64, 1),
            )
        upgraded.commit()
        # and still refuses a kind nobody declared
        with pytest.raises(sqlite3.IntegrityError):
            upgraded.execute(
                "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
                "VALUES (?,?,?,?,?,?,?)",
                ("bogus", "job-1", "att-1", "whatever", "/tmp/x", "d" * 64, 1),
            )
        # the index came back with the table
        names = {
            str(r["name"])
            for r in upgraded.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='artifacts'"
            ).fetchall()
        }
        assert "idx_artifacts_job" in names
    finally:
        upgraded.close()


def test_setup_script_kind_requires_migration_003(tmp_path: Path) -> None:
    """The provisioning script is evidence only from 003 onward."""
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    upto_v2 = tmp_path / "m2"
    upto_v2.mkdir()
    for name in ("001_initial.sql", "002_artifact_kinds.sql"):
        (upto_v2 / name).write_text(
            (migrations / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path, migrations_dir=upto_v2)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 2
        conn.execute(
            "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir) VALUES (?,?,?,?,?)",
            ("job-s", "php2shell", "https://example.com/poc", "now", "/tmp/job-s"),
        )
        conn.execute(
            "INSERT INTO attempts(id, job_id, attempt_no, attempt_dir, started_at) "
            "VALUES (?,?,?,?,?)",
            ("att-s", "job-s", 0, "/tmp/job-s/attempt-0", "now"),
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
                "VALUES (?,?,?,?,?,?,?)",
                ("a-s", "job-s", "att-s", "setup_script", "/tmp/setup.sh", "e" * 64, 3),
            )
        conn.rollback()
    finally:
        conn.close()

    upgraded = init_db(db_path, migrations_dir=migrations)
    try:
        assert upgraded.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == LATEST_MIGRATION
        upgraded.execute(
            "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
            "VALUES (?,?,?,?,?,?,?)",
            ("a-s", "job-s", "att-s", "setup_script", "/tmp/setup.sh", "e" * 64, 3),
        )
        upgraded.commit()
    finally:
        upgraded.close()
