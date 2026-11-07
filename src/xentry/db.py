"""SQLite index and migration runner."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations"
MIGRATION_RE = re.compile(r"^(\d+)_.*\.sql$")


class DatabaseError(RuntimeError):
    """The database could not be opened or migrated."""


def connect(path: str | Path) -> sqlite3.Connection:
    target = str(path)
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def _migrations(migrations_dir: Path) -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for path in migrations_dir.glob("*.sql"):
        match = MIGRATION_RE.match(path.name)
        if not match:
            continue
        found.append((int(match.group(1)), path))
    return sorted(found)


def _current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if row is None:
        return 0
    current = conn.execute("SELECT MAX(version) AS version FROM schema_version").fetchone()
    if current is None:
        return 0
    try:
        value = current["version"]
    except (TypeError, IndexError):
        value = current[0]
    return int(value or 0)


def migrate(conn: sqlite3.Connection, migrations_dir: Path = MIGRATIONS) -> int:
    migrations = _migrations(migrations_dir)
    current = _current_version(conn)
    if migrations and current > migrations[-1][0]:
        raise DatabaseError(f"database schema is newer than migrations: {current}")
    applied = current
    for version, path in migrations:
        if version <= current:
            continue
        sql = path.read_text(encoding="utf-8")
        try:
            conn.executescript(sql)
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise DatabaseError(f"migration failed: {path.name}: {exc}") from exc
        applied = max(applied, version)
    return applied


def init_db(path: str | Path, migrations_dir: Path = MIGRATIONS) -> sqlite3.Connection:
    conn = connect(path)
    migrate(conn, migrations_dir)
    return conn
