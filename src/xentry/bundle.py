"""Deterministic audit bundle for a finished or failed job.

The bundle is a reconstruction from the SQLite index plus the append-only
attempt event journals. It carries hashes, metadata, and journal records only:
artifact bytes stay in the job directory, and the nonce value is never written
to the index or the journal, so it cannot appear here.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from xentry import events

FORMAT = "xentry-audit-bundle/1"


def _rows(conn: sqlite3.Connection, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(query, params).fetchall()]


def _relative_dir(value: str, job_id: str) -> str:
    path = Path(value)
    parts = path.parts
    for index, part in enumerate(parts):
        if part == "jobs" and index + 1 < len(parts) and parts[index + 1] == job_id:
            return str(Path(*parts[index + 2 :])) if index + 2 < len(parts) else "."
    return path.name


def build_bundle(conn: sqlite3.Connection, job_id: str) -> dict[str, Any]:
    job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if job is None:
        raise KeyError(job_id)
    job_row = dict(job)
    job_row["state"] = job_row.get("outcome") or (
        "running" if job_row.get("started_at") else "queued"
    )
    job_row["attempt_dir"] = _relative_dir(str(job_row["attempt_dir"]), job_id)
    check = None
    if job_row.get("check_id"):
        check_row = conn.execute(
            "SELECT * FROM link_checks WHERE check_id=?", (job_row["check_id"],)
        ).fetchone()
        check = dict(check_row) if check_row is not None else None
    artifacts = _rows(
        conn,
        "SELECT id, attempt_id, kind, path, sha256, bytes FROM artifacts "
        "WHERE job_id=? ORDER BY rowid",
        (job_id,),
    )
    for artifact in artifacts:
        artifact["name"] = Path(str(artifact.pop("path"))).name
    attempts = _rows(
        conn,
        "SELECT id, attempt_no, attempt_dir, started_at, finished_at, failure_code, "
        "previous_attempt_id FROM attempts WHERE job_id=? ORDER BY attempt_no",
        (job_id,),
    )
    journal: list[dict[str, Any]] = []
    for attempt in attempts:
        for event in events.read(Path(str(attempt["attempt_dir"])) / "events.jsonl"):
            journal.append({"attempt_id": attempt["id"], **event})
    payload: dict[str, Any] = {
        "format": FORMAT,
        "job": job_row,
        "check": check,
        "attempts": attempts,
        "events": journal,
        "steps": _rows(
            conn,
            "SELECT seq, name, step_id, state, reason_code, started_at, finished_at "
            "FROM job_steps WHERE job_id=? ORDER BY seq, rowid",
            (job_id,),
        ),
        "validations": _rows(
            conn,
            "SELECT id, attempt_id, target_id, authority, validator_model, "
            "validator_prompt_hash, verdict, reason_code, nonce_id, "
            "runner_nonce_observed, null_actor_observed_nonce, evidence_json, "
            "evidence_sha256, ts FROM validations WHERE job_id=? ORDER BY ts, rowid",
            (job_id,),
        ),
        "outcomes": _rows(
            conn,
            "SELECT id, attempt_id, outcome, verdict, authority, reason_code, ts "
            "FROM job_outcomes WHERE job_id=? ORDER BY ts, rowid",
            (job_id,),
        ),
        "nonces": _rows(
            conn,
            "SELECT nonce_id, phase, sha256, path, owner, mode, created_at "
            "FROM nonces WHERE job_id=? ORDER BY created_at, rowid",
            (job_id,),
        ),
        "artifacts": artifacts,
        "broker_calls": _rows(
            conn,
            "SELECT seq, verb, params_sha256, started_at, finished_at, status, "
            "result_path, result_sha256 FROM broker_calls WHERE job_id=? ORDER BY seq, rowid",
            (job_id,),
        ),
    }
    for attempt in payload["attempts"]:
        attempt["attempt_dir"] = _relative_dir(str(attempt["attempt_dir"]), job_id)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return {**payload, "manifest_sha256": hashlib.sha256(canonical.encode()).hexdigest()}
