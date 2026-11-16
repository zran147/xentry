"""SQLite projections for jobs, steps, nonces, and outcomes."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from xentry import events


def _event(conn: sqlite3.Connection, attempt_id: str, event_type: str, payload: dict[str, Any]) -> None:
    row = conn.execute(
        "SELECT attempt_dir FROM attempts WHERE id=?", (attempt_id,)
    ).fetchone()
    if row is None:
        return
    events.append(
        Path(str(row["attempt_dir"])) / "events.jsonl",
        event_type,
        {"attempt_id": attempt_id, **payload},
    )


def now() -> str:
    return datetime.now(UTC).isoformat()


def _id() -> str:
    return uuid.uuid4().hex


def create_job(
    conn: sqlite3.Connection,
    *,
    data_dir: Path,
    poc_url: str,
    cve_url: str = "",
    check_id: str | None = None,
    bundle_sha256: str | None = None,
    kind: str = "job",
) -> tuple[str, str, Path]:
    job_id = _id()
    attempt_id = _id()
    attempt_dir = data_dir / "jobs" / job_id / "attempt-0"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    timestamp = now()
    conn.execute(
        "INSERT INTO jobs(id, cve_id, target_id, poc_url, check_id, bundle_sha256, "
        "created_at, attempt_dir, kind) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            job_id,
            None,
            "pending",
            poc_url,
            check_id,
            bundle_sha256,
            timestamp,
            str(attempt_dir),
            kind,
        ),
    )
    conn.execute(
        "INSERT INTO attempts(id, job_id, attempt_no, attempt_dir, started_at) "
        "VALUES (?,?,?,?,?)",
        (attempt_id, job_id, 0, str(attempt_dir), timestamp),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "job_created",
        {
            "job_id": job_id,
            "poc_url": poc_url,
            "cve_url": cve_url,
            "check_id": check_id,
            "bundle_sha256": bundle_sha256,
        },
    )
    return job_id, attempt_id, attempt_dir


def _job_event(conn: sqlite3.Connection, job_id: str, event_type: str, payload: dict[str, Any]) -> None:
    row = conn.execute(
        "SELECT id FROM attempts WHERE job_id=? ORDER BY attempt_no DESC LIMIT 1",
        (job_id,),
    ).fetchone()
    if row is not None:
        _event(conn, str(row["id"]), event_type, payload)


def set_plan(
    conn: sqlite3.Connection,
    job_id: str,
    *,
    cve_id: str,
    target_id: str,
    bundle_sha256: str,
) -> None:
    conn.execute(
        "UPDATE jobs SET cve_id=?, target_id=?, bundle_sha256=?, started_at=? WHERE id=?",
        (cve_id, target_id, bundle_sha256, now(), job_id),
    )
    conn.commit()
    _job_event(
        conn,
        job_id,
        "plan_set",
        {"cve_id": cve_id, "target_id": target_id, "bundle_sha256": bundle_sha256},
    )


def begin_step(
    conn: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    seq: int,
    name: str,
    step_id: str | None = None,
) -> str:
    row_id = _id()
    conn.execute(
        "INSERT INTO job_steps(id, job_id, attempt_id, seq, name, step_id, state, started_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (row_id, job_id, attempt_id, seq, name, step_id, "running", now()),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "step_started",
        {"row_id": row_id, "seq": seq, "name": name, "step_id": step_id},
    )
    return row_id


def finish_step(
    conn: sqlite3.Connection,
    step_row_id: str,
    *,
    state: str,
    reason_code: str | None = None,
    detail: str | None = None,
) -> None:
    conn.execute(
        "UPDATE job_steps SET state=?, finished_at=?, reason_code=?, detail=? WHERE id=?",
        (state, now(), reason_code, (detail or None), step_row_id),
    )
    conn.commit()
    row = conn.execute(
        "SELECT attempt_id, name, seq FROM job_steps WHERE id=?", (step_row_id,)
    ).fetchone()
    if row is not None:
        _event(
            conn,
            str(row["attempt_id"]),
            "step_finished",
            {
                "row_id": step_row_id,
                "seq": row["seq"],
                "name": row["name"],
                "state": state,
                "reason_code": reason_code,
            },
        )


def record_nonce(
    conn: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    phase: str,
    nonce_id: str,
    sha256: str,
    path: str,
    owner: str,
    mode: int,
    replace: bool = False,
) -> None:
    # One nonce per phase per attempt, enforced by the schema: placing a
    # second one in a normal job would be a bug worth failing on. The
    # experimental pipeline rewrites its PoC and re-places the real nonce for
    # each try, so it asks for the replacement explicitly. Only the last
    # digest is kept, which is the one the verdict rests on - an earlier
    # attempt's nonce was by definition never observed, or it would have ended
    # the job there.
    conflict = (
        " ON CONFLICT(attempt_id, phase) DO UPDATE SET nonce_id=excluded.nonce_id, "
        "sha256=excluded.sha256, path=excluded.path, owner=excluded.owner, "
        "mode=excluded.mode, created_at=excluded.created_at"
        if replace
        else ""
    )
    conn.execute(
        "INSERT INTO nonces(nonce_id, job_id, attempt_id, phase, sha256, path, owner, mode, "
        "created_at) VALUES (?,?,?,?,?,?,?,?,?)" + conflict,
        (nonce_id, job_id, attempt_id, phase, sha256, path, owner, mode, now()),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "nonce_placed",
        {
            "nonce_id": nonce_id,
            "phase": phase,
            "sha256": sha256,
            "path": path,
            "owner": owner,
            "mode": mode,
        },
    )


def record_outcome(
    conn: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    outcome: str,
    verdict: str,
    authority: str,
    reason_code: str,
) -> str:
    outcome_id = _id()
    timestamp = now()
    conn.execute(
        "INSERT INTO job_outcomes(id, job_id, attempt_id, outcome, verdict, authority, "
        "reason_code, ts) VALUES (?,?,?,?,?,?,?,?)",
        (outcome_id, job_id, attempt_id, outcome, verdict, authority, reason_code, timestamp),
    )
    conn.execute(
        "UPDATE jobs SET last_outcome_id=?, outcome=?, verdict=?, authority=?, "
        "reason_code=?, finished_at=? WHERE id=?",
        (outcome_id, outcome, verdict, authority, reason_code, timestamp, job_id),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "outcome",
        {
            "outcome_id": outcome_id,
            "outcome": outcome,
            "verdict": verdict,
            "authority": authority,
            "reason_code": reason_code,
        },
    )
    return outcome_id


def record_validation(
    conn: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    target_id: str,
    authority: str,
    validator_model: str,
    prompt_hash: str,
    verdict: str,
    reason_code: str,
    nonce_id: str,
    runner_nonce_observed: bool,
    null_actor_observed_nonce: bool,
    evidence: dict[str, Any],
) -> str:
    validation_id = _id()
    evidence_json = json.dumps(evidence, sort_keys=True)
    evidence_sha = hashlib.sha256(evidence_json.encode()).hexdigest()
    conn.execute(
        "INSERT INTO validations(id, job_id, attempt_id, target_id, authority, "
        "validator_model, validator_prompt_hash, verdict, reason_code, nonce_id, "
        "runner_nonce_observed, null_actor_observed_nonce, evidence_json, evidence_sha256, ts) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            validation_id,
            job_id,
            attempt_id,
            target_id,
            authority,
            validator_model,
            prompt_hash,
            verdict,
            reason_code,
            nonce_id,
            int(runner_nonce_observed),
            int(null_actor_observed_nonce),
            evidence_json,
            evidence_sha,
            now(),
        ),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "validation",
        {
            "validation_id": validation_id,
            "target_id": target_id,
            "authority": authority,
            "verdict": verdict,
            "reason_code": reason_code,
            "nonce_id": nonce_id,
            "validator_model": validator_model,
            "validator_prompt_hash": prompt_hash,
            "runner_nonce_observed": int(runner_nonce_observed),
            "null_actor_observed_nonce": int(null_actor_observed_nonce),
            "evidence": evidence,
            "evidence_sha256": evidence_sha,
        },
    )
    return validation_id


def record_artifact(
    conn: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    kind: str,
    path: Path,
    sha256: str,
    size: int,
) -> str:
    artifact_id = _id()
    conn.execute(
        "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
        "VALUES (?,?,?,?,?,?,?)",
        (artifact_id, job_id, attempt_id, kind, str(path), sha256, size),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "artifact",
        {
            "artifact_id": artifact_id,
            "kind": kind,
            "name": path.name,
            "path": str(path),
            "sha256": sha256,
            "bytes": size,
        },
    )
    return artifact_id


def _project_job(row: sqlite3.Row) -> dict[str, Any]:
    job = dict(row)
    job["state"] = job.get("outcome") or ("running" if job.get("started_at") else "queued")
    return job


def get_job(conn: sqlite3.Connection, job_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return _project_job(row) if row is not None else None


def list_jobs(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    # Jobs only. A rebuilt environment has no outcome by design and would
    # otherwise sit here looking like a run that never finished.
    rows = conn.execute(
        "SELECT * FROM jobs WHERE kind='job' ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_project_job(row) for row in rows]


def list_environments(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Rebuilt environments that are still up."""
    rows = conn.execute(
        "SELECT * FROM jobs WHERE kind='environment' AND outcome IS NULL "
        "ORDER BY created_at DESC"
    ).fetchall()
    return [_project_job(row) for row in rows]


def list_experiments(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    """Experimental runs, which are kept off the job list on purpose."""
    rows = conn.execute(
        "SELECT * FROM jobs WHERE kind='experiment' ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_project_job(row) for row in rows]


def count_live_jobs(conn: sqlite3.Connection) -> int:
    """Real jobs with no outcome yet, which is what blocks a restart."""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM jobs WHERE kind='job' AND outcome IS NULL"
    ).fetchone()
    return int(row["n"] if row is not None else 0)


def list_steps(conn: sqlite3.Connection, job_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM job_steps WHERE job_id=? ORDER BY seq", (job_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def list_validations(conn: sqlite3.Connection, job_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM validations WHERE job_id=? ORDER BY ts", (job_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def list_artifacts(conn: sqlite3.Connection, job_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, attempt_id, kind, sha256, bytes FROM artifacts "
        "WHERE job_id=? ORDER BY rowid",
        (job_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def set_cleanup_state(conn: sqlite3.Connection, job_id: str, state: str) -> None:
    conn.execute("UPDATE jobs SET cleanup_state=? WHERE id=?", (state, job_id))
    conn.commit()
    row = conn.execute(
        "SELECT id FROM attempts WHERE job_id=? ORDER BY attempt_no DESC LIMIT 1",
        (job_id,),
    ).fetchone()
    if row is not None:
        _event(conn, str(row["id"]), "cleanup_state", {"state": state})


def set_final_attempt(conn: sqlite3.Connection, job_id: str, attempt_id: str) -> None:
    conn.execute(
        "UPDATE jobs SET final_attempt_id=? WHERE id=?",
        (attempt_id, job_id),
    )
    conn.commit()


def record_broker_call(
    conn: sqlite3.Connection,
    *,
    job_id: str,
    attempt_id: str,
    call: dict[str, Any],
) -> None:
    call_id = str(call.get("id", ""))
    if not call_id:
        return
    conn.execute(
        "INSERT OR IGNORE INTO broker_calls(id, job_id, attempt_id, seq, verb, "
        "params_sha256, started_at, finished_at, status, result_path, result_sha256) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            call_id,
            job_id,
            attempt_id,
            int(call.get("seq", 0) or 0),
            str(call.get("verb", "unknown")),
            str(call.get("params_sha256", "")),
            call.get("started_at"),
            call.get("finished_at"),
            call.get("status"),
            call.get("result_path"),
            call.get("result_sha256"),
        ),
    )
    conn.commit()
    _event(
        conn,
        attempt_id,
        "broker_call",
        {
            "verb": str(call.get("verb", "unknown")),
            "seq": int(call.get("seq", 0) or 0),
            "status": call.get("status"),
            "params_sha256": str(call.get("params_sha256", "")),
            "result_sha256": call.get("result_sha256"),
        },
    )


def request_cancel(conn: sqlite3.Connection, job_id: str) -> None:
    conn.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
    conn.commit()
    row = conn.execute(
        "SELECT id FROM attempts WHERE job_id=? ORDER BY attempt_no DESC LIMIT 1",
        (job_id,),
    ).fetchone()
    if row is not None:
        _event(conn, str(row["id"]), "cancel_requested", {})


# A job is held when the runner has written its held-VM record and no outcome
# has been projected yet. cleanup_state is left alone: its CHECK constraint
# admits only four values, and "pending" is in any case the truth during a hold,
# because the teardown has not run.
RELEASE_MARKER = "release"


def held_release_path(conn: sqlite3.Connection, job_id: str) -> Path | None:
    row = conn.execute("SELECT attempt_dir FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None or not row["attempt_dir"]:
        return None
    return Path(str(row["attempt_dir"])) / RELEASE_MARKER


def is_release_requested(conn: sqlite3.Connection, job_id: str) -> bool:
    path = held_release_path(conn, job_id)
    return path is not None and path.exists()


def request_release(conn: sqlite3.Connection, job_id: str) -> bool:
    """Ask a held job to tear down now. False when the job is not held."""
    row = conn.execute(
        "SELECT 1 FROM jobs j JOIN artifacts a ON a.job_id=j.id "
        "WHERE j.id=? AND j.outcome IS NULL AND a.kind='held_vms'",
        (job_id,),
    ).fetchone()
    if row is None:
        return False
    path = held_release_path(conn, job_id)
    if path is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(now(), encoding="utf-8")
    return True


def get_check(conn: sqlite3.Connection, check_id: str) -> dict[str, Any] | None:
    # The jobs table keeps poc_url but not cve_url; the submitted CVE link is
    # recorded on the link check that approved the job.
    if not check_id:
        return None
    row = conn.execute(
        "SELECT * FROM link_checks WHERE check_id=?", (check_id,)
    ).fetchone()
    return dict(row) if row is not None else None


def list_held_jobs(
    conn: sqlite3.Connection, kind: str = "job"
) -> list[dict[str, Any]]:
    # Held by kind, so the experimental page shows its own VMs and the Running
    # VMs page never mixes an unpinned experiment in with the jobs.
    rows = conn.execute(
        "SELECT DISTINCT j.* FROM jobs j JOIN artifacts a ON a.job_id=j.id "
        "WHERE j.kind=? AND j.outcome IS NULL AND a.kind='held_vms' "
        "ORDER BY j.created_at DESC",
        (kind,),
    ).fetchall()
    return [_project_job(row) for row in rows]


def is_cancel_requested(conn: sqlite3.Connection, job_id: str) -> bool:
    row = conn.execute("SELECT cancel_requested FROM jobs WHERE id=?", (job_id,)).fetchone()
    return bool(row and row["cancel_requested"])
