#!/usr/bin/env python3
"""Rebuild the SQLite index from append-only attempt event journals.

The attempt directory is authoritative. This script verifies every journal hash
chain and replays job creation, plan, steps, nonces, artifacts, validations,
outcomes, cleanup, cancellation, and broker-call metadata into a fresh SQLite
database. Raw artifact bytes are not copied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from xentry import events
from xentry.db import init_db


def _attempt_no(path: Path) -> int:
    name = path.parent.name
    if name.startswith("attempt-"):
        try:
            return int(name.removeprefix("attempt-"))
        except ValueError:
            return 0
    return 0


def _event_value(record: dict[str, Any], key: str, default: Any = None) -> Any:
    payload = record.get("payload", {})
    return payload.get(key, default) if isinstance(payload, dict) else default


def _synthetic_call_id(attempt_id: str, seq: Any, verb: Any, ts: Any) -> str:
    material = f"{attempt_id}:{seq}:{verb}:{ts}"
    return hashlib.sha256(material.encode()).hexdigest()


def rebuild(jobs_root: Path, db_path: Path) -> dict[str, int]:
    paths = sorted(jobs_root.glob("*/attempt-*/events.jsonl"))
    for path in paths:
        if not events.verify(path):
            raise ValueError(f"event hash chain failed: {path}")
    conn = init_db(db_path)
    counts = {name: 0 for name in ("jobs", "attempts", "steps", "nonces", "artifacts", "validations", "outcomes", "broker_calls")}
    try:
        for path in paths:
            attempt_dir = path.parent
            job_id = attempt_dir.parent.name
            attempt_id = ""
            created_ts = ""
            records = events.read(path)
            for record in records:
                if record.get("type") == "job_created":
                    attempt_id = str(_event_value(record, "attempt_id", ""))
                    created_ts = str(record.get("ts", ""))
                    break
            if not attempt_id:
                raise ValueError(f"journal has no attempt_id: {path}")
            exists = conn.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone()
            if exists is None:
                first = next(record for record in records if record.get("type") == "job_created")
                conn.execute(
                    "INSERT INTO jobs(id, target_id, poc_url, check_id, bundle_sha256, "
                    "created_at, attempt_dir) VALUES (?,?,?,?,?,?,?)",
                    (
                        job_id,
                        "pending",
                        str(_event_value(first, "poc_url", "")),
                        _event_value(first, "check_id"),
                        _event_value(first, "bundle_sha256"),
                        created_ts,
                        str(attempt_dir),
                    ),
                )
                counts["jobs"] += 1
            conn.execute(
                "INSERT INTO attempts(id, job_id, attempt_no, attempt_dir, started_at) "
                "VALUES (?,?,?,?,?)",
                (attempt_id, job_id, _attempt_no(path), str(attempt_dir), created_ts),
            )
            counts["attempts"] += 1
            for record in records:
                kind = record.get("type")
                ts = str(record.get("ts", ""))
                if kind == "plan_set":
                    conn.execute(
                        "UPDATE jobs SET cve_id=?, target_id=?, bundle_sha256=?, "
                        "started_at=? WHERE id=?",
                        (
                            _event_value(record, "cve_id"),
                            _event_value(record, "target_id", "pending"),
                            _event_value(record, "bundle_sha256"),
                            ts,
                            job_id,
                        ),
                    )
                elif kind == "step_started":
                    conn.execute(
                        "INSERT INTO job_steps(id, job_id, attempt_id, seq, name, step_id, "
                        "state, started_at) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            _event_value(record, "row_id"),
                            job_id,
                            attempt_id,
                            int(_event_value(record, "seq", 0)),
                            str(_event_value(record, "name", "")),
                            _event_value(record, "step_id"),
                            "running",
                            ts,
                        ),
                    )
                    counts["steps"] += 1
                elif kind == "step_finished":
                    conn.execute(
                        "UPDATE job_steps SET state=?, reason_code=?, finished_at=? WHERE id=?",
                        (
                            _event_value(record, "state", "passed"),
                            _event_value(record, "reason_code"),
                            ts,
                            _event_value(record, "row_id"),
                        ),
                    )
                elif kind == "nonce_placed":
                    conn.execute(
                        "INSERT INTO nonces(nonce_id, job_id, attempt_id, phase, sha256, "
                        "path, owner, mode, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            _event_value(record, "nonce_id"),
                            job_id,
                            attempt_id,
                            _event_value(record, "phase"),
                            _event_value(record, "sha256"),
                            _event_value(record, "path"),
                            _event_value(record, "owner"),
                            int(_event_value(record, "mode", 0)),
                            ts,
                        ),
                    )
                    counts["nonces"] += 1
                elif kind == "artifact":
                    artifact_path = _event_value(record, "path") or str(
                        attempt_dir / str(_event_value(record, "name", ""))
                    )
                    conn.execute(
                        "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, "
                        "bytes) VALUES (?,?,?,?,?,?,?)",
                        (
                            _event_value(record, "artifact_id"),
                            job_id,
                            attempt_id,
                            _event_value(record, "kind"),
                            artifact_path,
                            _event_value(record, "sha256"),
                            int(_event_value(record, "bytes", 0)),
                        ),
                    )
                    counts["artifacts"] += 1
                elif kind == "validation":
                    evidence = _event_value(record, "evidence", {})
                    evidence_json = json.dumps(evidence, sort_keys=True)
                    conn.execute(
                        "INSERT INTO validations(id, job_id, attempt_id, target_id, authority, "
                        "validator_model, validator_prompt_hash, verdict, reason_code, nonce_id, "
                        "runner_nonce_observed, null_actor_observed_nonce, evidence_json, "
                        "evidence_sha256, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            _event_value(record, "validation_id"),
                            job_id,
                            attempt_id,
                            _event_value(record, "target_id"),
                            _event_value(record, "authority"),
                            _event_value(record, "validator_model"),
                            _event_value(record, "validator_prompt_hash"),
                            _event_value(record, "verdict"),
                            _event_value(record, "reason_code"),
                            _event_value(record, "nonce_id"),
                            int(_event_value(record, "runner_nonce_observed", 0)),
                            int(_event_value(record, "null_actor_observed_nonce", 0)),
                            evidence_json,
                            _event_value(record, "evidence_sha256"),
                            ts,
                        ),
                    )
                    conn.execute("UPDATE jobs SET final_attempt_id=? WHERE id=?", (attempt_id, job_id))
                    counts["validations"] += 1
                elif kind == "outcome":
                    outcome_id = _event_value(record, "outcome_id")
                    conn.execute(
                        "INSERT INTO job_outcomes(id, job_id, attempt_id, outcome, verdict, "
                        "authority, reason_code, ts) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            outcome_id,
                            job_id,
                            attempt_id,
                            _event_value(record, "outcome"),
                            _event_value(record, "verdict"),
                            _event_value(record, "authority"),
                            _event_value(record, "reason_code"),
                            ts,
                        ),
                    )
                    conn.execute(
                        "UPDATE jobs SET last_outcome_id=?, outcome=?, verdict=?, authority=?, "
                        "reason_code=?, finished_at=? WHERE id=?",
                        (
                            outcome_id,
                            _event_value(record, "outcome"),
                            _event_value(record, "verdict"),
                            _event_value(record, "authority"),
                            _event_value(record, "reason_code"),
                            ts,
                            job_id,
                        ),
                    )
                    conn.execute(
                        "UPDATE attempts SET finished_at=?, failure_code=? WHERE id=?",
                        (
                            ts,
                            _event_value(record, "reason_code")
                            if _event_value(record, "outcome") in {"failed", "cancelled", "interrupted"}
                            else None,
                            attempt_id,
                        ),
                    )
                    counts["outcomes"] += 1
                elif kind == "cleanup_state":
                    conn.execute(
                        "UPDATE jobs SET cleanup_state=? WHERE id=?",
                        (_event_value(record, "state"), job_id),
                    )
                elif kind == "cancel_requested":
                    conn.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
                elif kind == "broker_call":
                    seq = int(_event_value(record, "seq", 0))
                    verb = str(_event_value(record, "verb", "unknown"))
                    call_id = _synthetic_call_id(attempt_id, seq, verb, ts)
                    conn.execute(
                        "INSERT INTO broker_calls(id, job_id, attempt_id, seq, verb, "
                        "params_sha256, started_at, finished_at, status, result_sha256) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            call_id,
                            job_id,
                            attempt_id,
                            seq,
                            verb,
                            _event_value(record, "params_sha256"),
                            ts,
                            ts,
                            _event_value(record, "status"),
                            _event_value(record, "result_sha256"),
                        ),
                    )
                    counts["broker_calls"] += 1
            conn.commit()
    finally:
        conn.close()
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs-root", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--force", action="store_true", help="replace an existing database")
    args = parser.parse_args(argv)
    if args.db.exists():
        if not args.force:
            print(f"refusing to replace existing database: {args.db}")
            return 2
        args.db.unlink()
        for suffix in ("-wal", "-shm"):
            Path(str(args.db) + suffix).unlink(missing_ok=True)
    if not args.jobs_root.is_dir():
        print(f"jobs root is missing: {args.jobs_root}")
        return 2
    counts = rebuild(args.jobs_root, args.db)
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
