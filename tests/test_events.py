"""Attempt event journal and hash-chain tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from xentry import events
from xentry.db import init_db
from xentry.jobstore import (
    begin_step,
    create_job,
    finish_step,
    record_artifact,
    record_nonce,
    record_outcome,
    set_cleanup_state,
)

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


def test_event_hash_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "attempt" / "events.jsonl"
    events.append(path, "one", {"value": 1})
    events.append(path, "two", {"value": 2})
    events.append(path, "three", {"value": 3})
    assert events.verify(path)
    assert [event["type"] for event in events.read(path)] == ["one", "two", "three"]

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["payload"]["value"] = 99
    lines[1] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not events.verify(path)


def test_jobstore_writes_an_auditable_journal(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "xentry.db")
    job_id, attempt_id, attempt_dir = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    step_row = begin_step(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        seq=1,
        name="fetch",
        step_id=None,
    )
    finish_step(conn, step_row, state="passed")
    nonce = "a" * 32
    record_nonce(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        phase="real",
        nonce_id="real-1",
        sha256=hashlib.sha256(nonce.encode()).hexdigest(),
        path="/var/lib/xentry/nonce",
        owner="xentry-guest",
        mode=0o600,
    )
    evidence = attempt_dir / "evidence.txt"
    evidence.write_bytes(b"evidence")
    record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="evidence",
        path=evidence,
        sha256=hashlib.sha256(b"evidence").hexdigest(),
        size=len(b"evidence"),
    )
    set_cleanup_state(conn, job_id, "done")
    record_outcome(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        outcome="completed",
        verdict="inconclusive",
        authority="runner_observed",
        reason_code="validator_error",
    )
    conn.close()

    path = attempt_dir / "events.jsonl"
    records = events.read(path)
    assert [record["type"] for record in records] == [
        "job_created",
        "step_started",
        "step_finished",
        "nonce_placed",
        "artifact",
        "cleanup_state",
        "outcome",
    ]
    assert events.verify(path)
    assert nonce not in path.read_text(encoding="utf-8")
    assert records[3]["payload"]["sha256"] == hashlib.sha256(nonce.encode()).hexdigest()
