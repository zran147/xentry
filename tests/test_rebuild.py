"""Rebuild the SQLite index from the attempt event journals."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.rebuild_index import rebuild
from xentry.db import connect, init_db
from xentry.jobstore import (
    begin_step,
    create_job,
    finish_step,
    record_artifact,
    record_nonce,
    record_outcome,
    record_validation,
    set_cleanup_state,
    set_plan,
)

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


def _seed_journal(tmp_path: Path) -> tuple[str, str, Path]:
    conn = init_db(tmp_path / "app.db")
    job_id, attempt_id, attempt_dir = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
        check_id="check-1",
        bundle_sha256="d" * 64,
    )
    set_plan(
        conn,
        job_id,
        cve_id="CVE-2026-109618",
        target_id="php2shell",
        bundle_sha256="d" * 64,
    )
    step_row = begin_step(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        seq=1,
        name="fetch",
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
    artifact = attempt_dir / "cve.html"
    artifact.write_bytes(b"cve")
    record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="evidence",
        path=artifact,
        sha256=hashlib.sha256(b"cve").hexdigest(),
        size=3,
    )
    record_validation(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        target_id="php2shell",
        authority="runner_observed+llm_assessed",
        validator_model="fake",
        prompt_hash="e" * 64,
        verdict="reproduced",
        reason_code="nonce_observed",
        nonce_id="real-1",
        runner_nonce_observed=True,
        null_actor_observed_nonce=False,
        evidence={"nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest()},
    )
    set_cleanup_state(conn, job_id, "done")
    record_outcome(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        outcome="completed",
        verdict="reproduced",
        authority="runner_observed+llm_assessed",
        reason_code="nonce_observed",
    )
    conn.close()
    return job_id, attempt_id, attempt_dir


def test_rebuild_replays_the_journal(tmp_path: Path) -> None:
    job_id, attempt_id, attempt_dir = _seed_journal(tmp_path)
    rebuild_db = tmp_path / "rebuild.db"
    counts = rebuild(tmp_path / "jobs", rebuild_db)
    assert counts == {
        "jobs": 1,
        "attempts": 1,
        "steps": 1,
        "nonces": 1,
        "artifacts": 1,
        "validations": 1,
        "outcomes": 1,
        "broker_calls": 0,
    }
    conn = connect(rebuild_db)
    try:
        job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        assert job["cve_id"] == "CVE-2026-109618"
        assert job["target_id"] == "php2shell"
        assert job["outcome"] == "completed"
        assert job["verdict"] == "reproduced"
        assert job["authority"] == "runner_observed+llm_assessed"
        assert job["cleanup_state"] == "done"
        assert job["final_attempt_id"] == attempt_id
        step = conn.execute("SELECT state FROM job_steps WHERE job_id=?", (job_id,)).fetchone()
        assert step["state"] == "passed"
        nonce = conn.execute("SELECT sha256 FROM nonces WHERE attempt_id=?", (attempt_id,)).fetchone()
        assert nonce["sha256"] == hashlib.sha256(b"a" * 32).hexdigest()
        artifact = conn.execute("SELECT path FROM artifacts WHERE job_id=?", (job_id,)).fetchone()
        assert Path(artifact["path"]) == attempt_dir / "cve.html"
        validation = conn.execute(
            "SELECT verdict, evidence_json FROM validations WHERE job_id=?", (job_id,)
        ).fetchone()
        assert validation["verdict"] == "reproduced"
        assert "nonce_sha256" in json.loads(validation["evidence_json"])
    finally:
        conn.close()


def test_rebuild_refuses_a_tampered_journal(tmp_path: Path) -> None:
    _seed_journal(tmp_path)
    path = next((tmp_path / "jobs").glob("*/attempt-*/events.jsonl"))
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["payload"]["poc_url"] = "https://example.com/evil"
    lines[0] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash chain"):
        rebuild(tmp_path / "jobs", tmp_path / "rebuild.db")
