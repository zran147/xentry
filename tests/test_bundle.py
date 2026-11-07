"""Audit bundle reconstruction, hashes, and nonce secrecy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from xentry import events
from xentry.bundle import build_bundle
from xentry.db import init_db
from xentry.jobstore import (
    create_job,
    record_artifact,
    record_nonce,
    record_outcome,
    record_validation,
    set_plan,
)
from xentry.web.app import build_app

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


def _manifest(bundle: dict[str, object]) -> str:
    payload = {key: value for key, value in bundle.items() if key != "manifest_sha256"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def test_bundle_reconstructs_job_without_nonce_value(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
        conn,
        data_dir=tmp_path / "data",
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
    conn.execute(
        "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
        "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            "check-1",
            "https://example.com/cve",
            POC_URL,
            "CVE-2026-109618",
            "php2shell",
            "d" * 64,
            "2026-11-06T00:00:00+00:00",
            "2026-11-06T00:30:00+00:00",
        ),
    )
    conn.commit()
    evidence = attempt_dir / "target-response.txt"
    evidence.write_bytes(b"nonce response body")
    record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="evidence",
        path=evidence,
        sha256=hashlib.sha256(b"nonce response body").hexdigest(),
        size=len(b"nonce response body"),
    )
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
    record_outcome(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        outcome="completed",
        verdict="reproduced",
        authority="runner_observed+llm_assessed",
        reason_code="nonce_observed",
    )

    other_job, _other_attempt, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/other",
    )
    bundle = build_bundle(conn, job_id)
    assert build_bundle(conn, job_id) == bundle
    other_bundle = build_bundle(conn, other_job)
    conn.close()

    assert bundle["format"] == "xentry-audit-bundle/1"
    assert bundle["job"]["id"] == job_id
    assert bundle["job"]["check_id"] == "check-1"
    assert bundle["check"]["check_id"] == "check-1"
    assert bundle["check"]["bundle_sha256"] == "d" * 64
    assert bundle["attempts"][0]["attempt_dir"] == "attempt-0"
    assert bundle["steps"] == []
    assert bundle["validations"][0]["verdict"] == "reproduced"
    assert bundle["outcomes"][0]["outcome"] == "completed"
    assert bundle["nonces"][0]["sha256"] == hashlib.sha256(nonce.encode()).hexdigest()
    assert bundle["artifacts"][0]["name"] == "target-response.txt"
    assert "path" not in bundle["artifacts"][0]
    assert bundle["manifest_sha256"] == _manifest(bundle)
    assert [event["type"] for event in bundle["events"]] == [
        "job_created",
        "plan_set",
        "artifact",
        "nonce_placed",
        "validation",
        "outcome",
    ]
    assert events.verify(Path(str(attempt_dir)) / "events.jsonl")

    serialized = json.dumps(bundle, sort_keys=True, default=str)
    assert nonce not in serialized
    assert "nonce response body" not in serialized

    assert other_bundle["job"]["id"] == other_job
    assert other_bundle["artifacts"] == []
    assert other_bundle["validations"] == []


def test_bundle_endpoint_returns_manifest_and_404(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        response = client.get(f"/api/jobs/{job_id}/bundle")
        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]
        assert response.json()["manifest_sha256"] == _manifest(response.json())
        missing = client.get("/api/jobs/not-a-job/bundle")
        assert missing.status_code == 404
