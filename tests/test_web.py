"""Web app smoke tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from xentry.broker import BrokerError
from xentry.db import connect
from xentry.fetch import Fetched
from xentry.jobstore import create_job, record_artifact, record_outcome, set_plan
from xentry.models import Facts
from xentry.web.app import build_app

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


class FakeRunner:
    def __init__(self) -> None:
        self.submitted: list[tuple[str, str, str | None, str | None]] = []
        # Kept apart from `submitted`, whose tuple shape existing assertions
        # already index by position.
        self.harnessed: list[bool] = []

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def submit(
        self,
        cve_url: str,
        poc_url: str,
        *,
        check_id: str | None = None,
        bundle_sha256: str | None = None,
        harness: bool = False,
    ) -> str:
        self.submitted.append((cve_url, poc_url, check_id, bundle_sha256))
        self.harnessed.append(harness)
        return "job-abc"


class EnvRunner(FakeRunner):
    def __init__(self) -> None:
        super().__init__()
        self.built: list[str] = []
        self.destroyed: list[str] = []

    def build_environment(self, source_job_id: str) -> str:
        self.built.append(source_job_id)
        return "env-abc"

    def destroy_environment(self, job_id: str) -> None:
        self.destroyed.append(job_id)


class BlockedRunner(FakeRunner):
    def submit(self, *args: object, **kwargs: object) -> str:
        raise BrokerError("security_cleanup_failed", "orphan resources")


def _fetched(url: str) -> Fetched:
    body = b"pinned source"
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers={},
        body=body,
        text=body.decode(),
        sha256=hashlib.sha256(body).hexdigest(),
    )


def _facts(_artifacts: object) -> Facts:
    return Facts(
        cve_id="CVE-2026-109618",
        product="PHP",
        affected_range="8.4.0 ~ 8.4.26",
        version_evidence=[],
        protocol="http",
        ports=[8088],
        auth_required=False,
        build_strategy="Apache mod_php",
        poc_context="remote",
        citations=[],
    )


def test_link_check_and_job_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("xentry.web.app.fetch", _fetched)
    monkeypatch.setattr("xentry.web.app.extract", _facts)
    runner = FakeRunner()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=runner,  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_URL},
            headers=headers,
        )
        assert checked.status_code == 200
        plan = checked.json()
        assert plan["target_id"] == "php2shell"
        submitted = client.post(
            "/api/jobs",
            json={
                "cve_url": "https://example.com/cve",
                "poc_url": POC_URL,
                "check_id": plan["check_id"],
            },
            headers=headers,
        )
        assert submitted.status_code == 200
        assert submitted.json()["job_id"] == "job-abc"
        assert runner.submitted
        assert runner.submitted[0][2] == plan["check_id"]
        assert runner.submitted[0][3] == plan["bundle_sha256"]


def test_web_pages_and_token_gate(tmp_path: Path) -> None:
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        index = client.get("/")
        assert index.status_code == 200
        assert "Content-Security-Policy" in index.headers
        token = app.state.token
        assert token
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/api/system").status_code == 200
        assert client.get("/jobs/missing").status_code == 404
        assert client.get("/api/jobs/missing/steps").status_code == 404
        assert client.get("/api/jobs/missing/validations").status_code == 404
        assert client.get("/api/jobs/missing/events").status_code == 404

        denied = client.post("/api/preflight", json={})
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "csrf_invalid"

        client.cookies.clear()
        no_cookie = client.post(
            "/api/preflight",
            json={},
            headers={"X-Xentry-CSRF": token},
        )
        assert no_cookie.status_code == 401
        assert no_cookie.json()["error"]["code"] == "token_missing"
        client.get("/")

        allowed = client.post(
            "/api/preflight",
            json={},
            headers={"X-Xentry-CSRF": token},
        )
        assert allowed.status_code == 200
        assert "checks" in allowed.json()

        conn = connect(tmp_path / "data" / "xentry.db")
        try:
            job_id, _, _ = create_job(
                conn,
                data_dir=tmp_path / "data",
                poc_url="https://github.com/example/poc",
            )
            set_plan(
                conn,
                job_id,
                cve_id="CVE-2026-109618",
                target_id="php2shell",
                bundle_sha256="d" * 64,
            )
        finally:
            conn.close()
        page = client.get(f"/jobs/{job_id}")
        assert page.status_code == 200
        assert job_id[:12] in page.text
        assert "php2shell" in page.text


def test_evidence_endpoint_serves_recorded_artifact(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from xentry.db import init_db

    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    evidence = tmp_path / "evidence.txt"
    evidence.write_bytes(b"pinned-evidence")
    artifact_id = record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="evidence",
        path=evidence,
        sha256=hashlib.sha256(b"pinned-evidence").hexdigest(),
        size=len(b"pinned-evidence"),
    )
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        response = client.get(f"/api/jobs/{job_id}/evidence/{artifact_id}")
        assert response.status_code == 200
        assert response.content == b"pinned-evidence"
        missing = client.get(f"/api/jobs/{job_id}/evidence/not-an-artifact")
        assert missing.status_code == 404
        conn = connect(db_path)
        try:
            other_job, _other_attempt, _ = create_job(
                conn,
                data_dir=tmp_path / "data",
                poc_url=POC_URL,
                cve_url="https://example.com/other",
            )
        finally:
            conn.close()
        wrong_job = client.get(f"/api/jobs/{other_job}/evidence/{artifact_id}")
        assert wrong_job.status_code == 404


def test_cancel_endpoint_sets_cancel_flag(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from xentry.db import init_db

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
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        client.get("/")
        response = client.post(
            f"/api/jobs/{job_id}/cancel",
            json={},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert response.status_code == 200
        conn = connect(db_path)
        try:
            row = conn.execute("SELECT cancel_requested FROM jobs WHERE id=?", (job_id,)).fetchone()
            assert row[0] == 1
        finally:
            conn.close()


def test_preflight_uses_configured_manifests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket = tmp_path / "broker.sock"
    socket.write_text("", encoding="utf-8")
    images = tmp_path / "images.json"
    artifacts = tmp_path / "artifacts.json"
    images.write_text("{}", encoding="utf-8")
    artifacts.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("XENTRY_IMAGES_MANIFEST", str(images))
    monkeypatch.setenv("XENTRY_ARTIFACT_MANIFEST", str(artifacts))
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=socket,
    )
    with TestClient(app) as client:
        client.get("/")
        result = client.post(
            "/api/preflight",
            json={},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert result.status_code == 200
        assert result.json()["ok"] is True


def test_job_state_is_separate_from_verdict(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from xentry.db import init_db

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
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        queued = client.get(f"/api/jobs/{job_id}").json()["job"]
        assert queued["state"] == "queued"
        assert queued["verdict"] is None

        conn = connect(db_path)
        try:
            set_plan(
                conn,
                job_id,
                cve_id="CVE-2026-109618",
                target_id="php2shell",
                bundle_sha256="d" * 64,
            )
        finally:
            conn.close()
        running = client.get(f"/api/jobs/{job_id}").json()["job"]
        assert running["state"] == "running"
        assert running["verdict"] is None


def test_check_store_ttl_single_use_and_url_binding(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from datetime import UTC, datetime, timedelta

    from xentry.db import init_db
    from xentry.jobstore import now

    conn = init_db(db_path)
    base = datetime.now(UTC)
    rows = [
        ("expired", "https://example.com/cve", POC_URL, (base - timedelta(minutes=1)).isoformat(), None),
        ("used", "https://example.com/cve", POC_URL, (base + timedelta(minutes=30)).isoformat(), now()),
        ("valid", "https://example.com/cve", POC_URL, (base + timedelta(minutes=30)).isoformat(), None),
    ]
    for check_id, cve_url, poc_url, expires, used_at in rows:
        conn.execute(
            "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
            "bundle_sha256, created_at, expires_at, used_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                check_id,
                cve_url,
                poc_url,
                "CVE-2026-109618",
                "php2shell",
                "d" * 64,
                base.isoformat(),
                expires,
                used_at,
            ),
        )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}
        body = {"cve_url": "https://example.com/cve", "poc_url": POC_URL}

        unknown = client.post("/api/jobs", json={**body, "check_id": "missing"}, headers=headers)
        assert unknown.status_code == 404
        expired = client.post("/api/jobs", json={**body, "check_id": "expired"}, headers=headers)
        assert expired.status_code == 409
        used = client.post("/api/jobs", json={**body, "check_id": "used"}, headers=headers)
        assert used.status_code == 409
        mismatch = client.post(
            "/api/jobs",
            json={
                "cve_url": "https://example.com/other",
                "poc_url": POC_URL,
                "check_id": "valid",
            },
            headers=headers,
        )
        assert mismatch.status_code == 409
        accepted = client.post("/api/jobs", json={**body, "check_id": "valid"}, headers=headers)
        assert accepted.status_code == 200
        replay = client.post("/api/jobs", json={**body, "check_id": "valid"}, headers=headers)
        assert replay.status_code == 409


def test_blocked_submission_releases_the_check(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from datetime import UTC, datetime, timedelta

    from xentry.db import init_db

    conn = init_db(db_path)
    now_dt = datetime.now(UTC)
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
            now_dt.isoformat(),
            (now_dt + timedelta(minutes=30)).isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=BlockedRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        client.get("/")
        response = client.post(
            "/api/jobs",
            json={
                "cve_url": "https://example.com/cve",
                "poc_url": POC_URL,
                "check_id": "check-1",
            },
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert response.status_code == 409
        conn = connect(db_path)
        try:
            row = conn.execute(
                "SELECT used_at FROM link_checks WHERE check_id='check-1'"
            ).fetchone()
            assert row[0] is None
        finally:
            conn.close()


def test_configured_allowed_host_accepts_mutations(tmp_path: Path) -> None:
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        allowed_hosts="lab.internal",
    )
    with TestClient(app) as client:
        client.get("/")
        response = client.post(
            "/api/preflight",
            json={},
            headers={
                "Host": "lab.internal",
                "X-Xentry-CSRF": app.state.token,
            },
        )
        assert response.status_code == 200


def test_host_origin_and_csrf_checks(tmp_path: Path) -> None:
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        client.get("/")
        token = app.state.token
        headers = {"X-Xentry-CSRF": token}

        bad_host = client.post(
            "/api/preflight", json={}, headers={**headers, "Host": "evil.example"}
        )
        assert bad_host.status_code == 403
        assert bad_host.json()["error"]["code"] == "host_invalid"

        bad_origin = client.post(
            "/api/preflight",
            json={},
            headers={**headers, "Origin": "http://evil.example"},
        )
        assert bad_origin.status_code == 403
        assert bad_origin.json()["error"]["code"] == "origin_invalid"

        same_origin = client.post(
            "/api/preflight",
            json={},
            headers={**headers, "Origin": "http://testserver"},
        )
        assert same_origin.status_code == 200

        missing_csrf = client.post("/api/preflight", json={})
        assert missing_csrf.status_code == 403
        assert missing_csrf.json()["error"]["code"] == "csrf_invalid"

        wrong_type = client.post(
            "/api/preflight",
            content=b"{}",
            headers={**headers, "Content-Type": "text/plain"},
        )
        assert wrong_type.status_code == 400


def test_cancel_unknown_and_finished_job(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from xentry.db import init_db

    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.execute(
        "UPDATE jobs SET outcome='completed', verdict='inconclusive', "
        "authority='runner_observed' WHERE id=?",
        (job_id,),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}
        unknown = client.post("/api/jobs/not-a-job/cancel", json={}, headers=headers)
        assert unknown.status_code == 404
        finished = client.post(f"/api/jobs/{job_id}/cancel", json={}, headers=headers)
        assert finished.status_code == 409


def test_evidence_endpoint_rejects_tampered_file(tmp_path: Path) -> None:
    db_path = tmp_path / "data" / "xentry.db"
    from xentry.db import init_db

    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    evidence = tmp_path / "evidence.txt"
    evidence.write_bytes(b"original")
    artifact_id = record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="evidence",
        path=evidence,
        sha256=hashlib.sha256(b"original").hexdigest(),
        size=len(b"original"),
    )
    conn.close()
    evidence.write_bytes(b"tampered")
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        response = client.get(f"/api/jobs/{job_id}/evidence/{artifact_id}")
        assert response.status_code == 409
        assert "hash mismatch" in response.json()["detail"]


def _app_with_job(tmp_path: Path) -> tuple[object, str, Path]:
    from xentry.db import init_db

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    set_plan(
        conn,
        job_id,
        cve_id="CVE-2026-109618",
        target_id="php2shell",
        bundle_sha256="d" * 64,
    )
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    return app, job_id, db_path


def test_audit_page_shows_criteria_and_transcript(tmp_path: Path) -> None:
    app, job_id, db_path = _app_with_job(tmp_path)
    attempt_dir = tmp_path / "data" / "jobs" / job_id / "attempt-0"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    llm_dir = attempt_dir / "llm"
    llm_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        attempt_id = conn.execute(
            "SELECT id FROM attempts WHERE job_id=?", (job_id,)
        ).fetchone()["id"]
        for kind, name, text in (
            ("llm_extract_prompt", "extract.prompt.txt", "QUESTION-MARKER"),
            ("llm_extract_response", "extract.response.txt", "ANSWER-MARKER"),
        ):
            path = llm_dir / name
            body = text.encode()
            path.write_bytes(body)
            record_artifact(
                conn,
                job_id=job_id,
                attempt_id=str(attempt_id),
                kind=kind,
                path=path,
                sha256=hashlib.sha256(body).hexdigest(),
                size=len(body),
            )
    finally:
        conn.close()

    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}/audit")
        assert page.status_code == 200
        body = page.text
        # the success criteria come from the pinned target, not the model
        assert "Success criteria" in body
        assert "nonce is readable by the PHP web user" in body
        assert "not a risk assessment" in body
        # the captured call is shown
        assert "QUESTION-MARKER" in body
        assert "ANSWER-MARKER" in body
        # The card no longer carries a paragraph describing itself (the two
        # blurbs, "no tool calls to show" among them, were removed on request),
        # so what is pinned here is the stage block the transcript renders into.
        assert 'id="stage-extract"' in body


def test_audit_page_hides_tampered_transcript(tmp_path: Path) -> None:
    app, job_id, db_path = _app_with_job(tmp_path)
    attempt_dir = tmp_path / "data" / "jobs" / job_id / "attempt-0" / "llm"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    path = attempt_dir / "extract.prompt.txt"
    path.write_bytes(b"ORIGINAL")
    conn = connect(db_path)
    try:
        attempt_id = conn.execute(
            "SELECT id FROM attempts WHERE job_id=?", (job_id,)
        ).fetchone()["id"]
        record_artifact(
            conn,
            job_id=job_id,
            attempt_id=str(attempt_id),
            kind="llm_extract_prompt",
            path=path,
            sha256=hashlib.sha256(b"ORIGINAL").hexdigest(),
            size=8,
        )
    finally:
        conn.close()
    path.write_bytes(b"SWAPPED-CONTENT")

    with TestClient(app) as client:
        body = client.get(f"/jobs/{job_id}/audit").text
        assert "SWAPPED-CONTENT" not in body
        assert "hash mismatch" in body


def test_audit_page_unknown_job_is_404(tmp_path: Path) -> None:
    app, _job_id, _db = _app_with_job(tmp_path)
    with TestClient(app) as client:
        assert client.get("/jobs/does-not-exist/audit").status_code == 404


def test_vms_page_lists_held_jobs_and_release_gate(tmp_path: Path) -> None:
    app, job_id, db_path = _app_with_job(tmp_path)
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}  # type: ignore[attr-defined]

        empty = client.get("/vms")
        assert empty.status_code == 200
        # Both section counts read zero. Keyed on data-count rather than the
        # whole span, because the span now also carries that attribute - the
        # JS decrements it when a card is dropped, so it needs a handle.
        assert empty.text.count('data-count="held">0</span>') == 1
        assert empty.text.count('data-count="rebuilt">0</span>') == 1

        # a job that is not held cannot be released
        refused = client.post(f"/api/jobs/{job_id}/release", json={}, headers=headers)
        assert refused.status_code == 409

        missing = client.post("/api/jobs/nope/release", json={}, headers=headers)
        assert missing.status_code == 404

        attempt_dir = tmp_path / "data" / "jobs" / job_id / "attempt-0"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        held_path = attempt_dir / "held-vms.json"
        payload = (
            '{"attacker_ip": "10.42.0.20", "attacker_vm": "xentry-a", '
            '"held_at": "2026-11-11T05:00:00+00:00", "hold_s": 3600, '
            '"keys_dir": "/var/lib/xentry/jobs/j1/keys", '
            '"network_id": "xentry-net", "target_ip": "10.42.0.10", '
            '"target_vm": "xentry-t"}'
        )
        held_path.write_text(payload)
        conn = connect(db_path)
        try:
            attempt_id = conn.execute(
                "SELECT id FROM attempts WHERE job_id=?", (job_id,)
            ).fetchone()["id"]
            record_artifact(
                conn,
                job_id=job_id,
                attempt_id=str(attempt_id),
                kind="held_vms",
                path=held_path,
                sha256=hashlib.sha256(payload.encode()).hexdigest(),
                size=len(payload),
            )
        finally:
            conn.close()

        listed = client.get("/vms")
        assert listed.status_code == 200
        assert "xentry-t" in listed.text
        # The console is a TCP char device the broker holds, so ssh is the only
        # way in and is the one thing the card offers.
        assert "sudo ssh -i /var/lib/xentry/jobs/j1/keys/root" in listed.text
        assert "root@10.42.0.10" in listed.text
        assert "10.42.0.20" in listed.text

        accepted = client.post(f"/api/jobs/{job_id}/release", json={}, headers=headers)
        assert accepted.status_code == 200
        assert accepted.json()["release_requested"] is True
        marker = tmp_path / "data" / "jobs" / job_id / "attempt-0" / "release"
        assert marker.exists()


def test_job_page_shows_submitted_links(tmp_path: Path) -> None:
    """The CVE link comes from the link check; the PoC link from the job row."""
    from xentry.db import init_db

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
        check_id="chk1",
    )
    conn.execute(
        "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
        "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            "chk1",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
            POC_URL,
            "CVE-2026-109618",
            "php2shell",
            "d" * 64,
            "2026-11-11T05:00:00+00:00",
            "2026-11-11T05:30:00+00:00",
        ),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        body = client.get(f"/jobs/{job_id}").text
        assert "CVE link" in body
        assert "PoC link" in body
        assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2026-109618"' in body
        assert f'href="{POC_URL}"' in body
        assert 'rel="noreferrer noopener"' in body


def test_job_page_does_not_linkify_a_non_http_url(tmp_path: Path) -> None:
    """The API takes these as plain strings, so only http(s) becomes an href."""
    from xentry.db import init_db

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url="javascript:alert(1)",
        cve_url="javascript:alert(2)",
        check_id="chk2",
    )
    conn.execute(
        "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
        "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            "chk2",
            "javascript:alert(2)",
            "javascript:alert(1)",
            None,
            None,
            "d" * 64,
            "2026-11-11T05:00:00+00:00",
            "2026-11-11T05:30:00+00:00",
        ),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        body = client.get(f"/jobs/{job_id}").text
        assert 'href="javascript:' not in body
        # still shown, just not clickable
        assert "javascript:alert(1)" in body


def test_job_page_offers_a_retry_carrying_both_links(tmp_path: Path) -> None:
    """Retry hands the links back to the submit form, keeping both gates."""
    from xentry.db import init_db

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
        check_id="chk3",
    )
    conn.execute(
        "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
        "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
        (
            "chk3",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
            POC_URL,
            "CVE-2026-109618",
            "php2shell",
            "d" * 64,
            "2026-11-11T05:00:00+00:00",
            "2026-11-11T05:30:00+00:00",
        ),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        body = client.get(f"/jobs/{job_id}").text
        assert "Retry this job" in body
        # both links are carried, url-encoded, with the originating job
        assert "cve=https%3A//nvd.nist.gov/vuln/detail/CVE-2026-109618" in body
        assert "poc=https%3A//github.com/78ResearchLab" in body
        assert f"from={job_id}" in body


def test_job_page_omits_retry_without_usable_links(tmp_path: Path) -> None:
    """A job with no linkable urls gets no retry button."""
    from xentry.db import init_db

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url="not-a-url",
        cve_url="",
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        body = client.get(f"/jobs/{job_id}").text
        assert "Retry this job" not in body


def _app_with_candidate(tmp_path: Path) -> tuple[object, str, EnvRunner]:
    """An app whose database holds one completed, rebuildable job."""
    from xentry.db import init_db

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    # No link check: a rebuild fetches nothing, so it needs no recorded source.
    job_id, attempt_id, _dir = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    set_plan(
        conn,
        job_id,
        cve_id="CVE-2026-109618",
        target_id="php2shell",
        bundle_sha256="d" * 64,
    )
    record_outcome(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        outcome="completed",
        verdict="reproduced",
        authority="runner_observed+llm_assessed",
        reason_code="ok",
    )
    conn.close()
    runner = EnvRunner()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=runner,  # type: ignore[arg-type]
    )
    return app, job_id, runner


def test_a_rebuild_is_offered_for_a_completed_job_and_queued(tmp_path: Path) -> None:
    app, job_id, runner = _app_with_candidate(tmp_path)
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}  # type: ignore[attr-defined]

        page = client.get("/vms")
        assert page.status_code == 200
        assert "Running VMs" in page.text
        assert "Rebuilt VMs" in page.text
        assert job_id in page.text
        # One candidate to rebuild from, nothing rebuilt yet.
        assert page.text.count('data-count="held">0</span>') == 1
        assert page.text.count('data-count="rebuilt">0</span>') == 1

        queued = client.post("/api/environments", json={"job_id": job_id}, headers=headers)
        assert queued.status_code == 200
        # The only job here is finished, so nothing is in front of the rebuild.
        assert queued.json() == {"job_id": "env-abc", "state": "queued", "waiting_for": 0}
        # Rebuilt from that job's own target, not from anything the caller sent.
        assert runner.built == [job_id]


def test_a_rebuild_of_an_unknown_or_unfinished_job_is_refused(tmp_path: Path) -> None:
    app, _job_id, runner = _app_with_candidate(tmp_path)
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}  # type: ignore[attr-defined]
        missing = client.post("/api/environments", json={"job_id": "nope"}, headers=headers)
        assert missing.status_code == 404
        assert runner.built == []


def test_a_rebuild_cannot_be_requested_without_the_csrf_header(tmp_path: Path) -> None:
    app, job_id, runner = _app_with_candidate(tmp_path)
    with TestClient(app) as client:
        client.get("/")
        refused = client.post("/api/environments", json={"job_id": job_id})
        assert refused.status_code == 403
        assert runner.built == []


def test_a_running_environment_is_listed_with_its_login(tmp_path: Path) -> None:
    app, _job_id, runner = _app_with_candidate(tmp_path)
    db_path = tmp_path / "data" / "xentry.db"
    conn = connect(db_path)
    try:
        env_id, _attempt_id, env_dir = create_job(
            conn,
            data_dir=tmp_path / "data",
            poc_url=POC_URL,
            cve_url="https://example.com/cve",
            kind="environment",
        )
        set_plan(
            conn,
            env_id,
            cve_id="CVE-2026-109618",
            target_id="php2shell",
            bundle_sha256="d" * 64,
        )
    finally:
        conn.close()
    # Live state, so it is a plain file with no digest to check against.
    (env_dir / "environment.json").write_text(
        '{"attacker_ip": "10.42.5.20", "attacker_vm": "xentry-e-attacker", '
        '"built_at": "2026-11-12T11:00:00+00:00", '
        '"keys_dir": "/var/lib/xentry/jobs/e/keys", "network_id": "xentry-5", '
        '"poc_dir": "/home/xentry-guest/poc", "target_ip": "10.42.5.10", '
        '"target_vm": "xentry-e-target"}',
        encoding="utf-8",
    )
    with TestClient(app) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}  # type: ignore[attr-defined]

        page = client.get("/vms")
        assert "xentry-e-target" in page.text
        assert "sudo ssh -i /var/lib/xentry/jobs/e/keys/actor" in page.text
        assert "xentry-guest@10.42.5.20" in page.text
        # An environment is not a run, so it must not appear among the jobs.
        assert env_id not in client.get("/jobs").text

        gone = client.post(f"/api/environments/{env_id}/destroy", json={}, headers=headers)
        assert gone.status_code == 200
        assert gone.json() == {"job_id": env_id, "destroyed": True}
        assert runner.destroyed == [env_id]


def test_the_jobs_table_names_the_cve_not_the_target(tmp_path: Path) -> None:
    """target_id is "generic" for every derived job, so it identified nothing.

    The column said the same word down the whole page while the CVE - the one
    thing that tells two runs apart - was only on the job detail page.
    """
    app, job_id, _db = _app_with_job(tmp_path)
    with TestClient(app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "<th>CVE</th>" in page.text
        assert "<th>Target</th>" not in page.text
        assert "CVE-2026-109618" in page.text
        assert job_id[:12] in page.text


def test_every_rendered_timestamp_carries_its_utc_value(tmp_path: Path) -> None:
    """The server keeps writing UTC; the browser localises it.

    A reader should not have to do timezone arithmetic to tell whether a job
    ran before or after something they just did - but the UTC value is what a
    record and a bug report need, so it stays in data-ts and only the DISPLAY
    is local. Nothing is localised server-side, because the server does not
    know the reader's zone.
    """
    app, job_id, _db = _app_with_job(tmp_path)
    with TestClient(app) as client:
        for path in ("/", f"/jobs/{job_id}"):
            page = client.get(path)
            assert page.status_code == 200, path
            assert 'ts" data-ts="' in page.text, path
            # The offset proves it is still the UTC instant, not a local
            # rendering with the zone thrown away.
            assert "+00:00" in page.text, path
