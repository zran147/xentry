"""Web app smoke tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from xentry.broker import BrokerError
from xentry.db import connect
from xentry.fetch import Fetched
from xentry.jobstore import create_job, record_artifact, set_plan
from xentry.models import Facts
from xentry.web.app import build_app

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


class FakeRunner:
    def __init__(self) -> None:
        self.submitted: list[tuple[str, str, str | None, str | None]] = []

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
    ) -> str:
        self.submitted.append((cve_url, poc_url, check_id, bundle_sha256))
        return "job-abc"


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
