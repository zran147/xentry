"""UI vocabulary and field-separation tests."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from xentry.db import init_db
from xentry.jobstore import create_job, set_plan
from xentry.web.app import build_app

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"
BANNED = ("succeeded", "verified")


def _assert_unbanned(text: str, label: str) -> None:
    lowered = text.lower()
    for word in BANNED:
        assert word not in lowered, f"{label} contains banned word {word}"


def test_rendered_ui_separates_state_verdict_and_authority(tmp_path: Path) -> None:
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
    conn.execute(
        "UPDATE jobs SET outcome='completed', verdict='reproduced', "
        "authority='runner_observed+llm_assessed', reason_code='nonce_observed', "
        "cleanup_state='done' WHERE id=?",
        (job_id,),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        assert page.status_code == 200
        _assert_unbanned(page.text, "job page")
        for label in ("State", "Verdict", "Authority"):
            assert label in page.text
        assert "Audit bundle" in page.text
        assert "Evidence" in page.text
        assert "completed" in page.text
        assert "reproduced" in page.text
        assert "runner_observed+llm_assessed" in page.text

        detail = client.get(f"/api/jobs/{job_id}")
        assert detail.status_code == 200
        payload = detail.json()
        _assert_unbanned(json.dumps(payload), "job json")
        assert payload["job"]["outcome"] == "completed"
        assert payload["job"]["verdict"] == "reproduced"
        assert payload["job"]["authority"] == "runner_observed+llm_assessed"

        bundle = client.get(f"/api/jobs/{job_id}/bundle")
        assert bundle.status_code == 200
        _assert_unbanned(bundle.text, "bundle json")
        assert bundle.json()["job"]["id"] == job_id
