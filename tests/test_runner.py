"""Runner integration test with a fake broker and model layer."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from xentry.broker import BrokerError
from xentry.db import connect, init_db
from xentry.fetch import Fetched
from xentry.jobstore import create_job, get_job, list_steps, list_validations
from xentry.models import Facts, LlmVerdict
from xentry.runner import JobRunner

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


class FakeBroker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.destroyed: list[str] = []
        self.nonce = ""
        self.real_phase = False

    def call(self, verb: str, params: dict[str, object], **_kwargs: object) -> object:
        self.calls.append((verb, params))
        if verb == "create_network":
            return {"network_id": f"xentry-{params['job_id']}", "mirror_url": "http://10.42.0.1:8081"}
        if verb == "create_target":
            return {"vm_id": "xentry-job-target", "guest_ip": "10.0.0.10"}
        if verb == "create_attacker":
            return {"vm_id": "xentry-job-attacker", "guest_ip": "10.0.0.20"}
        if verb == "exec":
            return {"exit_code": 0, "stdout": "ok", "stderr": "", "duration_ms": 1}
        if verb == "copy_in":
            return {"remote_path": "/var/lib/xentry/artifacts/poc.tar.gz", "sha256": "a" * 64}
        if verb == "snapshot":
            return {"snapshot_id": "snap-1", "kind": params["kind"]}
        if verb == "restore":
            return {"snapshot_id": params["snapshot_id"], "restored": True}
        if verb == "place_nonce":
            self.nonce = str(params["value"])
            self.real_phase = str(params["nonce_id"]).startswith("real-")
            return {"sha256": hashlib.sha256(self.nonce.encode()).hexdigest()}
        if verb == "http_probe":
            if self.real_phase:
                return {
                    "status": 200,
                    "body_text": self.nonce,
                    "body_sha256": hashlib.sha256(self.nonce.encode()).hexdigest(),
                }
            return {"status": 404, "body_text": "", "body_sha256": "b" * 64}
        if verb == "destroy_vm":
            self.destroyed.append(str(params["vm_id"]))
            return {"destroyed": True}
        if verb == "destroy_network":
            self.destroyed.append(str(params["network_id"]))
            return {"destroyed": True}
        raise AssertionError(f"unexpected broker verb: {verb}")


def fake_fetch(url: str) -> Fetched:
    text = "CVE-2026-109618\nPHP 8.4.0 ~ 8.4.26\nApache mod_php\nport 8088\n"
    body = text.encode()
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers={},
        body=body,
        text=text,
        sha256=hashlib.sha256(body).hexdigest(),
    )


def fake_extract(_artifacts: object) -> Facts:
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


def fake_validate(_facts: object, _narrative: object) -> tuple[LlmVerdict, str, str]:
    return (
        LlmVerdict(
            verdict="reproduced",
            reason_code="ok",
            evidence_refs=["e1"],
            explanation="nonce observed",
        ),
        "fake-model",
        "c" * 64,
    )


class FakeDirtyBroker(FakeBroker):
    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        if verb == "create_attacker":
            raise AssertionError("dirtyfrag must not create an attacker")
        if verb == "snapshot":
            raise AssertionError("dirtyfrag must not snapshot")
        if verb == "reboot":
            self.calls.append((verb, params))
            return {"boot_id": "boot-2", "state": "running"}
        if verb == "read_host_evidence":
            data = f"serial console\n{self.nonce}\n".encode()
            return {
                "bytes_b64": base64.b64encode(data).decode("ascii"),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        if verb == "exec":
            self.calls.append((verb, params))
            step_id = str(params.get("step_id", ""))
            if step_id == "run-poc-dirtyfrag":
                return {
                    "exit_code": 0,
                    "stdout": f"uid=0\n{self.nonce}\n",
                    "stderr": "",
                    "duration_ms": 1,
                }
            return {"exit_code": 0, "stdout": "ok", "stderr": "", "duration_ms": 1}
        return super().call(verb, params, **kwargs)


def fake_dirty_extract(_artifacts: object) -> Facts:
    return Facts(
        cve_id="CVE-2026-43500",
        product="Linux kernel",
        affected_range="6.17.0-23-generic",
        version_evidence=[],
        protocol="local",
        ports=[],
        auth_required=False,
        build_strategy="gcc exp.c",
        poc_context="local",
        citations=[],
    )


def test_dirtyfrag_runner_uses_guest_authority(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    dirty_url = "https://github.com/V4bel/dirtyfrag"
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=dirty_url,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FakeDirtyBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_dirty_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", dirty_url, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["target_id"] == "dirtyfrag"
        assert job["outcome"] == "completed"
        assert job["verdict"] == "reproduced"
        assert job["authority"] == "guest_attested+llm_assessed"
        steps = list_steps(conn, job_id)
        names = [step["name"] for step in steps]
        assert "reboot" in names
        assert "fresh_boot" in names
        assert broker.destroyed == ["xentry-job-target", f"xentry-{job_id}"]
    finally:
        conn.close()


GITLAB_URL = "https://github.com/gagaltotal/CVE-2026-85706-gitlab-poc"


class FakeGitlabBroker(FakeBroker):
    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        if verb == "proxy_capture":
            self.calls.append((verb, params))
            return {
                "text": f"HTTP/1.1 400 Bad Request\r\n\r\n{self.nonce}",
                "sha256": hashlib.sha256(self.nonce.encode()).hexdigest(),
                "bytes": 42,
                "path": "/tmp/capture.pcap",
            }
        return super().call(verb, params, **kwargs)


def fake_gitlab_fetch(url: str) -> Fetched:
    text = "CVE-2026-85706\nGitLab CE/EE 18.7 - 19.3.1\nWorkhorse file read\n"
    body = text.encode()
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers={},
        body=body,
        text=text,
        sha256=hashlib.sha256(body).hexdigest(),
    )


def fake_gitlab_extract(_artifacts: object) -> Facts:
    return Facts(
        cve_id="CVE-2026-85706",
        product="GitLab",
        affected_range="18.7 - 19.3.1",
        version_evidence=[],
        protocol="http",
        ports=[80, 443],
        auth_required=False,
        build_strategy="go build",
        poc_context="remote",
        citations=[],
    )


def test_gitlab_runner_uses_target_capture_for_authority(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=GITLAB_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FakeGitlabBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_gitlab_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_gitlab_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", GITLAB_URL, attempt_id)

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["target_id"] == "gitlab"
        assert job["outcome"] == "completed"
        assert job["authority"] == "runner_observed+llm_assessed"
        names = [step["name"] for step in list_steps(conn, job_id)]
        assert "freeze" in names
        assert "restore" in names
        assert "target_probe" in names
        capture_calls = [params for verb, params in broker.calls if verb == "proxy_capture"]
        assert capture_calls
        assert capture_calls[0]["target_port"] == 80
    finally:
        conn.close()


class FailingCaptureBroker(FakeGitlabBroker):
    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        if verb == "proxy_capture":
            raise BrokerError("proxy_capture_failed", "capture permission denied")
        return super().call(verb, params, **kwargs)


def test_gitlab_capture_failure_fails_the_job(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=GITLAB_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FailingCaptureBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_gitlab_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_gitlab_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", GITLAB_URL, attempt_id)

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "proxy_capture_failed"
        assert job["cleanup_state"] == "done"
    finally:
        conn.close()


def test_php_runner_completes_with_nonce(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["target_id"] == "php2shell"
        assert job["outcome"] == "completed"
        assert job["verdict"] == "reproduced"
        assert job["cleanup_state"] == "done"
        assert job["final_attempt_id"] == attempt_id
        steps = list_steps(conn, job_id)
        assert steps
        assert all(step["state"] == "passed" for step in steps)
        validations = list_validations(conn, job_id)
        assert len(validations) == 1
        assert validations[0]["verdict"] == "reproduced"
        assert broker.destroyed == [
            "xentry-job-attacker",
            "xentry-job-target",
            f"xentry-{job_id}",
        ]
        assert any(verb == "place_nonce" and str(params["nonce_id"]).startswith("real-") for verb, params in broker.calls)
    finally:
        conn.close()


def test_nonce_value_is_absent_from_validator_input_and_sqlite(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FakeBroker()
    observed: dict[str, object] = {}

    def spy_validate(facts: object, narrative: object) -> tuple[LlmVerdict, str, str]:
        observed["facts"] = facts
        observed["narrative"] = narrative
        return fake_validate(facts, narrative)

    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=spy_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)

    nonce = broker.nonce
    assert len(nonce) == 32
    opaque = json.dumps(
        {
            "facts": observed["facts"].__dict__,
            "narrative": observed["narrative"].__dict__,
        },
        sort_keys=True,
    )
    assert nonce not in opaque
    assert nonce not in db_path.read_bytes().decode("utf-8", "replace")

    conn = connect(db_path)
    try:
        rows = conn.execute("SELECT sha256 FROM nonces WHERE job_id=?", (job_id,)).fetchall()
        assert len(rows) == 2
        assert hashlib.sha256(nonce.encode()).hexdigest() in {row[0] for row in rows}
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(nonces)").fetchall()
        }
        assert "value" not in columns
    finally:
        conn.close()


def test_job_deadline_stops_before_the_next_step(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
        job_deadline_s=0.0,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "deadline_exceeded"
        assert job["cleanup_state"] == "done"
        assert list_steps(conn, job_id) == []
    finally:
        conn.close()


def test_cancellation_before_the_next_step_runs_cleanup(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
    conn.commit()
    conn.close()
    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "cancelled"
        assert job["verdict"] == "not_run"
        assert job["reason_code"] == "cancelled"
        assert job["cleanup_state"] == "done"
        assert broker.destroyed == []
    finally:
        conn.close()


class MetadataBroker(FakeBroker):
    def __init__(self) -> None:
        super().__init__()
        self.metas: list[dict[str, object]] = []
        self.last_call: dict[str, object] | None = None

    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        self.metas.append(dict(kwargs))
        result = super().call(verb, params, **kwargs)
        self.last_call = {
            "id": f"call-{len(self.metas)}",
            "seq": kwargs.get("seq", 0),
            "verb": verb,
            "params_sha256": "a" * 64,
            "status": "ok",
        }
        return result


def test_broker_calls_are_attributed_and_indexed(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = MetadataBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    assert broker.metas
    assert all(meta.get("job_id") == job_id for meta in broker.metas)
    assert all(meta.get("attempt_id") == attempt_id for meta in broker.metas)
    assert [meta.get("seq") for meta in broker.metas] == list(
        range(1, len(broker.metas) + 1)
    )
    conn = connect(db_path)
    try:
        rows = conn.execute(
            "SELECT verb, job_id, attempt_id FROM broker_calls ORDER BY seq"
        ).fetchall()
        assert len(rows) == len(broker.metas)
        assert {row["job_id"] for row in rows} == {job_id}
        assert {row["attempt_id"] for row in rows} == {attempt_id}
    finally:
        conn.close()


def test_target_deadline_overrides_the_global_deadline(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
        target_deadlines={"php2shell": 0.0},
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["reason_code"] == "deadline_exceeded"
        assert [step["name"] for step in list_steps(conn, job_id)] == [
            "fetch",
            "extract",
            "plan",
        ]
        assert not any(verb == "create_network" for verb, _params in broker.calls)
    finally:
        conn.close()


class AttackerStuckBroker(FakeBroker):
    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        if verb == "destroy_vm" and str(params.get("vm_id", "")).endswith("-attacker"):
            self.calls.append((verb, params))
            raise BrokerError("teardown_failed", "attacker stuck")
        return super().call(verb, params, **kwargs)


def test_teardown_continues_after_one_destroy_failure(tmp_path: Path) -> None:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = AttackerStuckBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "security_cleanup_failed"
        assert job["cleanup_state"] == "failed"
        destroys = [params for verb, params in broker.calls if verb == "destroy_vm"]
        assert {"vm_id": "xentry-job-target"} in destroys
        assert any(verb == "destroy_network" for verb, _params in broker.calls)
    finally:
        conn.close()
