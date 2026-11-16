"""Runner integration test with a fake broker and model layer."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
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
        self.staged: list[str] = []
        self.nonce = ""
        self.real_phase = False
        self.locked: dict[str, object] | None = None

    def call(self, verb: str, params: dict[str, object], **_kwargs: object) -> object:
        self.calls.append((verb, params))
        if verb == "create_network":
            # The dated apt mirror too: a DERIVED target installs packages
            # from it, and without these keys provision refuses with "no apt
            # mirror is running". The real broker returns them when
            # XENTRY_START_APT_PROXY=1, which is how every derived job on the
            # host has provisioned.
            return {
                "network_id": f"xentry-{params['job_id']}",
                "mirror_url": "http://10.42.0.1:8081",
                "apt_proxy_url": "http://10.42.0.1:8082",
                "apt_snapshot": "20211004T000000Z",
                "apt_archive": "debian",
            }
        if verb == "create_target":
            return {"vm_id": "xentry-job-target", "guest_ip": "10.0.0.10"}
        if verb == "create_attacker":
            return {"vm_id": "xentry-job-attacker", "guest_ip": "10.0.0.20"}
        if verb == "exec":
            return {"exit_code": 0, "stdout": "ok", "stderr": "", "duration_ms": 1}
        if verb == "copy_in":
            return {"remote_path": "/var/lib/xentry/artifacts/poc.tar.gz", "sha256": "a" * 64}
        if verb == "stage_artifact":
            # Staging an operator-approved file. Only the derived REBUILD
            # reaches this in these tests - a checked-in rebuild approves
            # nothing - and without it stage_approved died with "unexpected
            # broker verb", which reads as a product failure rather than a gap
            # in this double.
            self.staged.append(str(params["artifact_id"]))
            return {"artifact_id": params["artifact_id"], "sha256": params["sha256"]}
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
        if verb == "lock_network":
            self.locked = dict(params)
            return {
                "locked": True,
                "target_ports": params.get("target_ports", []),
                "mirror_stopped": True,
                "apt_proxy_stopped": True,
            }
        if verb == "copy_out":
            # The step command trace. Tests that assert on its contents
            # override this with a real file; here the path is absent on
            # purpose, so the runner's best-effort collection stays silent.
            return {"path": "/nonexistent/guest.trace", "sha256": "c" * 64, "bytes": 0}
        raise AssertionError(f"unexpected broker verb: {verb}")


def fake_fetch(url: str, **_options: object) -> Fetched:
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


def fake_gitlab_fetch(url: str, **_options: object) -> Fetched:
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


def _unstable_fetch() -> Callable[[str], Fetched]:
    """A fetch that never returns the same bytes twice.

    This is what NVD behind Cloudflare does: identical content, but a
    per-request `ray` id in the markup, so every fetch hashes differently.
    """
    counter = {"n": 0}

    def fetch_fn(url: str, **_options: object) -> Fetched:
        counter["n"] += 1
        text = (
            "CVE-2026-109618\nPHP 8.4.0 ~ 8.4.26\nApache mod_php\nport 8088\n"
            f"<!-- ray={counter['n']:016x} -->\n"
        )
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

    return fetch_fn


def test_stored_sources_survive_an_unstable_page(tmp_path: Path) -> None:
    """A job whose CVE page changes bytes between check and run still runs."""
    from xentry.fetch import bundle_sha256
    from xentry.sourcestore import save

    fetch_fn = _unstable_fetch()
    # What the link check fetched and approved.
    approved_cve = fetch_fn("https://example.com/cve")
    approved_poc = fetch_fn(
        "https://raw.githubusercontent.com/78ResearchLab/"
        "PHP2Shell-Full-Chain-Exploit/167085410a9342fafbd1bd64f5006920dbc83b8e/README.md"
    )
    approved_bundle = bundle_sha256([approved_cve, approved_poc])

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
        check_id="storedcheck1",
        bundle_sha256=approved_bundle,
    )
    conn.close()
    save(tmp_path, "storedcheck1", {"cve": approved_cve, "poc": approved_poc})

    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fetch_fn,
        broker_factory=lambda: broker,
    )
    runner.run_job(
        job_id, "https://example.com/cve", POC_URL, attempt_id, approved_bundle
    )

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["reason_code"] != "source_unavailable"
        assert job["outcome"] == "completed"
        assert job["verdict"] == "reproduced"
    finally:
        conn.close()


def test_missing_store_still_guards_changed_sources(tmp_path: Path) -> None:
    """Without stored bytes the digest comparison remains the safety net."""
    from xentry.fetch import bundle_sha256

    fetch_fn = _unstable_fetch()
    approved_cve = fetch_fn("https://example.com/cve")
    approved_poc = fetch_fn("https://example.com/poc")
    approved_bundle = bundle_sha256([approved_cve, approved_poc])

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
        check_id="absentcheck",
        bundle_sha256=approved_bundle,
    )
    conn.close()
    # No save(): the store is empty, so the runner re-fetches and the digests
    # cannot agree.
    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fetch_fn,
        broker_factory=lambda: broker,
    )
    runner.run_job(
        job_id, "https://example.com/cve", POC_URL, attempt_id, approved_bundle
    )

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "source_unavailable"
    finally:
        conn.close()


def test_hold_keeps_vms_until_the_ttl_expires(tmp_path: Path) -> None:
    """With a hold configured the VMs survive the probe, then are destroyed."""
    from xentry.jobstore import list_artifacts

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
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
        hold_s=0.3,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        # The TTL is mandatory: nothing stays up waiting for a person forever.
        assert job["cleanup_state"] == "done"
        assert job["outcome"] == "completed"
        assert job["verdict"] == "reproduced"
        kinds = {str(a["kind"]) for a in list_artifacts(conn, job_id)}
        assert "held_vms" in kinds
    finally:
        conn.close()
    # Teardown still happened, and the verdict came after it.
    assert "xentry-job-attacker" in broker.destroyed
    assert "xentry-job-target" in broker.destroyed


def test_release_ends_the_hold_early(tmp_path: Path) -> None:
    """Pressing release destroys the VMs without waiting out the TTL."""
    import threading
    import time as _time

    from xentry.jobstore import list_held_jobs, request_release

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
    )
    conn.close()

    released = threading.Event()

    def releaser() -> None:
        # Wait for the hold, then release it, as the page's button does.
        for _ in range(600):
            watch = connect(db_path)
            try:
                if any(job["id"] == job_id for job in list_held_jobs(watch)):
                    assert request_release(watch, job_id)
                    released.set()
                    return
            finally:
                watch.close()
            _time.sleep(0.01)

    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
        hold_s=60.0,
    )
    watcher = threading.Thread(target=releaser, daemon=True)
    watcher.start()
    started = _time.monotonic()
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    elapsed = _time.monotonic() - started
    watcher.join(timeout=5)

    assert released.is_set(), "the job never reached the held state"
    assert elapsed < 30, f"release did not shorten the 60s hold (took {elapsed:.1f}s)"
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["cleanup_state"] == "done"
        assert job["verdict"] == "reproduced"
    finally:
        conn.close()


def test_no_hold_destroys_immediately(tmp_path: Path) -> None:
    """hold_s=0 keeps the original behaviour: no held state is ever recorded."""
    from xentry.jobstore import list_artifacts

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
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
        kinds = {str(a["kind"]) for a in list_artifacts(conn, job_id)}
        assert "held_vms" not in kinds
    finally:
        conn.close()


def _run_with_indefinite_hold(tmp_path: Path, ender: str) -> dict[str, object]:
    """Run a job held with no deadline, ended by release or cancel."""
    import threading
    import time as _time

    from xentry.jobstore import list_held_jobs, request_cancel, request_release

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
    )
    conn.close()
    acted = threading.Event()

    def actor() -> None:
        for _ in range(1500):
            watch = connect(db_path)
            try:
                if any(job["id"] == job_id for job in list_held_jobs(watch)):
                    if ender == "release":
                        assert request_release(watch, job_id)
                    else:
                        request_cancel(watch, job_id)
                    acted.set()
                    return
            finally:
                watch.close()
            _time.sleep(0.01)

    broker = FakeBroker()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
        hold_s=-1.0,
    )
    watcher = threading.Thread(target=actor, daemon=True)
    watcher.start()
    started = _time.monotonic()
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)
    elapsed = _time.monotonic() - started
    watcher.join(timeout=5)
    assert acted.is_set(), "the job never reached the held state"
    # No deadline: only the human action can have ended this.
    assert elapsed < 60, f"hold did not end promptly ({elapsed:.1f}s)"
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        return dict(job)
    finally:
        conn.close()


def test_indefinite_hold_ends_only_on_release(tmp_path: Path) -> None:
    job = _run_with_indefinite_hold(tmp_path, "release")
    assert job["cleanup_state"] == "done"
    assert job["outcome"] == "completed"
    assert job["verdict"] == "reproduced"


def test_indefinite_hold_can_also_be_escaped_by_cancel(tmp_path: Path) -> None:
    """Cancel is the second way out, so a held job is never unreclaimable.

    It tears down and still reports the verdict rather than discarding it: by
    the time a job is held the exploit has already run and the evidence is
    already recorded, so there is nothing left to abort and throwing the
    result away would lose real information.
    """
    job = _run_with_indefinite_hold(tmp_path, "cancel")
    assert job["cleanup_state"] == "done"
    assert job["outcome"] == "completed"
    assert job["verdict"] == "reproduced"


def test_provision_script_is_recorded_as_evidence(tmp_path: Path) -> None:
    """The script the broker runs lands in the evidence at its pinned digest."""
    import yaml

    from xentry.jobstore import list_artifacts

    repo = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
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

    source = repo / "targets" / "php2shell" / "setup.sh"
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    conn = connect(db_path)
    try:
        scripts = [a for a in list_artifacts(conn, job_id) if a["kind"] == "setup_script"]
        assert len(scripts) == 1
        assert scripts[0]["sha256"] == expected
        assert scripts[0]["bytes"] == len(source.read_bytes())
    finally:
        conn.close()
    # The bytes are kept with the attempt, and are the same ones the broker
    # re-verifies on the guest against the pinned manifest digest.
    assert (attempt_dir / "setup.sh").read_bytes() == source.read_bytes()
    manifest = yaml.safe_load((repo / "targets" / "steps.yaml").read_text(encoding="utf-8"))
    assert manifest["steps"]["setup-php"]["sha256"] == expected


class TracingBroker(FakeBroker):
    """A broker that serves a guest command trace through copy_out."""

    trace_text = "+ set -euo pipefail\n+ curl -fsS http://mirror/artifacts/php\n+ make -j4\n"

    def __init__(self, trace_dir: Path) -> None:
        super().__init__()
        self.trace_path = trace_dir / "guest.trace"
        self.trace_path.write_text(self.trace_text, encoding="utf-8")

    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        if verb == "copy_out":
            self.calls.append((verb, params))
            return {"path": str(self.trace_path), "sha256": "a" * 64, "bytes": 1}
        return super().call(verb, params, **kwargs)


def test_provision_commands_are_collected_and_recorded(tmp_path: Path) -> None:
    """The traced commands land beside the attempt and in the evidence."""
    from xentry.jobstore import list_artifacts

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
        conn,
        data_dir=tmp_path,
        poc_url=POC_URL,
        cve_url="https://example.com/cve",
    )
    conn.close()
    broker = TracingBroker(tmp_path)
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

    commands = attempt_dir / "provision-commands.txt"
    assert commands.read_text(encoding="utf-8") == TracingBroker.trace_text
    conn = connect(db_path)
    try:
        digests = {a["sha256"] for a in list_artifacts(conn, job_id)}
        assert hashlib.sha256(TracingBroker.trace_text.encode()).hexdigest() in digests
    finally:
        conn.close()


def test_the_provisioning_channel_closes_before_any_poc_code_runs(tmp_path: Path) -> None:
    """locked_rules existed, was tested, and had no caller.

    The apt proxy and the artifact mirror are host services the target reaches
    over the job bridge during provisioning. They used to stay reachable for the
    life of the job, which handed a stranger's exploit the one path off its own
    bridge while it ran. The lock now happens after readiness, and the ports it
    opens are the target's declared ones.
    """
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _ = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
    )
    conn.close()
    broker = FakeBroker()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)

    verbs = [verb for verb, _params in broker.calls]
    assert "lock_network" in verbs, verbs
    assert broker.locked is not None
    assert broker.locked["target_ports"] == [8088]

    lock_at = verbs.index("lock_network")
    poc_steps = {"build-poc-php", "run-poc-php", "null-php"}
    for index, (verb, params) in enumerate(broker.calls):
        if verb == "exec" and str(params.get("step_id")) in poc_steps:
            assert index > lock_at, f"{params.get('step_id')} ran before the lock"
        if verb in {"copy_in", "place_nonce", "snapshot"}:
            assert index > lock_at, f"{verb} ran before the lock"


def test_a_failure_between_steps_is_recorded_where_a_reader_looks(
    tmp_path: Path,
) -> None:
    """Job 9cca773bf56c failed with nothing to show for it.

    The per-step handler writes detail onto its own row. The outer handler, for
    an exception raised BETWEEN steps, kept str(exc) in a local and dropped it
    - so that job ended `harness_error` with every recorded step passed, no
    failed step, and nothing in the journal either, because uvicorn never sees
    the runner's exception. There was no way at all to learn what it had been.
    """
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
    )
    conn.close()

    def explode(_artifacts: object) -> Facts:
        raise RuntimeError("the shape of the thing that went wrong")

    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=explode,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=FakeBroker,
    )
    runner.run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)

    conn = connect(db_path)
    try:
        failed = [s for s in list_steps(conn, job_id) if s["state"] == "failed"]
    finally:
        conn.close()
    assert failed, "a failure with no step left nothing for a reader to see"
    # The message, not just the code - the code was never the missing part.
    assert "the shape of the thing that went wrong" in str(failed[-1]["detail"])


def test_a_cancelled_job_does_not_get_a_synthetic_step() -> None:
    """"cancelled" and "deadline_exceeded" say everything in the reason_code.

    A row per cancelled job would be noise in the very table the synthetic row
    exists to make readable, so those two are excluded by name.
    """
    from xentry.runner import SELF_EVIDENT

    assert "cancelled" in SELF_EVIDENT
    assert "deadline_exceeded" in SELF_EVIDENT


def test_a_failed_step_keeps_both_streams() -> None:
    """A wordpress provision failed with a 56-character detail.

    The site read `stderr or stdout`, and apt splits a failure across the two:
    the diagnosis goes to stdout - "dpkg: error processing package ..." - and
    only the summary to stderr - "E: Sub-process /usr/bin/dpkg returned an
    error code (1)". stderr being non-empty meant stdout was never consulted,
    so the detail named neither the package nor the reason. Both halves are
    needed: the step scripts write their own messages to stderr.
    """
    both = JobRunner._output({
        "stdout": "dpkg: error processing package wordpress (--configure):\n"
                  " subprocess returned error exit status 1",
        "stderr": "E: Sub-process /usr/bin/dpkg returned an error code (1)",
    })
    assert "error processing package wordpress" in both
    assert "E: Sub-process" in both

    # A script that writes only to stderr must keep working - that is where
    # setup-generic.sh puts "nothing is listening on port 80".
    only_err = JobRunner._output(
        {"stdout": "", "stderr": "nothing is listening on port 80"}
    )
    assert only_err == "nothing is listening on port 80"
    assert JobRunner._output({"stdout": "boom", "stderr": ""}) == "boom"
    assert JobRunner._output({"stdout": "", "stderr": "   "}) == ""


def test_apt_progress_does_not_crowd_out_the_diagnosis() -> None:
    """Keeping both streams was not enough; the tail was the wrong shape.

    The wordpress provision named its failing package only because the summary
    happened to be last. dpkg's REASON - "trying to overwrite ..., which is
    also in package ..." - sat above 95 lines of "Unpacking ..." and fell off
    the end of a 1500-character tail. Dropping apt's progress chatter keeps the
    error AND the indented continuation under it, which a grep for "error"
    would have cut in half.
    """
    stdout = "\n".join(
        [
            (
                "dpkg: error processing archive "
                "/tmp/48-libcurl4-gnutls_8.21.0-2_amd64.deb (--unpack):"
            ),
            (
                " trying to overwrite '/usr/lib/x86_64-linux-gnu/libcurl.so.4.8.0', "
                "which is also in package libcurl4 7.74.0-1.3"
            ),
        ]
        + [f"Unpacking package-{n} (1.0-{n}) ..." for n in range(95)]
        + ["Errors were encountered while processing:",
           " /tmp/48-libcurl4-gnutls_8.21.0-2_amd64.deb"]
    )
    got = JobRunner._output(
        {"stdout": stdout, "stderr": "E: Sub-process /usr/bin/dpkg returned an error code (1)"}
    )
    assert "trying to overwrite" in got, "the reason was lost again"
    assert "also in package libcurl4" in got
    assert "Unpacking package-50" not in got, "progress chatter survived"
    assert len(got) < 600, f"{len(got)} chars - the filter is not filtering"
