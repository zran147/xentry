"""Restart recovery for jobs whose in-memory queue entries were lost."""

from __future__ import annotations

from pathlib import Path

import pytest

from xentry.broker import BrokerError
from xentry.db import connect, init_db
from xentry.fetch import Fetched
from xentry.jobstore import create_job, get_job, record_outcome
from xentry.models import Facts
from xentry.runner import JobRunner

POC_URL = "https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit"


class RecoveryBroker:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, verb: str, params: dict[str, object] | None = None, **kwargs: object) -> object:
        self.calls.append((verb, params or {}))
        if verb == "list_managed":
            return {
                "domains": [
                    {"name": "xentry-job-target", "state": "running"},
                    {"name": "xentry-job-attacker", "state": "running"},
                    {"name": "xentry-other-target", "state": "running"},
                ],
                "networks": [
                    {"name": "xentry-job", "active": True},
                    {"name": "xentry-other", "active": True},
                ],
            }
        if verb in {"destroy_vm", "destroy_network"}:
            return {"destroyed": True}
        raise AssertionError(f"unexpected verb: {verb}")


class UnavailableBroker:
    def call(self, verb: str, params: dict[str, object] | None = None, **kwargs: object) -> object:
        raise BrokerError("broker_unavailable", "socket missing")


def _runner(tmp_path: Path, broker: object) -> JobRunner:
    return JobRunner(
        db_path=tmp_path / "xentry.db",
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: Facts(
            cve_id="CVE-2026-109618",
            product="PHP",
            affected_range="8.4.0 ~ 8.4.26",
            version_evidence=[],
            protocol="http",
            ports=[8088],
            auth_required=False,
            build_strategy="source build",
            poc_context="remote",
            citations=[],
        ),
        validate_fn=lambda _facts, _narrative: (None, "fake", "0" * 64),
        fetch_fn=lambda url: Fetched(
            url=url,
            final_url=url,
            status=200,
            headers={},
            body=b"source",
            text="source",
            sha256="a" * 64,
        ),
        broker_factory=lambda: broker,  # type: ignore[return-value]
    )


def _unfinished_job(db_path: Path, data_dir: Path, job_id: str = "job") -> tuple[str, str]:
    conn = init_db(db_path)
    try:
        created, attempt_id, _ = create_job(
            conn,
            data_dir=data_dir,
            poc_url=POC_URL,
            cve_url="https://example.com/cve",
        )
    finally:
        conn.close()
    return created, attempt_id


def test_recovery_marks_interrupted_and_destroys_managed(
    tmp_path: Path,
) -> None:
    job_id, _attempt_id = _unfinished_job(tmp_path / "xentry.db", tmp_path)
    finished_job, finished_attempt = _unfinished_job(
        tmp_path / "xentry.db", tmp_path
    )
    conn = connect(tmp_path / "xentry.db")
    try:
        record_outcome(
            conn,
            job_id=finished_job,
            attempt_id=finished_attempt,
            outcome="completed",
            verdict="inconclusive",
            authority="runner_observed",
            reason_code="validator_error",
        )
    finally:
        conn.close()
    # The broker's managed names use the contract's xentry-<job_id>-<role>
    # convention, so make the fixture describe these jobs.
    class NamedBroker(RecoveryBroker):
        def call(self, verb: str, params: dict[str, object] | None = None, **kwargs: object) -> object:
            if verb == "list_managed":
                return {
                    "domains": [
                        {"name": f"xentry-{job_id}-target", "state": "running"},
                        {"name": f"xentry-{job_id}-attacker", "state": "running"},
                    ],
                    "networks": [{"name": f"xentry-{job_id}", "active": True}],
                }
            return super().call(verb, params, **kwargs)

    broker = NamedBroker()
    runner = _runner(tmp_path, broker)
    recovered = runner.recover_interrupted()
    assert recovered == [job_id]

    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "interrupted"
        assert job["verdict"] == "not_run"
        assert job["authority"] == "runner_observed"
        assert job["reason_code"] == "interrupted"
        assert job["cleanup_state"] == "done"
        untouched = get_job(conn, finished_job)
        assert untouched is not None
        assert untouched["outcome"] == "completed"
        assert untouched["reason_code"] == "validator_error"
    finally:
        conn.close()

    assert broker.calls == [
        ("destroy_vm", {"vm_id": f"xentry-{job_id}-attacker"}),
        ("destroy_vm", {"vm_id": f"xentry-{job_id}-target"}),
        ("destroy_network", {"network_id": f"xentry-{job_id}"}),
    ]


def test_recovery_without_broker_leaves_cleanup_pending(tmp_path: Path) -> None:
    job_id, _attempt_id = _unfinished_job(tmp_path / "xentry.db", tmp_path)
    runner = _runner(tmp_path, UnavailableBroker())
    assert runner.recover_interrupted() == [job_id]
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "interrupted"
        assert job["cleanup_state"] == "pending"
    finally:
        conn.close()


def test_recovery_continues_after_one_destroy_failure(tmp_path: Path) -> None:
    job_id, _attempt_id = _unfinished_job(tmp_path / "xentry.db", tmp_path)

    class PartialBroker(RecoveryBroker):
        def call(self, verb: str, params: dict[str, object] | None = None, **kwargs: object) -> object:
            if verb == "list_managed":
                return {
                    "domains": [
                        {"name": f"xentry-{job_id}-target", "state": "running"},
                        {"name": f"xentry-{job_id}-attacker", "state": "running"},
                    ],
                    "networks": [{"name": f"xentry-{job_id}", "active": True}],
                }
            if verb == "destroy_vm" and str((params or {}).get("vm_id", "")).endswith("-attacker"):
                self.calls.append((verb, params or {}))
                raise BrokerError("teardown_failed", "attacker stuck")
            return super().call(verb, params, **kwargs)

    broker = PartialBroker()
    runner = _runner(tmp_path, broker)
    assert runner.recover_interrupted() == [job_id]
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["reason_code"] == "security_cleanup_failed"
        assert job["cleanup_state"] == "failed"
    finally:
        conn.close()
    assert ("destroy_vm", {"vm_id": f"xentry-{job_id}-target"}) in broker.calls
    assert ("destroy_network", {"network_id": f"xentry-{job_id}"}) in broker.calls


def test_submit_is_blocked_until_failed_cleanup_is_resolved(tmp_path: Path) -> None:
    job_id, _attempt_id = _unfinished_job(tmp_path / "xentry.db", tmp_path)
    conn = connect(tmp_path / "xentry.db")
    try:
        from xentry.jobstore import set_cleanup_state

        set_cleanup_state(conn, job_id, "failed")
    finally:
        conn.close()

    class ManagedBroker(RecoveryBroker):
        def __init__(self, names: list[str]):
            super().__init__()
            self.names = names

        def call(self, verb: str, params: dict[str, object] | None = None, **kwargs: object) -> object:
            if verb == "list_managed":
                return {
                    "domains": [{"name": name, "state": "running"} for name in self.names],
                    "networks": [],
                }
            return super().call(verb, params, **kwargs)

    blocked = ManagedBroker([f"xentry-{job_id}-target"])
    runner = _runner(tmp_path, blocked)
    with pytest.raises(BrokerError) as exc:
        runner.submit("https://example.com/cve", POC_URL)
    assert exc.value.code == "security_cleanup_failed"

    clear = ManagedBroker([])
    runner = _runner(tmp_path, clear)
    new_job = runner.submit("https://example.com/cve", POC_URL)
    assert new_job != job_id
    conn = connect(tmp_path / "xentry.db")
    try:
        resolved = get_job(conn, job_id)
        assert resolved is not None
        assert resolved["cleanup_state"] == "done"
    finally:
        conn.close()
