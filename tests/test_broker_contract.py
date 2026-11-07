"""Broker socket contract tests (Phase 0)."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from broker.main import BrokerServer
from xentry.broker import BrokerClient, BrokerError


@pytest.fixture
def broker(tmp_path: Path):
    server = BrokerServer(
        tmp_path / "broker.sock",
        tmp_path / "journal",
        allowed_uids={os.getuid()},
    )
    server.start()
    yield BrokerClient(tmp_path / "broker.sock", timeout=5.0), tmp_path / "journal"
    server.stop()


def test_ping_and_registry_resolution(broker) -> None:
    client, _ = broker
    assert client.call("ping", job_id="job-1") == {"pong": True}
    assert client.resolve_artifact("php-8.4.26-src") == {"artifact_id": "php-8.4.26-src"}
    assert client.call("resolve_target", {"target_id": "dirtyfrag"}) == {"target_id": "dirtyfrag"}
    assert client.call("resolve_step", {"step_id": "prefix-gitlab-nonce"}) == {
        "step_id": "prefix-gitlab-nonce",
        "allowed_users": ["root"],
        "broker_side": False,
    }


def test_unknown_ids_params_and_verbs_are_rejected(broker) -> None:
    client, _ = broker
    with pytest.raises(BrokerError) as exc:
        client.resolve_artifact("not-an-artifact")
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        client.call("not-a-verb")
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        client.call("resolve_target", {"target_id": "dirtyfrag", "extra": True})
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        client.call("create_target", {"job_id": "j", "target_id": "nope", "image_id": "nope"})
    assert exc.value.code == "broker_registry_rejected"


def test_step_allowlists_and_raw_argv_rejection(broker) -> None:
    client, _ = broker
    setup = client.call("resolve_step", {"step_id": "setup-php"})
    actor = client.call("resolve_step", {"step_id": "run-poc-php"})
    assert setup["allowed_users"] == ["root"]
    assert actor["allowed_users"] == ["xentry-guest"]
    with pytest.raises(BrokerError) as exc:
        client.call(
            "exec",
            {
                "vm_id": "vm-1",
                "step_id": "setup-php",
                "params": {"argv": ["id"]},
                "tty": False,
                "timeout_s": 10,
            },
        )
    assert exc.value.code == "broker_registry_rejected"
    result = client.call(
        "exec",
        {
            "vm_id": "vm-1",
            "step_id": "run-poc-php",
            "params": {},
            "tty": False,
            "timeout_s": 10,
        },
    )
    assert result["status"] == "not_implemented"
    assert result["allowed_users"] == ["xentry-guest"]


def test_copy_in_rejects_traversal(broker) -> None:
    client, _ = broker
    for path in ("../etc/passwd", "/etc/passwd", "a/../../b"):
        with pytest.raises(BrokerError) as exc:
            client.call(
                "copy_in",
                {"vm_id": "vm-1", "artifact_id": "php-8.4.26-src", "guest_path": path},
            )
        assert exc.value.code == "broker_registry_rejected"


def test_destroy_is_idempotent(broker) -> None:
    client, _ = broker
    first = client.destroy_vm("vm-1")
    second = client.destroy_vm("vm-1")
    assert first == second == {"destroyed": True, "vm_id": "vm-1"}
    assert client.destroy_network("net-1") == {"destroyed": True, "network_id": "net-1"}


def test_http_probe_verb_is_present(broker) -> None:
    client, _ = broker
    result = client.call(
        "http_probe",
        {
            "vm_id": "vm-1",
            "network_id": "net-1",
            "port": 8088,
            "method": "GET",
            "path": "/",
            "timeout_s": 10,
            "max_bytes": 4096,
        },
    )
    assert result["status"] == "not_implemented"
    with pytest.raises(BrokerError) as exc:
        client.call(
            "http_probe",
            {
                "vm_id": "vm-1",
                "network_id": "net-1",
                "port": 0,
                "method": "GET",
                "path": "/",
                "timeout_s": 10,
                "max_bytes": 4096,
            },
        )
    assert exc.value.code == "broker_registry_rejected"


def test_proxy_capture_verb_is_present(broker) -> None:
    client, _ = broker
    result = client.call(
        "proxy_capture",
        {"vm_id": "vm-1", "network_id": "net-1", "target_port": 80, "timeout_s": 30},
    )
    assert result["status"] == "not_implemented"
    with pytest.raises(BrokerError) as exc:
        client.call(
            "proxy_capture",
            {"vm_id": "vm-1", "network_id": "net-1", "target_port": 0, "timeout_s": 30},
        )
    assert exc.value.code == "broker_registry_rejected"


def test_broker_calls_journal(broker) -> None:
    client, journal = broker
    client.call("ping", job_id="job-1", attempt_id="attempt-0", seq=7)
    path = journal / "job-1" / "broker_calls.jsonl"
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    record = records[-1]
    assert record["verb"] == "ping"
    assert record["job_id"] == "job-1"
    assert record["attempt_id"] == "attempt-0"
    assert record["seq"] == 7
    assert record["status"] == "ok"
    assert len(record["params_sha256"]) == 64
    assert len(record["result_sha256"]) == 64
    assert client.last_call == record


def test_job_client_attributes_calls_and_sequence(broker) -> None:
    from xentry.runner import _JobBrokerClient

    client, journal = broker
    calls: list[dict[str, object]] = []
    proxy = _JobBrokerClient(client, "job-1", "attempt-0", calls.append)
    assert proxy.call("ping") == {"pong": True}
    assert proxy.call("resolve_target", {"target_id": "dirtyfrag"}) == {"target_id": "dirtyfrag"}
    records = [
        json.loads(line)
        for line in (journal / "job-1" / "broker_calls.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [record["verb"] for record in records] == ["ping", "resolve_target"]
    assert [record["seq"] for record in records] == [1, 2]
    assert [call["id"] for call in calls] == [record["id"] for record in records]


class FakeRuntime:
    def handle(self, verb: str, params: dict[str, object]) -> dict[str, object]:
        return {"runtime_verb": verb, "params": params}


def test_runtime_verbs_are_dispatched(tmp_path: Path) -> None:
    server = BrokerServer(
        tmp_path / "broker.sock",
        tmp_path / "journal",
        allowed_uids={os.getuid()},
        runtime=FakeRuntime(),
    )
    server.start()
    try:
        client = BrokerClient(tmp_path / "broker.sock", timeout=5.0)
        result = client.call("create_network", {"job_id": "job-1", "profile_id": "isolated"})
        assert result == {
            "runtime_verb": "create_network",
            "params": {"job_id": "job-1", "profile_id": "isolated"},
        }
    finally:
        server.stop()


def test_broker_serves_calls_concurrently(tmp_path: Path) -> None:
    class SlowRuntime:
        def handle(self, verb: str, params: dict[str, object]) -> dict[str, object]:
            time.sleep(0.5)
            return {"verb": verb}

    server = BrokerServer(
        tmp_path / "broker.sock",
        tmp_path / "journal",
        allowed_uids={os.getuid()},
        runtime=SlowRuntime(),
    )
    server.start()
    try:
        client = BrokerClient(tmp_path / "broker.sock", timeout=5.0)
        results: list[object] = []

        def call() -> None:
            results.append(
                client.call(
                    "http_probe",
                    {
                        "vm_id": "vm-1",
                        "network_id": "net-1",
                        "port": 80,
                        "method": "GET",
                        "path": "/",
                        "timeout_s": 1,
                        "max_bytes": 1,
                    },
                )
            )

        started = time.monotonic()
        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert time.monotonic() - started < 0.9
        assert results == [{"verb": "http_probe"}, {"verb": "http_probe"}]
    finally:
        server.stop()


def test_peer_uid_is_enforced(tmp_path: Path) -> None:
    server = BrokerServer(
        tmp_path / "broker.sock",
        tmp_path / "journal",
        allowed_uids={os.getuid() + 1},
    )
    server.start()
    try:
        client = BrokerClient(tmp_path / "broker.sock", timeout=5.0)
        with pytest.raises(BrokerError) as exc:
            client.ping()
        assert exc.value.code == "broker_unavailable"
    finally:
        server.stop()
