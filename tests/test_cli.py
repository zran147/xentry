"""Cleanup CLI order test."""

from __future__ import annotations

from xentry import cli


class FakeClient:
    def __init__(self, socket_path: str | None = None) -> None:
        self.socket_path = socket_path
        self.calls: list[tuple[str, dict[str, str]]] = []

    def call(self, verb: str, params: dict[str, str] | None = None, **_kwargs: object) -> object:
        params = params or {}
        self.calls.append((verb, params))
        if verb == "list_managed":
            return {
                "domains": [
                    {"name": "xentry-job-target", "state": "running"},
                    {"name": "xentry-job-attacker", "state": "running"},
                ],
                "networks": [{"name": "xentry-job", "active": True}],
            }
        return {"destroyed": True}


def test_cleanup_destroys_attacker_then_target_then_network(monkeypatch) -> None:
    holder: dict[str, FakeClient] = {}

    def factory(socket_path: str | None = None) -> FakeClient:
        client = FakeClient(socket_path)
        holder["client"] = client
        return client

    monkeypatch.setattr("xentry.cli.BrokerClient", factory)
    assert cli.main(["--broker-socket", "/tmp/x", "cleanup", "--force"]) == 0
    calls = holder["client"].calls
    assert calls[0][0] == "list_managed"
    assert [verb for verb, _ in calls[1:]] == ["destroy_vm", "destroy_vm", "destroy_network"]
    assert calls[1][1]["vm_id"] == "xentry-job-attacker"
    assert calls[2][1]["vm_id"] == "xentry-job-target"
    assert calls[3][1]["network_id"] == "xentry-job"
