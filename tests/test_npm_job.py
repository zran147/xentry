"""An application-package job, end to end through the runner.

The lab, the dependency versions and the two closure ids here are the real
ones from briskets/CVE-2026-126187-poc, resolved on this host.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path
from typing import Any

import pytest

from tests.test_generic_target import GenericBroker
from tests.test_runner import fake_validate
from xentry.db import connect, init_db
from xentry.fetch import Fetched
from xentry.jobstore import create_job, get_job, list_steps
from xentry.models import Facts
from xentry.runner import JobRunner

POC_REPO = "https://github.com/briskets/CVE-2026-126187-poc"
LAB = """{
  "name": "ghsa-xqc2-lab",
  "private": true,
  "scripts": {"build": "next build", "start": "next start -p 3100"},
  "dependencies": {"next": "16.4.0", "react": "19.3.0", "react-dom": "19.3.0"}
}"""
CUTOFF = "2026-11-09T00:00:00Z"


def _archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        info = tarfile.TarInfo("repo/poc.py")
        body = b"print('poc')\n"
        info.size = len(body)
        handle.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


ARCHIVE = _archive()


# The advisory as the extractor sees it: one `path: value` line per field.
# Its publication date is what dates the registry mirror, exactly as it dates
# the apt snapshot serial, so a fixture without one is not a fixture at all.
ADVISORY = (
    "cveMetadata.cveId: CVE-2026-126187\n"
    "cveMetadata.datePublished: 2026-11-10T22:33:57.528Z\n"
    "containers.cna.title: React: Unauthenticated Remote Code Execution\n"
)


def _fetch(url: str, **_options: object) -> Fetched:
    if "codeload" in url:
        body = ARCHIVE
    elif url.endswith("/lab/package.json"):
        body = LAB.encode()
    else:
        body = ADVISORY.encode()
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers={},
        body=body,
        text=body.decode("utf-8", "replace"),
        sha256=hashlib.sha256(body).hexdigest(),
    )


def _facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "cve_id": "CVE-2026-126187",
        "product": "React",
        "affected_range": "< 19.3.1",
        "version_evidence": [],
        "protocol": "http",
        "ports": [3100],
        "auth_required": False,
        "build_strategy": "docker build ./lab",
        "poc_context": "remote",
        "setup_packages": [],
        "setup_units": [],
        "app_dir": "lab",
        "fixed_versions": ["19.0.9", "19.1.10", "19.2.9", "19.3.1"],
        "poc_entrypoint": "poc.py",
        "citations": [],
    }
    base.update(overrides)
    return Facts(**base)


class NpmBroker(GenericBroker):
    """Answers the ecosystem steps, and lets only the real run succeed."""

    def __init__(self, registry: str = "http://10.42.1.1:8083") -> None:
        super().__init__()
        self.copied: list[dict[str, Any]] = []
        self.registry = registry

    def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
        if verb == "create_network":
            result = dict(super().call(verb, params, **kwargs))
            # The broker starts no registry proxy without a cutoff, so the
            # fake reports one only when the runner asked for one.
            cutoff = str(params.get("registry_cutoff") or "")
            return {
                **result,
                "registry_proxy_url": self.registry if cutoff else "",
                "registry_cutoff": cutoff,
            }
        if verb == "copy_in":
            self.copied.append(dict(params))
            return {
                "remote_path": f"/var/lib/xentry/artifacts/{params['guest_path']}",
                "sha256": "a" * 64,
            }
        if verb == "exec" and str(params.get("step_id")) == "run-poc-generic":
            self.exec_params.setdefault("run-poc-generic-calls", {})
            calls = self.exec_params.setdefault("run-poc-calls", {})
            calls[str(len(calls))] = dict(params.get("params") or {})
            # The fixed build is not vulnerable, so only the real phase leaks.
            stdout = f"leaked: {self.nonce}" if self.real_phase else "connection refused"
            self.exec_params["run-poc-generic"] = dict(params.get("params") or {})
            return {"exit_code": 0, "stdout": stdout, "stderr": "", "duration_ms": 1}
        return super().call(verb, params, **kwargs)


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    facts: Facts,
    broker: NpmBroker,
    fetch: Any = None,
) -> str:
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    conn.close()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: facts,
        validate_fn=fake_validate,
        fetch_fn=fetch or _fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)
    return job_id


def test_an_npm_job_runs_with_a_control_and_reproduces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = NpmBroker()
    job_id = _run(tmp_path, monkeypatch, _facts(), broker)
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None, "job row missing"
        assert job["target_id"] == "npm"
        assert job["outcome"] == "completed", job["reason_code"]
        assert job["verdict"] == "reproduced"
        names = [row["name"] for row in list_steps(conn, job_id)]
        # The source and both closures are in the guest before provisioning,
        # and the control runs before the restore brings the target back.
        assert names.index("stage_app") < names.index("provision")
        assert "control_actor" in names and "probe_control" in names
        assert names.index("probe_control") < names.index("restore")
        assert names.index("restore") < names.index("real_actor")
        seqs = [row["seq"] for row in list_steps(conn, job_id)]
        assert seqs == sorted(set(seqs)), "sequence numbers collide or go backwards"
    finally:
        conn.close()


def test_the_steps_get_the_mirror_and_the_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = NpmBroker()
    _run(tmp_path, monkeypatch, _facts(), broker)
    # Only the lab's source is copied in: the dependencies and the runtime
    # both come from the job's mirror while the network is still open.
    to_target = [
        item["artifact_id"] for item in broker.copied if item["vm_id"] == "xentry-job-target"
    ]
    assert to_target == ["app-source"]
    setup = broker.exec_params["setup-npm"]
    assert setup["registry_url"] == "http://10.42.1.1:8083/"
    assert setup["app_archive"] == "/var/lib/xentry/artifacts/app-source.tar.gz"
    assert setup["app_dir"] == "lab"
    assert setup["build"] == "next-build"
    assert setup["start"] == "next-start"
    assert setup["port"] == "3100"
    assert setup["node_version"].startswith("v")
    assert len(setup["node_sha256"]) == 64
    assert setup["fixed_subject"] == "react"
    assert setup["fixed_version"] == "19.3.1"
    assert setup["control_port"] == "3101"
    assert broker.exec_params["readiness-npm"] == {"ports": "3100 3101", "package": "react"}


def test_the_mirror_is_dated_from_the_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same rule the apt serial uses, and the reason a range is safe.

    Resolving against a live registry would take today's answer to the lab's
    ranges, and for a recent CVE today's answer leans toward the fix.
    """
    broker = NpmBroker()
    _run(tmp_path, monkeypatch, _facts(), broker)
    created = [params for verb, params in broker.calls if verb == "create_network"]
    assert created[0]["registry_cutoff"] == CUTOFF


def test_a_job_with_no_usable_advisory_date_is_refused_not_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """"" is not "today": an undated index is an unpinned one."""
    broker = NpmBroker()

    def undated(url: str) -> Fetched:
        if "codeload" in url or url.endswith("/lab/package.json"):
            return _fetch(url)
        body = b"an advisory page with no publication date"
        return Fetched(
            url=url, final_url=url, status=200, headers={}, body=body,
            text=body.decode(), sha256=hashlib.sha256(body).hexdigest(),
        )

    job_id = _run(tmp_path, monkeypatch, _facts(), broker, fetch=undated)
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["reason_code"] == "no_observable"
        detail = [r["detail"] for r in list_steps(conn, job_id) if r["state"] == "failed"]
        assert "publication date" in detail[0]
    finally:
        conn.close()


def test_the_control_run_points_at_the_fixed_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = NpmBroker()
    _run(tmp_path, monkeypatch, _facts(), broker)
    ports = [call["port"] for call in broker.exec_params["run-poc-calls"].values()]
    # Control first, against 3101; then the real run against 3100.
    assert ports == ["3101", "3100"]


def test_a_control_that_also_leaks_fails_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exploit that works against the fixed version has not shown that the
    vulnerability is why it works."""

    class LeakyBroker(NpmBroker):
        def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
            if verb == "exec" and str(params.get("step_id")) == "run-poc-generic":
                return {
                    "exit_code": 0,
                    "stdout": f"leaked: {self.nonce}",
                    "stderr": "",
                    "duration_ms": 1,
                }
            return super().call(verb, params, **kwargs)

    job_id = _run(tmp_path, monkeypatch, _facts(), LeakyBroker())
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "control_actor_observed_nonce"
        failed = [row["name"] for row in list_steps(conn, job_id) if row["state"] == "failed"]
        assert failed == ["probe_control"]
    finally:
        conn.close()


def test_an_advisory_with_no_fix_still_runs_and_claims_less(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refusing would make the better evidence a precondition for any."""
    broker = NpmBroker()
    job_id = _run(tmp_path, monkeypatch, _facts(fixed_versions=[]), broker)
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "completed", job["reason_code"]
        assert "control_actor" not in [r["name"] for r in list_steps(conn, job_id)]
    finally:
        conn.close()
    assert "fixed_subject" not in broker.exec_params["setup-npm"]
    assert broker.exec_params["readiness-npm"]["ports"] == "3100"


def test_a_product_the_lab_does_not_declare_leaves_no_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CVE-2026-126187's affected package is vendored inside next and absent
    from the tree, so there is nothing honest to move."""
    broker = NpmBroker()
    _run(tmp_path, monkeypatch, _facts(product="react-server-dom-webpack"), broker)
    setup = broker.exec_params["setup-npm"]
    assert "fixed_subject" not in setup
    assert broker.exec_params["readiness-npm"]["package"] == ""


def test_the_audit_page_shows_the_claim_this_job_actually_earned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A derived target's claims are per job, not per target id: the control
    run's claim names the versions it moved, so it cannot be looked up."""
    import json

    job_id = _run(tmp_path, monkeypatch, _facts(), NpmBroker())
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        recorded = json.loads(
            (Path(str(job["attempt_dir"])) / "criteria.json").read_text()
        )
    finally:
        conn.close()
    claim = " ".join(recorded["proves"])
    assert "moved to 19.3.1" in claim
    assert "react" in claim
    # And the caveat the control answers is gone, not left beside it.
    assert not any("until the same stack" in c for c in recorded["not_proves"])


def test_a_job_without_a_control_records_the_weaker_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    job_id = _run(tmp_path, monkeypatch, _facts(fixed_versions=[]), NpmBroker())
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        recorded = json.loads(
            (Path(str(job["attempt_dir"])) / "criteria.json").read_text()
        )
    finally:
        conn.close()
    assert any("until the same stack" in c for c in recorded["not_proves"])


# ---------------------------------------------------- the gate a paste hits ---


def _web_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *pinned: str) -> Any:
    from fastapi.testclient import TestClient

    from tests.test_web import FakeRunner
    from xentry.web.app import build_app

    monkeypatch.setattr("xentry.web.app.fetch", _fetch)
    monkeypatch.setattr("xentry.web.app.extract", lambda _artifacts: _facts())
    monkeypatch.setattr("xentry.web.app.resolved_artifacts", lambda: set(pinned))
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    return TestClient(app), app


def _check(client: Any, app: Any) -> Any:
    client.get("/")
    return client.post(
        "/api/links/check",
        json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
        headers={"X-Xentry-CSRF": app.state.token},
    )


def test_the_form_offers_the_npm_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without this the apt path refuses it at the form - "no apt package to
    install" - and the job that could run never starts."""
    client, app = _web_app(tmp_path, monkeypatch)
    with client:
        result = _check(client, app)
        assert result.status_code == 200, result.json()
        body = result.json()
        assert body["target_id"] == "npm"
        assert body["plan"]["target_ports"] == [3100, 3101]
        assert body["plan"]["subject_package"] == "react"
        assert body["plan"]["fixed_version"] == "19.3.1"
        # Nothing had to be pinned for this to be offered, which is the whole
        # difference: a pasted CVE reaches an ecosystem target on its own.
        assert body["plan"]["derived"] is True


def test_a_lab_the_harness_cannot_rebuild_falls_back_to_the_apt_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """app_dir is a model's reading of a README, not a guarantee."""
    from xentry.fetch import FetchError

    def no_lab(url: str) -> Fetched:
        if url.endswith("/package.json"):
            raise FetchError("HTTP status 404")
        return _fetch(url)

    monkeypatch.setattr("xentry.web.app.fetch", no_lab)
    client, app = _web_app(tmp_path, monkeypatch)
    monkeypatch.setattr("xentry.web.app.fetch", no_lab)
    with client:
        result = _check(client, app)
        # The apt path then has its own say, and because nothing else is wrong
        # with this CVE - remote PoC, known port - what is left is a download.
        # The channels are the record that it was a last resort.
        assert result.status_code == 200, result.json()
        body = result.json()
        assert body["state"] == "needs_artifact"
        # "no apt package", not "no Ubuntu package": this refusal is shown for
        # Debian plans too - the resolver chooses between five releases across
        # both archives - and naming one distribution sent a reader with a
        # Debian target looking for the wrong thing.
        assert "no apt package" in body["detail"]
        assert "Ubuntu" not in body["detail"]
        tried = [item["channel"] for item in body["channels"]]
        assert tried[:3] == [
            "a checked-in target",
            "an application-package lab",
            "an apt archive",
        ], tried
        # Whatever releases this test's fixture leaves unbuilt are named too,
        # so "no archive carries this" cannot stand in for "that archive was
        # never built here".
        assert all("not consulted" in item["channel"] for item in body["channels"][3:])
        assert ".deb" in body["accepts"] and ".tar.gz" in body["accepts"]


def test_the_form_refuses_an_advisory_with_no_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mirror is dated from the advisory, so a dateless one has nothing to
    resolve against - and the job would otherwise discover that at step 4,
    after a network and a VM."""

    def undated(url: str) -> Fetched:
        if "codeload" in url or url.endswith("/lab/package.json"):
            return _fetch(url)
        body = b"a GitHub advisory page with no publication date"
        return Fetched(
            url=url, final_url=url, status=200, headers={}, body=body,
            text=body.decode(), sha256=hashlib.sha256(body).hexdigest(),
        )

    client, app = _web_app(tmp_path, monkeypatch)
    monkeypatch.setattr("xentry.web.app.fetch", undated)
    with client:
        result = _check(client, app)
        assert result.status_code == 422
        assert "publication date" in result.json()["detail"]
