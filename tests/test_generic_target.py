"""A target derived from extracted facts: what it admits, and what it proves.

The three checked-in targets each carry a hand-designed observation. This path
has one observation for every remote PoC - the attacker printed a file that
only exists on the target - so the tests that matter are about where it refuses
to go and how weakly it states what it saw.
"""

from __future__ import annotations

import hashlib
import lzma
from pathlib import Path
from typing import Any

import pytest

from tests.test_runner import FakeBroker, fake_validate
from xentry import generic
from xentry.db import connect, init_db
from xentry.fetch import Fetched, FetchError
from xentry.jobstore import create_job, get_job, list_steps
from xentry.models import Facts
from xentry.runner import JobRunner

POC_REPO = "https://github.com/example/poc-repo"
ARCHIVE = b"\x1f\x8b" + b"a pretend tarball" * 8
ARCHIVE_SHA = hashlib.sha256(ARCHIVE).hexdigest()


def _facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "cve_id": "CVE-2026-55555",
        "product": "Widget Server",
        "affected_range": "2.0.0 - 2.1.3",
        "version_evidence": [],
        "protocol": "http",
        "ports": [8080],
        "auth_required": False,
        "build_strategy": "apt package",
        "poc_context": "remote",
        "setup_packages": ["widget-server"],
        "setup_units": ["widget-server"],
        "poc_entrypoint": "exploit.py",
        "citations": [],
    }
    base.update(overrides)
    return Facts(**base)


# ------------------------------------------------------------- admission ---


def test_a_poc_with_no_apt_package_is_refused_before_a_vm_is_built() -> None:
    """The failure of job f5223aa4a369, caught at admission instead.

    CVE-2026-126187's PoC builds its lab with `docker build ./lab`, so the
    extractor correctly reported no Ubuntu package. The job created a network
    and a VM, provisioned nothing for three minutes, then waited five more for
    port 3100 that nothing was ever going to serve.
    """
    facts = _facts(setup_packages=[], setup_units=[], ports=[3100], app_dir="lab")
    assert not generic.admits(facts)
    with pytest.raises(generic.NoObservable) as caught:
        generic.derive(facts, POC_REPO)
    assert "3100" in str(caught.value)
    # It ships a lab, so the refusal points at the path that rebuilds one.
    assert "lab as the directory" in str(caught.value)


def test_a_poc_that_assumes_a_target_says_so_instead(tmp_path: Path) -> None:
    """CVE-2026-56290 is this case and the message mattered.

    Its repository is one Python script, two screenshots and a README that
    assumes a Joomla install already exists. Telling that reader to use "an
    ecosystem target" sends them looking for a lab that was never there; the
    truth is that the PoC says nothing about installing the affected software.
    """
    facts = _facts(setup_packages=[], setup_units=[], ports=[], protocol="https")
    assert facts.app_dir is None
    with pytest.raises(generic.NoObservable) as caught:
        generic.derive(facts, POC_REPO)
    message = str(caught.value)
    assert "says how to install the affected software" in message
    assert "ecosystem" not in message
    assert "443" in message, "the protocol default still names the port"


def test_a_package_is_still_all_that_is_needed() -> None:
    """A unit-less package is ordinary: many publish their own unit."""
    assert generic.admits(_facts(setup_units=[]))


def test_an_http_advisory_with_no_port_gets_the_standard_one() -> None:
    """Advisories state the protocol and leave the port to the deployment.

    "Unauthenticated RCE in <web app>" names no port, and neither does the
    PoC's README, so every HTTP CVE was refused for a field that no advisory
    publishes. The standard port for the protocol is a provisioning default,
    not an extracted claim.
    """
    assert generic.derive(_facts(ports=[]), POC_REPO).target_ports == (80,)
    assert generic.derive(_facts(ports=[], protocol="https"), POC_REPO).target_ports == (443,)
    # A stated port still wins.
    assert generic.derive(_facts(ports=[3100]), POC_REPO).target_ports == (3100,)


def test_a_protocol_with_no_standard_port_is_still_refused() -> None:
    with pytest.raises(generic.NoObservable) as excinfo:
        generic.derive(_facts(protocol="tcp", ports=[]), POC_REPO)
    assert "no standard one" in str(excinfo.value)


def test_a_remote_poc_with_a_port_is_admitted() -> None:
    target = generic.derive(_facts(), POC_REPO)
    assert target.target_id == "generic"
    assert target.cve_ids == ("CVE-2026-55555",)
    assert target.target_ports == (8080,)
    assert target.attacker_profile_id == "attacker-remote"
    # The observation is the attacker's transcript, so the nonce only has to be
    # unreachable over the network - not owned by a service user nobody named.
    assert target.evidence_channel.kind == "attacker_transcript"
    assert target.nonce.owner == "root"
    assert target.nonce.mode == 0o644


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"poc_context": "local"}, "local PoC"),
        ({"ports": [], "protocol": "tcp"}, "no port"),
        ({"protocol": "local", "ports": [1]}, "not a network protocol"),
        ({"ports": [0]}, "not usable"),
        ({"ports": list(range(8000, 8010))}, "too many"),
    ],
)
def test_facts_with_no_clean_observable_are_refused(
    overrides: dict[str, Any], expected: str
) -> None:
    with pytest.raises(generic.NoObservable) as excinfo:
        generic.derive(_facts(**overrides), POC_REPO)
    assert expected in str(excinfo.value)


def test_the_claim_is_stated_as_weakly_as_it_deserves() -> None:
    target = generic.derive(_facts(), POC_REPO)
    proves = " ".join(target.what_proves).lower()
    assert "attacker vm printed" in proves
    caveats = " ".join(target.what_does_not_prove).lower()
    # Two things a reader could otherwise assume: that the version was checked,
    # and that anything on the target was observed.
    # "verified" is a banned word in rendered text (G10), so the caveat says
    # checked; tests/test_ui_vocabulary.py holds that line.
    assert "no version was checked against the advisory" in caveats
    assert "attested by the attacker" in caveats
    assert target.expected_version == ""


# ------------------------------------------------- the constrained vocabulary ---


def test_only_package_and_unit_names_reach_the_setup_step() -> None:
    assert generic.tokens(["apache2", "php8.3=8.3.1-1"], "package") == "apache2 php8.3=8.3.1-1"
    assert generic.tokens([], "unit") == ""
    for bad in ("apache2; id", "$(id)", "a b", "--help", "/etc/passwd", "apache2&&id"):
        with pytest.raises(generic.NoObservable):
            generic.tokens([bad], "package")


def test_the_entrypoint_cannot_point_outside_the_poc() -> None:
    assert generic.entrypoint(_facts(poc_entrypoint="./exploit.py")) == "exploit.py"
    assert generic.entrypoint(_facts(poc_entrypoint="src/run.sh")) == "src/run.sh"
    for bad in ("/etc/passwd", "../x.py", "./../x.py", "a;b.py", "..", "./"):
        with pytest.raises(generic.NoObservable):
            generic.entrypoint(_facts(poc_entrypoint=bad))


def test_an_unnamed_entrypoint_is_refused_rather_than_guessed() -> None:
    """Two plausible scripts would make the choice silently, and that choice
    decides what "the PoC" means for the verdict."""
    with pytest.raises(generic.NoObservable) as excinfo:
        generic.entrypoint(_facts(poc_entrypoint=None))
    assert "will not pick one" in str(excinfo.value)


# ------------------------------------------------------------- the whole run ---


class GenericBroker(FakeBroker):
    """A broker that answers the derived target's steps."""

    def __init__(self) -> None:
        super().__init__()
        self.staged: list[dict[str, Any]] = []
        self.exec_params: dict[str, dict[str, Any]] = {}

    def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
        if verb == "stage_artifact":
            self.staged.append(dict(params))
            return {"artifact_id": params["artifact_id"], "sha256": params["sha256"]}
        if verb == "create_network":
            result = super().call(verb, params, **kwargs)
            # Both proxies, as the real broker reports them: the attacker's is
            # a second one on Ubuntu at the current serial, because the
            # target's serves one archive at the advisory's serial.
            return {
                **result,
                "apt_proxy_url": "http://10.42.1.1:8082",
                "apt_snapshot": "x",
                "attacker_apt_proxy_url": "http://10.42.1.1:8084",
                "attacker_apt_snapshot": "20261101T000000Z",
            }
        if verb == "exec":
            self.exec_params[str(params.get("step_id"))] = dict(params.get("params") or {})
            step = str(params.get("step_id"))
            # The real actor prints the nonce it read; the null actor does not.
            if step == "run-poc-generic":
                return {
                    "exit_code": 0,
                    "stdout": f"leaked: {self.nonce}",
                    "stderr": "",
                    "duration_ms": 1,
                }
            return {"exit_code": 0, "stdout": "ok", "stderr": "", "duration_ms": 1}
        return super().call(verb, params, **kwargs)


# What Launchpad answers for "which versions of this package did this release
# publish": the archive carries 2.0.9, and the advisory says 2.0.0 - 2.1.3.
LP_PAYLOAD = (
    '{"total_size": 1, "entries": [{"binary_package_version": "2.0.9-1ubuntu1"}]}'
)


# A date, because a derived job provisions from one day before the advisory
# and is now REFUSED when no serial can be derived from it. Before that guard
# these fixtures provisioned from the broker's default, which is today - the
# same silent misprovisioning that made job 5bd509cb install sudo 1.9.17p2 for
# a 2020 CVE.
PUBLISHED = b"cveMetadata.datePublished: 2022-06-01T00:00:00.000Z\n"


# The dated Packages index the archive pre-flight reads. Real stanzas, xz'd,
# because refusal() decompresses what it gets - and big enough compressed to
# clear MIN_INDEX_BYTES, which is how the archive says "this suite exists".
PACKAGES_XZ = lzma.compress(
    b"Package: widget-server\nVersion: 2.0.9-1ubuntu1\nArchitecture: amd64\n\n"
    + b"".join(
        f"Package: filler{n}\nVersion: {n}.{n}-{n}\nArchitecture: amd64\n\n".encode()
        for n in range(600)
    )
)


def _fetch(url: str, **_options: object) -> Fetched:
    if "codeload" in url:
        body = ARCHIVE
    elif "api.launchpad.net" in url:
        body = LP_PAYLOAD.encode()
    elif "Packages.xz" in url:
        body = PACKAGES_XZ
    else:
        body = b"source\n" + PUBLISHED
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers={},
        body=body,
        text=body.decode("utf-8", "replace"),
        sha256=hashlib.sha256(body).hexdigest(),
    )


def _pin_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend every generic image is built, which is what the catalog says on
    a host where they have been."""
    from xentry import release

    monkeypatch.setattr(
        "xentry.runner.resolved_artifacts",
        lambda: {item.artifact_id for item in release.RELEASES},
    )


def _run(
    tmp_path: Path, facts: Facts, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, Path, GenericBroker]:
    _pin_all(monkeypatch)
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    conn.close()
    broker = GenericBroker()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: facts,
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)
    return job_id, attempt_dir, broker


def test_a_pasted_pair_runs_without_anything_being_wired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job_id, attempt_dir, broker = _run(tmp_path, _facts(), monkeypatch)
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["target_id"] == "generic"
        assert job["cve_id"] == "CVE-2026-55555"
        assert job["outcome"] == "completed"
        # Attested, never observed: the runner read the attacker's transcript.
        assert job["authority"] == "guest_attested+llm_assessed"
        names = [row["name"] for row in list_steps(conn, job_id)]
        assert "stage_poc" in names
        assert all(row["state"] == "passed" for row in list_steps(conn, job_id))
    finally:
        conn.close()

    # The PoC bytes that ran are the ones recorded, and the broker verified the
    # digest before it would copy them in.
    assert broker.staged == [
        {
            "job_id": job_id,
            "artifact_id": "poc-generic",
            "path": str(attempt_dir / "poc-generic.tar.gz"),
            "sha256": ARCHIVE_SHA,
        }
    ]
    assert (attempt_dir / "poc-generic.tar.gz").read_bytes() == ARCHIVE


def test_the_derived_steps_get_only_validated_parameters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _job_id, _dir, broker = _run(tmp_path, _facts(), monkeypatch)
    setup = broker.exec_params["setup-generic"]
    assert setup["packages"] == "widget-server"
    assert setup["units"] == "widget-server"
    # jammy, not noble. This fixture's advisory is published 2022-06-01, so the
    # serial is 20220531, and noble did not exist for another two years - the
    # runner used to provision it anyway and then ask the proxy for a released
    # index that has never existed. jammy released in April 2022, two months
    # before this advisory, so it is the newest release the archive actually
    # had at that serial.
    assert setup["suite"] == "jammy"
    assert setup["apt_proxy_url"] == "http://10.42.1.1:8082"
    # The version check is the point of resolving a release at all: readiness
    # asserts the installed package matches what the advisory named.
    assert broker.exec_params["readiness-generic"] == {
        "ports": "8080",
        "package": "widget-server",
        "expected_version": "2.0",
        # And the CVE id, so readiness can ask the installed package's own
        # changelog whether this fix is already backported into it - the one
        # case a version check cannot see.
        "cve_id": "CVE-2026-55555",
    }
    assert setup["sources_format"] == "deb822"
    assert broker.exec_params["build-poc-generic"]["poc_sha256"] == ARCHIVE_SHA
    assert broker.exec_params["build-poc-generic"]["entrypoint"] == "exploit.py"
    run = broker.exec_params["run-poc-generic"]
    assert run["entrypoint"] == "exploit.py"
    assert run["port"] == "8080"
    assert run["nonce_path"] == generic.NONCE_PATH
    assert broker.exec_params["null-generic"] == {"target_ip": "10.0.0.10", "port": "8080"}


def test_a_poc_that_prints_nothing_ends_nonce_not_observed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SilentBroker(GenericBroker):
        def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
            if verb == "exec" and str(params.get("step_id")) == "run-poc-generic":
                self.exec_params["run-poc-generic"] = dict(params.get("params") or {})
                return {"exit_code": 0, "stdout": "done", "stderr": "", "duration_ms": 1}
            return super().call(verb, params, **kwargs)

    _pin_all(monkeypatch)
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    conn.close()
    broker = SilentBroker()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: _facts(),
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        failed = [row for row in list_steps(conn, job_id) if row["state"] == "failed"]
        assert [row["name"] for row in failed] == ["target_probe"]
        assert job["reason_code"] == "nonce_not_observed"
    finally:
        conn.close()


def test_an_unsupported_cve_fails_with_no_observable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pin_all(monkeypatch)
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    conn.close()
    broker = GenericBroker()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: _facts(poc_context="local", ports=[]),
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "no_observable"
        # Nothing was created: the refusal happens at admission.
        assert broker.destroyed == []
        assert not any(verb == "create_network" for verb, _ in broker.calls)
    finally:
        conn.close()


# ----------------------------------------------------- the gate a paste hits ---


def _web_app(
    tmp_path: Path,
    facts: Facts,
    monkeypatch: pytest.MonkeyPatch,
    fetch_fn: Any = None,
) -> Any:
    """The app, with the extractor replaced by the facts under test."""
    from fastapi.testclient import TestClient

    from tests.test_web import FakeRunner
    from xentry.web.app import build_app

    monkeypatch.setattr("xentry.web.app.fetch", fetch_fn or _fetch)
    monkeypatch.setattr("xentry.web.app.extract", lambda _artifacts: facts)
    from xentry import release as release_module

    monkeypatch.setattr(
        "xentry.web.app.resolved_artifacts",
        lambda: {item.artifact_id for item in release_module.RELEASES},
    )
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    return TestClient(app), app


def test_an_unwired_cve_passes_the_link_check_and_says_it_is_derived(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app = _web_app(tmp_path, _facts(), monkeypatch)
    with client:
        client.get("/")
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert checked.status_code == 200
        result = checked.json()
        assert result["target_id"] == "generic"
        plan = result["plan"]
        # The plan is what a reader approves before anything runs, so the
        # weaker standing is stated there and not only in the verdict.
        assert plan["derived"] is True
        assert plan["authority"] == "guest_attested+llm_assessed"
        assert plan["packages"] == "widget-server"
        assert plan["poc_entrypoint"] == "exploit.py"
        assert any("derived from extracted facts" in line for line in plan["caveats"])
        assert plan["target_ports"] == [8080]
        assert plan["nonce_path"] == generic.NONCE_PATH


def test_a_cve_with_no_clean_observable_is_refused_at_the_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app = _web_app(tmp_path, _facts(poc_context="local", ports=[]), monkeypatch)
    with client:
        client.get("/")
        refused = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert refused.status_code == 422
        # A link-check refusal carries FastAPI's plain detail, not the
        # {"error": {...}} envelope the token and host gates use.
        detail = refused.json()["detail"]
        assert "no_observable" in detail
        # And it says what was missing, not just that it refused.
        assert "local PoC" in detail


def test_an_unnamed_entrypoint_is_refused_at_the_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app = _web_app(tmp_path, _facts(poc_entrypoint=None), monkeypatch)
    with client:
        client.get("/")
        refused = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert refused.status_code == 422
        assert "will not pick one" in refused.json()["detail"]


def test_a_checked_in_cve_is_unaffected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """php2shell still matches by CVE and still has to match its PoC pin."""
    from tests.test_web import POC_URL
    from tests.test_web import _facts as php_facts

    client, app = _web_app(tmp_path, php_facts(None), monkeypatch)
    with client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_URL},
            headers=headers,
        )
        assert checked.status_code == 200
        assert checked.json()["target_id"] == "php2shell"
        assert checked.json()["plan"]["derived"] is False
        mismatched = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers=headers,
        )
        assert mismatched.status_code == 422
        assert "target pin" in mismatched.json()["detail"]


def test_a_derived_job_is_not_offered_for_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rebuilding one would need the derived target, which only an extractor
    call produces - so it is left out of the picker rather than failing on the
    click, and a refusal from the runner is still a refusal, not a 500."""
    from fastapi.testclient import TestClient

    from tests.test_web import FakeRunner
    from xentry.jobstore import record_outcome, set_plan
    from xentry.runner import RunnerFailure
    from xentry.web.app import _rebuild_candidates, build_app

    data = tmp_path / "data"
    db_path = data / "xentry.db"
    conn = init_db(db_path)
    derived_job, derived_attempt, _d = create_job(
        conn, data_dir=data, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    set_plan(
        conn, derived_job, cve_id="CVE-2026-55555", target_id="generic", bundle_sha256="d" * 64
    )
    record_outcome(
        conn,
        job_id=derived_job,
        attempt_id=derived_attempt,
        outcome="completed",
        verdict="reproduced",
        authority="guest_attested+llm_assessed",
        reason_code="ok",
    )
    pinned_job, pinned_attempt, _p = create_job(
        conn, data_dir=data, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    set_plan(
        conn, pinned_job, cve_id="CVE-2026-109618", target_id="php2shell", bundle_sha256="d" * 64
    )
    record_outcome(
        conn,
        job_id=pinned_job,
        attempt_id=pinned_attempt,
        outcome="completed",
        verdict="reproduced",
        authority="runner_observed+llm_assessed",
        reason_code="ok",
    )
    conn.commit()
    # The derived job has no stored facts in this fixture, so it is still not
    # offered - the rule is now "offered while its facts survive" rather than
    # "never offered", and with nothing stored the answer is the same.
    assert [row["target_id"] for row in _rebuild_candidates(conn, tmp_path)] == ["php2shell"]
    conn.close()

    class RefusingRunner(FakeRunner):
        def build_environment(self, source_job_id: str) -> str:
            raise RunnerFailure("unsupported_target", "no known target")

    app = build_app(
        data_dir=data,
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=RefusingRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        client.get("/")
        headers = {"X-Xentry-CSRF": app.state.token}
        # Not offered at all.
        assert (
            client.post(
                "/api/environments", json={"job_id": derived_job}, headers=headers
            ).status_code
            == 404
        )
        # And a runner that refuses an offered job says so, rather than 500.
        refused = client.post("/api/environments", json={"job_id": pinned_job}, headers=headers)
        assert refused.status_code == 422
        assert "unsupported_target" in refused.json()["detail"]


# ------------------------------------------------- the tables must agree ---


def test_every_registered_target_has_images_and_a_profile() -> None:
    """A derived job died at create_target because three tables disagreed.

    resolve_target() admitted the id from broker/registry.py, then
    TARGET_IMAGES[target_id] raised KeyError - an unhandled one, surfacing as
    harness_error rather than as a refusal. Nothing checked that the lists were
    the same list.
    """
    from broker.registry import ARTIFACTS, IMAGES, TARGETS
    from broker.runtime import TARGET_IMAGES, TARGET_PROFILES

    assert set(TARGETS) == set(TARGET_IMAGES) == set(TARGET_PROFILES)
    for target_id, image_ids in TARGET_IMAGES.items():
        assert image_ids, f"{target_id} has no image"
        for image_id in image_ids:
            assert image_id in IMAGES, f"{target_id} uses an unregistered image: {image_id}"
            assert IMAGES[image_id] in ARTIFACTS, f"{image_id} maps to an unknown artifact"


def test_the_release_matrix_is_wired_end_to_end() -> None:
    """Five places have to agree about each release, and a derived job finds
    out at create_target if they do not."""
    import yaml

    from broker.registry import IMAGES
    from broker.runtime import TARGET_IMAGES
    from xentry import release

    root = Path(__file__).resolve().parents[1]
    manifests = yaml.safe_load((root / "config/image-manifests.yaml").read_text())["images"]
    catalog = yaml.safe_load((root / "config/artifacts.yaml").read_text())["artifacts"]

    assert {item.image_id for item in release.RELEASES} == set(TARGET_IMAGES["generic"])
    # DEBIAN FIRST, then Ubuntu newest to oldest. The order is a policy, not a
    # detail: by_package() returns the first release carrying the package and
    # usable[0] is the fallback, so whatever sits at the front is what an
    # advisory that names no version gets. Debian leads because
    # snapshot.debian.org has the full pocket history while
    # snapshot.ubuntu.com only captured -updates and -security from about
    # 2023-06, and because sid is newer than the bullseye base so apt only
    # upgrades - never needing a version the archive stopped serving.
    assert [item.version for item in release.RELEASES] == [
        "11", "24.04", "22.04", "20.04", "18.04",
    ]
    assert release.RELEASES[0].archive == "debian"
    for item in release.RELEASES:
        assert IMAGES[item.image_id] == item.artifact_id
        spec = manifests[item.image_id]
        # Minimal on purpose: the apt mirror installs what a CVE needs.
        # The archive's own keyring, because apt verifies the snapshot Release
        # against it: Ubuntu's keys cannot check a Debian Release and the job
        # would fail at apt update with NO_PUBKEY.
        keyring = "ubuntu-keyring" if item.archive == "ubuntu" else "debian-archive-keyring"
        assert set(spec["packages"]) == {"ca-certificates", "curl", keyring}
        base = catalog[spec["base_artifact"]]
        assert base["status"] == "resolved"
        assert len(str(base["sha256"])) == 64
        # Each release needs its own base cloud image; one shared base would
        # mean one release's packages on another's userland.
        assert item.version.replace(".", "") in base["url"].replace(".", "")
        # 18.04's apt is too old for deb822 .sources files.
        assert item.sources_format == ("oneline" if item.version == "18.04" else "deb822")
    # BASE_IMAGE_ID and SUITE are a PAIR: setup-generic points apt at <suite>,
    # so a default naming one release with a suite from another would point apt
    # at an archive that image cannot install from. That is the invariant worth
    # holding, and it is checked here directly.
    #
    # It used to be written as "BASE_IMAGE_ID == RELEASES[0].image_id", which
    # coupled a documented default to the ORDER - and the order is now a policy
    # about which archive can be dated best, with Debian first. The two are
    # separate concerns: nothing reads BASE_IMAGE_ID to choose a release, and
    # the release a job runs on comes from resolve() or the fallback.
    paired = [item for item in release.RELEASES if item.image_id == generic.BASE_IMAGE_ID]
    assert len(paired) == 1, generic.BASE_IMAGE_ID
    assert paired[0].suite == generic.SUITE, (paired[0].suite, generic.SUITE)


def test_each_suite_matches_its_image_release() -> None:
    """Ubuntu's suite is its own release; Debian's is deliberately not.

    For Ubuntu, setup-generic points apt at <suite>, -updates and -security, so
    a suite that is not the image's release would install from the wrong
    archive. Debian pairs a bullseye userland with *sid*, on purpose: a stable
    suite backports a fix without changing the upstream version, so bullseye
    never carried a vulnerable apache2 2.4.49 while sid at the same serial did.
    The two are two months apart, which is what keeps the dependency
    resolution honest.
    """
    from xentry import release

    expected = {
        "24.04": "noble",
        "22.04": "jammy",
        "20.04": "focal",
        "18.04": "bionic",
        "11": "sid",
    }
    for item in release.RELEASES:
        assert expected[item.version] == item.suite
        # The image has to be of the archive whose serials it will install
        # from: a Debian suite on an Ubuntu image has no matching keyring and
        # an Ubuntu suite on a Debian one has no matching components.
        assert item.image_id.startswith(item.archive), item
        assert item.artifact_id.startswith(item.archive), item
        assert item.version in item.image_id


def test_create_target_refuses_an_id_the_tables_disagree_on(tmp_path: Path) -> None:
    from broker.errors import BrokerError
    from broker.registry import TARGETS
    from broker.runtime import BrokerRuntime

    runtime = BrokerRuntime(tmp_path / "data", tmp_path / "images")
    unknown = next(iter(TARGETS))
    # A real id whose tables are intact still gets past this check; a bogus one
    # is a refusal, never an unhandled KeyError.
    with pytest.raises(BrokerError) as excinfo:
        runtime.create_target("job-1", "not-a-target", "ubuntu-24.04-generic")
    assert excinfo.value.code == "broker_registry_rejected"
    assert unknown in TARGETS


def test_the_artifact_gate_still_passes(tmp_path: Path) -> None:
    """Every catalog entry must be resolved; an image declared but not yet
    built belongs in the image manifest, not in the pinned catalog."""
    import subprocess
    import sys as _sys

    root = Path(__file__).resolve().parents[1]
    done = subprocess.run(
        [_sys.executable, str(root / "scripts/fetch-artifacts.py"), "--mode", "dry-run"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_step_a_target_names_is_one_the_broker_will_run() -> None:
    """Two jobs died at provision with "unknown step id: setup-generic".

    targets/steps.yaml described the step, the script was present and its hash
    matched - but broker/registry.py keeps its own allowlist, and resolve_step()
    consults that. The generic steps were missing from it, so every derived job
    failed at its first provisioning call. The images-and-profiles test next to
    this one checked the same class of disagreement one table over.
    """
    import yaml

    from broker.registry import RegistryError, resolve_step
    from xentry.targets import TARGETS as APP_TARGETS

    root = Path(__file__).resolve().parents[1]
    manifest = yaml.safe_load((root / "targets/steps.yaml").read_text())["steps"]

    targets = [*APP_TARGETS.values(), generic.derive(_facts(), POC_REPO)]
    for target in targets:
        guest_steps = [
            target.setup_step_id,
            target.readiness_step_id,
            target.build_step_id,
            target.invocation_step_id,
            target.null_step_id,
            target.poc.build_step_id,
            target.poc.invocation_step_id,
        ]
        for step_id in guest_steps:
            if not step_id:
                continue
            try:
                resolve_step(step_id)
            except RegistryError as exc:  # pragma: no cover - the failure is the point
                raise AssertionError(f"{target.target_id}: {exc}") from exc
            assert step_id in manifest, f"{target.target_id}: {step_id} is not in steps.yaml"
        # A probe the broker runs must be registered too. A response_parse probe
        # reads a transcript the runner already holds and never calls out.
        for probe in target.probes:
            if probe.kind == "response_parse":
                continue
            resolve_step(probe.step_id)


def test_a_refused_check_hands_back_the_id_its_transcript_is_under(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal is the one case where the model's own reply is worth reading.

    The transcript was being written for every check and then made unreachable
    for exactly the checks that needed it: the id it is filed under lived only
    inside the request, and an ExtractorError carried nothing. Nothing covered
    the log endpoint at all, so neither half was noticed.
    """
    import re as _re

    from xentry import transcript
    from xentry.extract import ExtractorError

    def _refuse(_artifacts: Any) -> Any:
        transcript.record("extract", "the prompt as sent", '{"cve_id": "CVE-0000-00000"}')
        raise ExtractorError("evidence_insufficient", "quote is not checkable")

    client, app = _web_app(tmp_path, _facts(), monkeypatch)
    monkeypatch.setattr("xentry.web.app.extract", _refuse)
    with client:
        client.get("/")
        refused = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert refused.status_code == 422
        detail = refused.json()["detail"]
        assert "quote is not checkable" in detail
        found = _re.search(r"\[([0-9a-f]{32})\]", detail)
        assert found is not None, detail
        log = client.get(f"/api/checks/{found.group(1)}/log")
        assert log.status_code == 200
        items = log.json()["items"]
        assert items["extract.prompt.txt"] == "the prompt as sent"
        assert "CVE-0000-00000" in items["extract.response.txt"]


def test_a_version_chosen_by_date_says_so_in_the_caveats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A job that could not assert a version must not read like one that did."""
    from xentry import release as release_module

    archive = release_module.Resolution(
        release=release_module.RELEASES[0],
        package="policykit-1",
        prefix="",
        version="",
        exact=False,
    )
    dated = generic.derive(_facts(), POC_REPO, resolution=archive)
    assert any("named no version to match" in line for line in dated.what_does_not_prove)
    assert dated.expected_version == ""
    # And an ordinary resolution carries no such caveat.
    matched = release_module.Resolution(
        release=release_module.RELEASES[0],
        package="widget-server",
        prefix="2.0",
        version="2.0.9-1",
        exact=False,
    )
    ordinary = generic.derive(_facts(), POC_REPO, resolution=matched)
    assert not any(
        "named no version to match" in line for line in ordinary.what_does_not_prove
    )
    assert ordinary.expected_version == "2.0"


def test_a_job_runs_the_facts_its_check_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Job f062e5c1 refused what its own check had admitted.

    Byte-identical cve, poc and nvd artifacts, and two different replies: the
    check read blasty's curl line as poc_command, the job read null and
    refused for want of an entrypoint. temperature=0 is not a determinism
    guarantee from any provider, so the plan the operator approved has to be
    the plan that runs. The check stores its facts beside the bytes they came
    from and the job loads them - and when it does, the extractor is not
    called at all.
    """
    from xentry import sourcestore

    _pin_all(monkeypatch)
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, _dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    # The check's own artifacts and facts, as _link_check stores them.
    check_id = "c" * 32
    conn.execute("UPDATE jobs SET check_id=? WHERE id=?", (check_id, job_id))
    conn.commit()
    conn.close()
    admitted = _facts()
    sourcestore.save(
        tmp_path,
        check_id,
        {"cve": _fetch("https://example.com/cve"), "poc": _fetch(POC_REPO)},
    )
    sourcestore.save_facts(tmp_path, check_id, admitted.model_dump_json())

    asked: list[int] = []

    def second_reading(_artifacts: Any) -> Facts:
        asked.append(1)
        # What the job used to do: read the bytes again and get something the
        # operator never approved. This one cannot be run at all.
        return _facts(poc_entrypoint=None)

    broker = GenericBroker()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=second_reading,
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)

    conn = connect(db_path)
    try:
        row = conn.execute("SELECT outcome FROM jobs WHERE id=?", (job_id,)).fetchone()
    finally:
        conn.close()
    assert str(row["outcome"]) == "completed"
    # The extractor was never asked, because the answer was already approved.
    assert asked == []


def test_a_job_with_no_dated_archive_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Job 5bd509cb installed sudo 1.9.17p2-9 for a 2020 advisory.

    snapshot_for returns "" below SNAPSHOT_FLOOR, "" used to leave the
    broker's default serial in force, and that default is now - so a pre-floor
    advisory provisioned from TODAY. Readiness caught that one on the version
    check; the by_package and ceiling-sweep paths leave expected_version empty
    by design, and there nothing would have.
    """
    from xentry import generic as generic_mod

    monkeypatch.setattr(generic_mod, "advisory_published", lambda _text: "2020-01-29T00:00:00Z")
    job_id, _dir, _broker = _run(tmp_path, _facts(), monkeypatch)
    conn = connect(tmp_path / "xentry.db")
    try:
        row = conn.execute(
            "SELECT outcome, reason_code FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
    finally:
        conn.close()
    assert str(row["outcome"]) == "failed"
    assert str(row["reason_code"]) == "unsupported_target"


def _every_release_answered(detail: str) -> None:
    """Every built release must appear in a refusal, by name.

    The operator's standing instruction, and the bug that earned it: the sweep
    used to be driven by release.resolve() over a shrinking pool, and resolve
    returns None for its own reasons - no version prefix, no ceiling, no hit
    on what an archive EVER carried. So it gave up while the pool still held
    releases whose DATED index had never been consulted, and the refusal was
    reported as though all of them had answered. Asserting the sentence per
    release is the only form of this check that cannot drift back.
    """
    from xentry import release as release_module

    missing = [
        item.suite
        for item in release_module.RELEASES
        if item.suite not in detail
    ]
    assert not missing, f"these releases never answered: {missing}\n{detail}"


def _index_of(*stanzas: bytes) -> bytes:
    """A dated Packages index big enough compressed to look like a real suite."""
    filler = b"".join(
        f"Package: filler{n}\nVersion: {n}.{n}-{n}\nArchitecture: amd64\n\n".encode()
        for n in range(600)
    )
    return lzma.compress(b"".join(stanzas) + filler)


def _check_with_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: bytes | None
) -> tuple[int, str]:
    """Run the link check with the dated archive serving `index`."""

    def fetch_fn(url: str, **_options: object) -> Fetched:
        if "Packages.xz" in url:
            if index is None:
                raise FetchError("HTTP status 404")
            body = index
        elif "codeload" in url:
            body = ARCHIVE
        elif "api.launchpad.net" in url:
            body = LP_PAYLOAD.encode()
        else:
            body = b"source\n" + PUBLISHED
        return Fetched(
            url=url,
            final_url=url,
            status=200,
            headers={},
            body=body,
            text=body.decode("utf-8", "replace"),
            sha256=hashlib.sha256(body).hexdigest(),
        )

    client, app = _web_app(tmp_path, _facts(), monkeypatch, fetch_fn=fetch_fn)
    with client:
        client.get("/")
        answer = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
    return answer.status_code, str(answer.json().get("detail", ""))


def test_the_check_refuses_a_version_the_dated_archive_does_not_carry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worst failure mode this harness has, caught before a VM exists.

    CVE-2021-40438 resolved apache2 2.4.48 on jammy, whose GA archive carries
    2.4.52 - already fixed. That job PROVISIONS, runs the exploit against a
    patched build and reports that the CVE did not reproduce. published_versions
    cannot see it: Launchpad answers what the suite ever published, across all
    pockets and all time. Only the dated index knows.
    """
    status, detail = _check_with_index(
        tmp_path,
        monkeypatch,
        _index_of(b"Package: widget-server\nVersion: 9.9.9-1\nArchitecture: amd64\n\n"),
    )
    # Not a hard refusal any more: with no release carrying it, the artifact
    # path stays open - and the detail has to name EVERY built release, which
    # is the property that was previously asserted and not true.
    assert status == 200
    assert "9.9.9-1" in detail
    assert "widget-server" in detail
    _every_release_answered(detail)


def test_the_check_refuses_a_suite_with_no_index_at_that_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A serial before the release existed, which Ubuntu answers with a stub.

    snapshot.ubuntu.com serves `dists/noble` at a 2022 serial as 200 with a
    nine-byte xz of nothing rather than a 404, so "the request succeeded" says
    nothing. Every PwnKit job this session took that path: noble did not exist
    at 20220127. Measured as a stub, not inferred.
    """
    status, detail = _check_with_index(tmp_path, monkeypatch, lzma.compress(b""))
    assert status == 200
    assert "served no readable package index" in detail
    assert "may predate the release" in detail
    _every_release_answered(detail)


def test_the_check_refuses_a_package_the_dated_archive_lacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The index was read and the package is simply not in it - grafana in sid.

    Distinct from the stub case: here the serial is honoured and the answer is
    negative, so the refusal must not blame the serial.
    """
    status, detail = _check_with_index(tmp_path, monkeypatch, _index_of())
    assert status == 200
    assert "does not carry widget-server" in detail
    assert "predates" not in detail
    _every_release_answered(detail)


def test_the_check_passes_when_the_dated_archive_carries_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And an unreadable index is not a refusal either way.

    A component that 404s is a miss, not an error: Debian has no universe and
    Ubuntu no contrib, so asking for both always produces one. If every
    component is unreachable the check refuses - which is the stub case - so
    this pins the opposite, that a served index naming the resolved version
    lets the plan through.
    """
    status, _detail = _check_with_index(
        tmp_path,
        monkeypatch,
        _index_of(
            b"Package: widget-server\nVersion: 2.0.9-1ubuntu1\nArchitecture: amd64\n\n"
        ),
    )
    assert status == 200


def test_an_epoch_is_not_part_of_the_version_an_advisory_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """jammy's zabbix is 1:5.0.17+dfsg-1 for upstream 5.0.17.

    An epoch is archive bookkeeping. Comparing it to the advisory's version
    verbatim would refuse every package that has one, which is a large and
    arbitrary slice of both archives.
    """
    status, _detail = _check_with_index(
        tmp_path,
        monkeypatch,
        _index_of(
            b"Package: widget-server\nVersion: 3:2.0.9-1ubuntu1\nArchitecture: amd64\n\n"
        ),
    )
    assert status == 200


def test_a_release_that_did_not_exist_at_the_serial_is_passed_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resolver proposed noble for a 2023 advisory. Now it moves on.

    published_versions asks whether an archive EVER carried a version, so the
    first release it likes may be one that did not exist at the serial - and
    because a release pocket is immutable, that release's archive answers with
    its GA build, which for an old advisory is already fixed. Measured in the
    live sweep: CVE-2021-44790 wanted apache2 2.4.51 and was offered jammy,
    whose GA carries 2.4.52; Debian sid at the same serial carries 2.4.51.

    Here the first release's dated index carries the wrong version and the
    second carries the right one, so the check must be ADMITTED on the second
    rather than refused on the first - the whole point of the sweep.
    """
    asked: list[str] = []

    def fetch_fn(url: str, **_options: object) -> Fetched:
        if "Packages.xz" in url:
            asked.append(url)
            # The first release asked for is wrong; any later one is right.
            wrong = len(asked) == 1
            body = _index_of(
                b"Package: widget-server\nVersion: "
                + (b"9.9.9-1" if wrong else b"2.0.9-1ubuntu1")
                + b"\nArchitecture: amd64\n\n"
            )
        elif "codeload" in url:
            body = ARCHIVE
        elif "api.launchpad.net" in url:
            body = LP_PAYLOAD.encode()
        else:
            body = b"source\n" + PUBLISHED
        return Fetched(
            url=url,
            final_url=url,
            status=200,
            headers={},
            body=body,
            text=body.decode("utf-8", "replace"),
            sha256=hashlib.sha256(body).hexdigest(),
        )

    client, app = _web_app(tmp_path, _facts(), monkeypatch, fetch_fn=fetch_fn)
    with client:
        client.get("/")
        answer = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
    assert answer.status_code == 200, answer.json()
    # It did not stop at the first release: more than one dated index was read.
    assert len({url.split("/dists/")[1].split("/")[0] for url in asked}) > 1


def test_no_built_release_carries_it_at_that_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When every release is wrong, the refusal names what each one carried.

    The sweep must not silently fall through to the last release it tried; a
    reader needs to see that the archives were all asked and all answered no.
    """

    def fetch_fn(url: str, **_options: object) -> Fetched:
        if "Packages.xz" in url:
            body = _index_of(
                b"Package: widget-server\nVersion: 9.9.9-1\nArchitecture: amd64\n\n"
            )
        elif "codeload" in url:
            body = ARCHIVE
        elif "api.launchpad.net" in url:
            body = LP_PAYLOAD.encode()
        else:
            body = b"source\n" + PUBLISHED
        return Fetched(
            url=url,
            final_url=url,
            status=200,
            headers={},
            body=body,
            text=body.decode("utf-8", "replace"),
            sha256=hashlib.sha256(body).hexdigest(),
        )

    client, app = _web_app(tmp_path, _facts(), monkeypatch, fetch_fn=fetch_fn)
    with client:
        client.get("/")
        answer = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
    assert answer.status_code == 200
    detail = str(answer.json()["detail"])
    assert "9.9.9-1" in detail
    _every_release_answered(detail)
