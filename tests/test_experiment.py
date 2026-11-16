"""The experimental pipeline: a model writes the PoC.

Everything up to the PoC is the derived-target path. What is new is that the
exploit has no pin at all, so the tests here are about the two things that must
survive that: the boundary the generated code runs behind, and the evidence
that makes its output mean anything.
"""

from __future__ import annotations

import hashlib
import tarfile
from pathlib import Path
from typing import Any

import pytest

from tests.test_generic_target import ARCHIVE, GenericBroker, _facts, _pin_all
from tests.test_runner import fake_validate
from xentry.db import connect, init_db
from xentry.fetch import Fetched
from xentry.jobstore import (
    get_job,
    list_experiments,
    list_jobs,
    list_steps,
)
from xentry.models import Facts
from xentry.runner import JobRunner

CVE_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-55555"
GOOD_POC = "import sys\nimport socket\nimport os\nprint('read it')\nsys.exit(0)\n"


def _fetch(url: str) -> Fetched:
    # Dated, because a derived job is refused when no snapshot serial can be
    # derived from the advisory - see the guard in runner.create_network.
    body = (
        ARCHIVE
        if "codeload" in url
        else b'{"cveMetadata": {"datePublished": "2022-06-01T00:00:00.000Z"}}'
    )
    if "api.launchpad.net" in url:
        body = b'{"total_size": 1, "entries": [{"binary_package_version": "2.0.9-1ubuntu1"}]}'
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers={},
        body=body,
        text=body.decode("utf-8", "replace"),
        sha256=hashlib.sha256(body).hexdigest(),
    )


class ExperimentBroker(GenericBroker):
    """Answers the derived steps; the PoC prints the nonce it was given."""

    def __init__(self, leak: bool = True) -> None:
        super().__init__()
        self.leak = leak
        self.runs = 0

    def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
        if verb == "exec" and str(params.get("step_id")) == "run-poc-generic":
            self.exec_params["run-poc-generic"] = dict(params.get("params") or {})
            self.runs += 1
            if self.leak:
                return {
                    "exit_code": 0,
                    "stdout": f"leaked: {self.nonce}",
                    "stderr": "",
                    "duration_ms": 1,
                }
            return {"exit_code": 1, "stdout": "", "stderr": "connection refused", "duration_ms": 1}
        return super().call(verb, params, **kwargs)


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    broker: ExperimentBroker | None = None,
    poc: str = GOOD_POC,
    attempts: str = "1",
) -> tuple[str, Path, ExperimentBroker, list[str]]:
    _pin_all(monkeypatch)
    monkeypatch.setenv("XENTRY_POC_ATTEMPTS", attempts)
    authored: list[str] = []

    def fake_author(cve_text: str, facts: Facts, hint: str, previous: str = "") -> str:
        authored.append(previous)
        return poc

    monkeypatch.setattr("xentry.pocgen.author", fake_author)
    used = broker or ExperimentBroker()
    db_path = tmp_path / "xentry.db"
    init_db(db_path).close()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: _facts(),
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: used,
    )
    job_id = runner.submit_experiment(CVE_URL)
    item = runner._queue.get_nowait()
    assert item is not None
    runner.run_job(
        item.job_id,
        item.cve_url,
        item.poc_url,
        item.attempt_id,
        item.expected_bundle,
        experiment=item.experiment,
    )
    return job_id, tmp_path / "jobs" / job_id / "attempt-0", used, authored


# ------------------------------------------------------------- the pipeline ---


def test_an_experiment_runs_from_the_cve_link_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job_id, attempt_dir, broker, authored = _run(tmp_path, monkeypatch)
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["kind"] == "experiment"
        assert job["poc_url"] == ""
        assert job["outcome"] == "completed"
        assert job["verdict"] == "reproduced"
        # Attested by the attacker, as every derived run is.
        assert job["authority"] == "guest_attested+llm_assessed"
        names = [row["name"] for row in list_steps(conn, job_id)]
        assert "author_poc" in names
        # No PoC was fetched, because none was named.
        assert "stage_poc" not in names
        # And it is not a job: the job list must not show it.
        assert [row["id"] for row in list_jobs(conn)] == []
        assert [row["id"] for row in list_experiments(conn)] == [job_id]
    finally:
        conn.close()
    assert authored == [""]
    # The generated file is recorded, and staged by digest like any artifact.
    assert (attempt_dir / "exploit-1.py").read_text(encoding="utf-8") == GOOD_POC
    staged = broker.staged[0]
    archive = attempt_dir / "poc-generic.tar.gz"
    assert staged["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive) as handle:
        assert handle.getnames() == ["poc/exploit.py"]


def test_the_generated_code_runs_as_the_unprivileged_actor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The boundary does not move for generated code: the same checked-in step,
    the same actor, the same disposable VM."""
    _job_id, _dir, broker, _authored = _run(tmp_path, monkeypatch)
    from pathlib import Path as _Path

    from broker.steps import StepRegistry

    root = _Path(__file__).resolve().parents[1]
    registry = StepRegistry(root / "targets" / "steps.yaml", root / "targets")
    assert registry.steps["run-poc-generic"].user == "xentry-guest"
    assert registry.steps["build-poc-generic"].user == "xentry-guest"
    run = broker.exec_params["run-poc-generic"]
    assert run["entrypoint"] == "exploit.py"
    assert run["nonce_path"] == "/var/lib/xentry/nonce"


# -------------------------------------------------------------- the retries ---


def test_a_failed_attempt_is_rewritten_with_redacted_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The feedback must not carry the nonce: handing it to the author would
    let the next attempt print it without reading it from the target."""

    class LeakyBroker(ExperimentBroker):
        def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
            if verb == "exec" and str(params.get("step_id")) == "run-poc-generic":
                self.runs += 1
                self.exec_params["run-poc-generic"] = dict(params.get("params") or {})
                if self.runs == 1:
                    # A partial success: the failure text quotes the nonce.
                    return {
                        "exit_code": 1,
                        "stdout": f"got {self.nonce} but then crashed",
                        "stderr": "",
                        "duration_ms": 1,
                    }
                return {
                    "exit_code": 0,
                    "stdout": f"leaked: {self.nonce}",
                    "stderr": "",
                    "duration_ms": 1,
                }

            return super().call(verb, params, **kwargs)

    broker = LeakyBroker()
    job_id, _dir, used, authored = _run(tmp_path, monkeypatch, broker=broker, attempts="2")
    assert used.runs == 2
    assert len(authored) == 2
    feedback = authored[1]
    assert feedback, "the second attempt got no feedback"
    assert "[REDACTED]" in feedback
    assert used.nonce not in feedback
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "completed"
        names = [row["name"] for row in list_steps(conn, job_id)]
        assert "real_actor_try_1" in names
        assert "real_actor" in names
    finally:
        conn.close()


def test_attempts_are_bounded_and_the_last_failure_stands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = ExperimentBroker(leak=False)
    job_id, _dir, used, authored = _run(tmp_path, monkeypatch, broker=broker, attempts="3")
    assert used.runs == 3
    assert len(authored) == 3
    conn = connect(tmp_path / "xentry.db")
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "exploit_failed"
    finally:
        conn.close()


def test_the_attempt_cap_is_clamped(monkeypatch: pytest.MonkeyPatch) -> None:
    from xentry.runner import _poc_attempts

    monkeypatch.delenv("XENTRY_POC_ATTEMPTS", raising=False)
    assert _poc_attempts() == 3
    for value, expected in (("1", 1), ("7", 7), ("0", 1), ("-4", 1), ("99", 10), ("x", 3)):
        monkeypatch.setenv("XENTRY_POC_ATTEMPTS", value)
        assert _poc_attempts() == expected


# ------------------------------------------------------------- the authoring ---


def test_a_refusal_is_not_written_out_as_a_poc(monkeypatch: pytest.MonkeyPatch) -> None:
    """A model that declines returns prose. Writing it to disk would look like
    a broken exploit rather than a model that would not answer."""
    from xentry import pocgen

    class Reply:
        def __init__(self, text: str) -> None:
            self.choices = [type("C", (), {"message": type("M", (), {"content": text})()})()]

    monkeypatch.setenv("XENTRY_POC_MODEL", "openai/local")
    for text in ("I cannot help with that.", "", "```python\n```"):
        monkeypatch.setattr("litellm.completion", lambda _text=text, **_kw: Reply(_text))
        with pytest.raises(pocgen.PocGenError) as excinfo:
            pocgen.author("advisory", _facts(), "10.42.1.10")
        assert excinfo.value.code == "poc_rejected"


def test_an_oversized_reply_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from xentry import pocgen

    class Reply:
        def __init__(self, text: str) -> None:
            self.choices = [type("C", (), {"message": type("M", (), {"content": text})()})()]

    monkeypatch.setenv("XENTRY_POC_MODEL", "openai/local")
    huge = "print('x')\n" * 10_000
    monkeypatch.setattr("litellm.completion", lambda **_kw: Reply(huge))
    with pytest.raises(pocgen.PocGenError) as excinfo:
        pocgen.author("advisory", _facts(), "10.42.1.10")
    assert excinfo.value.code == "poc_rejected"


def test_no_model_configured_is_a_clean_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    from xentry import pocgen

    monkeypatch.delenv("XENTRY_POC_MODEL", raising=False)
    with pytest.raises(pocgen.PocGenError) as excinfo:
        pocgen.author("advisory", _facts(), "10.42.1.10")
    assert excinfo.value.code == "provider_unavailable"
    assert "XENTRY_POC_MODEL" in str(excinfo.value)


def test_a_retry_whose_author_fails_is_a_recorded_step_with_its_own_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The likeliest failure of this whole pipeline is an unreachable model.

    It must land on a row with provider_unavailable, not escape the retry loop
    as harness_error.
    """
    from xentry import pocgen

    _pin_all(monkeypatch)
    monkeypatch.setenv("XENTRY_POC_ATTEMPTS", "2")
    calls: list[int] = []

    def flaky(cve_text: str, facts: Facts, hint: str, previous: str = "") -> str:
        calls.append(1)
        if len(calls) == 1:
            return GOOD_POC
        raise pocgen.PocGenError("provider_unavailable", "connection refused")

    monkeypatch.setattr("xentry.pocgen.author", flaky)
    broker = ExperimentBroker(leak=False)
    db_path = tmp_path / "xentry.db"
    init_db(db_path).close()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: _facts(),
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    )
    job_id = runner.submit_experiment(CVE_URL)
    item = runner._queue.get_nowait()
    assert item is not None
    runner.run_job(
        item.job_id,
        item.cve_url,
        item.poc_url,
        item.attempt_id,
        item.expected_bundle,
        experiment=item.experiment,
    )
    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        assert job["outcome"] == "failed"
        assert job["reason_code"] == "provider_unavailable"
        failed = [
            (row["name"], row["reason_code"])
            for row in list_steps(conn, job_id)
            if row["state"] == "failed"
        ]
        assert ("author_poc_try_2", "provider_unavailable") in failed
    finally:
        conn.close()


def test_the_generated_prompt_and_reply_are_recorded_as_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """There is no repository to point at, so what the model was asked and what
    it answered is the entire provenance of the run.

    The artifacts CHECK rejected these kinds, and transcript.record() swallows a
    failing sink by design, so they were written to disk with no row at all.
    """
    from xentry.jobstore import list_artifacts

    _pin_all(monkeypatch)
    monkeypatch.setenv("XENTRY_POC_ATTEMPTS", "1")
    monkeypatch.setenv("XENTRY_POC_MODEL", "openai/local")

    class Reply:
        def __init__(self, text: str) -> None:
            self.choices = [type("C", (), {"message": type("M", (), {"content": text})()})()]

    monkeypatch.setattr("litellm.completion", lambda **_kw: Reply(GOOD_POC))
    broker = ExperimentBroker()
    db_path = tmp_path / "xentry.db"
    init_db(db_path).close()
    runner = JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: _facts(),
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    )
    job_id = runner.submit_experiment(CVE_URL)
    item = runner._queue.get_nowait()
    assert item is not None
    runner.run_job(
        item.job_id,
        item.cve_url,
        item.poc_url,
        item.attempt_id,
        item.expected_bundle,
        experiment=item.experiment,
    )
    conn = connect(db_path)
    try:
        kinds = {row["kind"] for row in list_artifacts(conn, job_id)}
        assert "llm_pocgen_prompt" in kinds
        assert "llm_pocgen_response" in kinds
    finally:
        conn.close()
    recorded = (tmp_path / "jobs" / job_id / "attempt-0" / "llm" / "pocgen.prompt.txt").read_text(
        encoding="utf-8"
    )
    # The advisory and the target address are in the prompt; the nonce is not,
    # which is what makes the generated code unable to fake the observation.
    assert "10.0.0.10" in recorded
    assert "CVE-2026-55555" in recorded
    assert broker.nonce
    assert broker.nonce not in recorded
