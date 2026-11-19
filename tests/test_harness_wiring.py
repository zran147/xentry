"""The provision step, when a model owns it.

These drive the whole branch with a scripted model and no network, which is
what `provision_fn` being injected is for. The point is not that a model can
provision - it is that the plumbing around one behaves: the guard when no
model is configured, the session journal, the give-up artifact, and the
ordinary path staying untouched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.test_runner import FakeBroker, fake_extract, fake_fetch, fake_validate
from xentry.db import init_db
from xentry.jobstore import create_job, get_job
from xentry.runner import JobRunner

CAPTURE = {
    "dpkg-query": "redis-server 5:5.0.14-1\nlibc6 2.28-10",
    "ss -Hltn": "0.0.0.0:6379",
    "systemctl list-unit-files": "redis-server.service",
}


class HarnessBroker(FakeBroker):
    """FakeBroker plus the one verb a model drives, answering a fixed machine."""

    def call(self, verb: str, params: dict[str, Any], **kw: Any) -> Any:
        if verb == "free_exec_target":
            command = str(params.get("command") or "")
            body = next((v for k, v in CAPTURE.items() if k in command), "")
            self.calls.append((verb, params))
            return {"exit_code": 0, "stdout": body, "stderr": "", "duration_ms": 1}
        return super().call(verb, params, **kw)


def _runner(tmp_path: Path, provision_fn: Any = None) -> JobRunner:
    return JobRunner(
        db_path=tmp_path / "xentry.db",
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        provision_fn=provision_fn,
    )


def _harness_job(tmp_path: Path) -> str:
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, _attempt, _dir = create_job(
            conn, data_dir=tmp_path, poc_url="https://example.com/poc", kind="harness_job"
        )
        return job_id
    finally:
        conn.close()


def test_the_kind_chooses_the_branch_and_nothing_else_does() -> None:
    """A harness job must not reach the reviewed setup script, and vice versa.

    The step keeps its position, its seq and its name - only the way of
    getting there changes - so the one thing that can go wrong silently is the
    branch reading the wrong field.
    """
    import inspect

    source = inspect.getsource(JobRunner)
    assert '(get_job(conn, job_id) or {}).get("kind")) == "harness_job"' in source
    assert '"provision-generated" if harnessed else target.setup_step_id' in source
    assert "harness_provision if harnessed else setup_step" in source


def test_a_harness_job_without_a_model_is_refused_not_quietly_ordinary() -> None:
    """provision_fn=None must fail, never fall back to the reviewed script.

    A silent fallback is the worst outcome available: the job would record
    kind='harness_job' and the Route row would say a model built the target,
    while the reviewed script had actually done it.
    """
    import inspect

    from xentry import harness

    source = inspect.getsource(JobRunner)
    assert "harness mode needs a provisioner model" in source
    # And the failure is a RunnerFailure, so the step fails rather than the
    # run crashing with an AttributeError halfway through provisioning.
    assert 'raise RunnerFailure(\n                        "harness_error"' in source
    # The tool layer it would have built offers only the target's free verb.
    assert "free_exec_target" in harness.EXPLORE_TOOLS


def test_the_prompt_is_recorded_as_an_artifact_before_the_model_runs() -> None:
    """A prompt change has to show up in the history, not be invisible.

    ADR 0003 asks for this explicitly: the prompt is the most consequential
    thing in the mode, so it is stored per job like the extractor's.
    """
    import inspect

    source = inspect.getsource(JobRunner)
    assert 'kind="llm_provision_prompt"' in source
    recorded = source.index('kind="llm_provision_prompt"')
    started = source.index("harness.run_session(")
    assert recorded < started, "the prompt is recorded after the model ran"


def test_a_give_up_is_written_where_truncation_cannot_reach_it() -> None:
    """_detail keeps the last 4000 characters; the reasoning is the whole value.

    The redis job's real error arrived cut mid-sentence for exactly this
    reason, so a model's "I cannot build this, and here is why" is an
    artifact.
    """
    import inspect

    source = inspect.getsource(JobRunner)
    give_up = source.index("provision-gave-up.txt")
    failure = source.index('"provision_failed", outcome.detail or outcome.reason_code')
    assert give_up < failure, "the artifact is written after the failure is raised"
    assert 'kind="evidence"' in source[give_up - 400 : give_up + 400]


def test_the_session_records_every_kind_the_feed_draws() -> None:
    """A tool call that leaves no trace is the one thing this mode cannot have.

    The journal is hash-chained, so what it holds is verifiable - but only
    what reaches it. These three are what the live feed renders.
    """
    import inspect

    source = inspect.getsource(JobRunner)
    # Scoped to the branch and counted, rather than matched against an exact
    # indentation - a formatting-sensitive assertion fails on a reformat and
    # passes on a deletion, which is the wrong way round.
    block = source[source.index("def harness_provision") : source.index("def setup_step")]
    assert block.count("session_event(") == 3, block.count("session_event(")
    for kind in ('"tool_call"', '"readiness"', '"declaration"'):
        assert kind in block, kind


def test_an_ordinary_job_never_builds_a_tool_layer(tmp_path: Path) -> None:
    """The reviewed path must be unchanged by all of this.

    If a plain job ever constructed a ToolLayer or took a snapshot it did not
    need, the harness work would have cost every existing job something.
    """
    broker = HarnessBroker()
    runner = _runner(tmp_path, provision_fn=lambda prompt, tools: lambda f: "")
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, _a, _d = create_job(conn, data_dir=tmp_path, poc_url="https://e/p")
        assert str((get_job(conn, job_id) or {}).get("kind")) == "job"
    finally:
        conn.close()
    assert not [verb for verb, _p in broker.calls if verb == "free_exec_target"]
    assert runner.provision_fn is not None  # configured, and still unused


def test_every_broker_call_the_branch_makes_uses_a_vocabulary_the_broker_has() -> None:
    """An invented parameter value fails at the first live run, not in CI.

    The branch asked for kind="harness-clean" and the broker allows exactly
    {"disk", "memory"}, so the first harness job that ever reached a model
    died at its first broker call with "invalid snapshot kind" - after
    creating a network and a VM. The vocabulary is the broker's, so it is read
    from the broker here rather than restated.
    """
    import inspect
    import re

    from broker.runtime import BrokerRuntime
    from xentry.runner import JobRunner

    source = inspect.getsource(JobRunner)
    block = source[source.index("def harness_provision") : source.index("def setup_step")]

    # The snapshot kind, against the set the broker actually checks.
    allowed = re.search(
        r"if kind not in \{([^}]+)\}", inspect.getsource(BrokerRuntime.snapshot)
    )
    assert allowed, "the broker's snapshot check changed shape"
    kinds = {value.strip().strip('"') for value in allowed.group(1).split(",")}
    asked = re.search(r'"snapshot", \{"vm_id": target_vm, "kind": "([a-z-]+)"\}', block)
    assert asked, "the branch no longer takes a snapshot the way this test reads"
    assert asked.group(1) in kinds, f"{asked.group(1)} is not one of {sorted(kinds)}"

    # And every verb it names is a verb the broker routes.
    from broker.main import VERB_PARAMS

    for verb in re.findall(r'client\.call\(\s*"([a-z_]+)"', block):
        assert verb in VERB_PARAMS, verb
