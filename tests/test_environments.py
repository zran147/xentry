"""Rebuilt environments: VMs brought back up for a human, not for evidence.

An environment runs the same sequence as a job and stops after the PoC is
built, so the two share almost all of their code. What has to be kept apart is
everything that makes a job a claim: an environment is never listed as a job,
never counted as one in flight, and never carries a verdict.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from tests.test_runner import (
    POC_URL,
    FakeBroker,
    fake_extract,
    fake_fetch,
    fake_validate,
)
from xentry.db import connect, init_db
from xentry.jobstore import (
    count_live_jobs,
    create_job,
    get_job,
    is_cancel_requested,
    list_environments,
    list_held_jobs,
    list_jobs,
    list_steps,
    record_outcome,
)
from xentry.runner import JobRunner, RunnerFailure
from xentry.web.app import _rebuild_candidates


def _runner(tmp_path: Path, broker: object) -> JobRunner:
    return JobRunner(
        db_path=tmp_path / "xentry.db",
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: broker,  # type: ignore[return-value]
    )


# ------------------------------------------------------------- the split ---


def test_an_environment_is_not_a_job_anywhere_it_would_be_counted(
    tmp_path: Path,
) -> None:
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, _attempt, _dir = create_job(
            conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
        )
        env_id, _eattempt, _edir = create_job(
            conn,
            data_dir=tmp_path,
            poc_url=POC_URL,
            cve_url="https://example.com/cve",
            kind="environment",
        )
        conn.commit()

        assert [row["id"] for row in list_jobs(conn)] == [job_id]
        assert [row["id"] for row in list_environments(conn)] == [env_id]
        # An environment has no outcome by design, so it must not look like a
        # job in flight: that is what a restart refuses to interrupt.
        assert count_live_jobs(conn) == 1
        assert list_held_jobs(conn) == []
    finally:
        conn.close()


def test_a_destroyed_environment_leaves_the_running_list(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "xentry.db")
    try:
        env_id, attempt_id, _dir = create_job(
            conn,
            data_dir=tmp_path,
            poc_url=POC_URL,
            cve_url="https://example.com/cve",
            kind="environment",
        )
        record_outcome(
            conn,
            job_id=env_id,
            attempt_id=attempt_id,
            outcome="cancelled",
            verdict="not_run",
            authority="runner_observed",
            reason_code="environment_destroyed",
        )
        assert list_environments(conn) == []
    finally:
        conn.close()


def test_the_kind_column_arrives_with_migration_005(tmp_path: Path) -> None:
    """A database written before this feature keeps its rows listed as jobs."""
    migrations = Path(__file__).resolve().parents[1] / "migrations"
    older = tmp_path / "m4"
    older.mkdir()
    for path in sorted(migrations.glob("00[1-4]_*.sql")):
        (older / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path, migrations_dir=older)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 4
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("SELECT kind FROM jobs")
        conn.execute(
            "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir) VALUES (?,?,?,?,?)",
            ("old-job", "php2shell", POC_URL, "now", "/tmp/old-job"),
        )
        conn.commit()
    finally:
        conn.close()

    upgraded = init_db(db_path, migrations_dir=migrations)
    try:
        assert upgraded.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 7
        row = upgraded.execute("SELECT kind FROM jobs WHERE id='old-job'").fetchone()
        assert row["kind"] == "job"
        assert [item["id"] for item in list_jobs(upgraded)] == ["old-job"]
    finally:
        upgraded.close()


# -------------------------------------------------------- what to rebuild ---


def test_a_cve_can_be_rebuilt_from_its_most_recent_completed_job(
    tmp_path: Path,
) -> None:
    conn = init_db(tmp_path / "xentry.db")
    try:
        ids = []
        for index in range(3):
            job_id, attempt_id, _dir = create_job(
                conn,
                data_dir=tmp_path,
                poc_url=POC_URL,
                cve_url="https://example.com/cve",
            )
            conn.execute(
                "UPDATE jobs SET cve_id=?, target_id=?, created_at=? WHERE id=?",
                ("CVE-2026-109618", "php2shell", f"2026-11-1{index}T00:00:00+00:00", job_id),
            )
            # The middle one failed, so it is not a thing to rebuild from.
            record_outcome(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                outcome="failed" if index == 1 else "completed",
                verdict="not_reproduced" if index == 1 else "reproduced",
                authority="runner_observed",
                reason_code="ok",
            )
            ids.append(job_id)
        # A second CVE gets its own entry, and an unfinished job gets none.
        other, other_attempt, _d = create_job(
            conn,
            data_dir=tmp_path,
            poc_url=POC_URL,
            cve_url="https://example.com/cve2",
        )
        conn.execute(
            "UPDATE jobs SET cve_id=?, target_id=? WHERE id=?",
            ("CVE-2026-85706", "gitlab", other),
        )
        record_outcome(
            conn,
            job_id=other,
            attempt_id=other_attempt,
            outcome="completed",
            verdict="reproduced",
            authority="runner_observed",
            reason_code="ok",
        )
        create_job(conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve")
        conn.commit()

        candidates = _rebuild_candidates(conn, tmp_path)
        # Ordered by CVE id as text, which is why 109618 sorts before 85706.
        assert [item["cve_id"] for item in candidates] == [
            "CVE-2026-109618",
            "CVE-2026-85706",
        ]
        by_cve = {item["cve_id"]: item for item in candidates}
        assert by_cve["CVE-2026-109618"]["job_id"] == ids[2]
        assert by_cve["CVE-2026-109618"]["target_id"] == "php2shell"
    finally:
        conn.close()


def test_a_job_with_no_link_check_can_still_be_rebuilt_from(tmp_path: Path) -> None:
    """Nothing is fetched, so no recorded source URL is needed.

    A rebuild takes the target id and runs the checked-in setup script over the
    pinned image. scripts/run_job_php.py submits without a link check and its
    jobs are rebuildable all the same.
    """
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, attempt_id, _dir = create_job(
            conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
        )
        conn.execute(
            "UPDATE jobs SET cve_id=?, target_id=? WHERE id=?",
            ("CVE-2026-43284", "dirtyfrag", job_id),
        )
        record_outcome(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            outcome="completed",
            verdict="reproduced",
            authority="guest_attested+llm_assessed",
            reason_code="ok",
        )
        conn.commit()
        assert conn.execute("SELECT COUNT(*) AS n FROM link_checks").fetchone()["n"] == 0
        candidates = _rebuild_candidates(conn, tmp_path)
        assert [item["job_id"] for item in candidates] == [job_id]
        assert candidates[0]["target_id"] == "dirtyfrag"
        # And the CVE that was run, not the target's first one.
        assert candidates[0]["cve_id"] == "CVE-2026-43284"
    finally:
        conn.close()


# ------------------------------------------------------------- the rebuild ---


def _source_job(tmp_path: Path, target_id: str = "php2shell") -> str:
    """A completed job, which is all a rebuild is offered from."""
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, attempt_id, _dir = create_job(
            conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
        )
        conn.execute(
            "UPDATE jobs SET cve_id=?, target_id=? WHERE id=?",
            ("CVE-2026-109618", target_id, job_id),
        )
        record_outcome(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            outcome="completed",
            verdict="reproduced",
            authority="runner_observed+llm_assessed",
            reason_code="ok",
        )
        conn.commit()
    finally:
        conn.close()
    return job_id


def _queue_build(tmp_path: Path) -> tuple[JobRunner, FakeBroker, str]:
    source = _source_job(tmp_path)
    broker = FakeBroker()
    runner = _runner(tmp_path, broker)
    return runner, broker, runner.build_environment(source)


def _build(tmp_path: Path) -> tuple[JobRunner, FakeBroker, str, Path]:
    runner, broker, env_id = _queue_build(tmp_path)
    item = runner._queue.get_nowait()
    assert item is not None
    runner.run_job(
        item.job_id,
        item.cve_url,
        item.poc_url,
        item.attempt_id,
        item.expected_bundle,
        environment=item.environment,
    )
    return runner, broker, env_id, tmp_path / "jobs" / env_id / "attempt-0"


def test_a_rebuild_leaves_both_vms_and_the_network_up(tmp_path: Path) -> None:
    _runner_obj, broker, env_id, attempt_dir = _build(tmp_path)
    assert broker.destroyed == []
    record = json.loads((attempt_dir / "environment.json").read_text(encoding="utf-8"))
    assert record["target_vm"] == "xentry-job-target"
    assert record["attacker_vm"] == "xentry-job-attacker"
    assert record["network_id"] == f"xentry-{env_id}"
    assert record["target_ip"] == "10.0.0.10"
    assert record["attacker_ip"] == "10.0.0.20"
    assert record["poc_dir"]
    assert record["keys_dir"].endswith("keys")


def test_a_rebuild_fetches_nothing_and_asks_no_model(tmp_path: Path) -> None:
    """The target is known, so steps 1-3 of a job have nothing to decide."""
    fetched: list[str] = []
    extracted = 0

    def count_fetch(url: str) -> object:
        fetched.append(url)
        return fake_fetch(url)

    def count_extract(artifacts: object) -> object:
        nonlocal extracted
        extracted += 1
        return fake_extract(artifacts)

    source = _source_job(tmp_path)
    broker = FakeBroker()
    runner = JobRunner(
        db_path=tmp_path / "xentry.db",
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=count_extract,  # type: ignore[arg-type]
        validate_fn=fake_validate,
        fetch_fn=count_fetch,  # type: ignore[arg-type]
        broker_factory=lambda: broker,  # type: ignore[return-value]
    )
    env_id = runner.build_environment(source)
    item = runner._queue.get_nowait()
    assert item is not None
    runner.run_job(
        item.job_id,
        item.cve_url,
        item.poc_url,
        item.attempt_id,
        item.expected_bundle,
        environment=item.environment,
    )

    assert fetched == []
    assert extracted == 0
    conn = connect(tmp_path / "xentry.db")
    try:
        names = [row["name"] for row in list_steps(conn, env_id)]
        assert names[0] == "select_target"
        assert "fetch" not in names
        assert "extract" not in names
        # The target it chose is the one the source job ran.
        row = get_job(conn, env_id)
        assert row is not None
        assert row["target_id"] == "php2shell"
        assert row["cve_id"] == "CVE-2026-109618"
    finally:
        conn.close()


def test_a_rebuild_never_measures_anything(tmp_path: Path) -> None:
    """It stops before the nonce, so it cannot produce or imply a verdict."""
    _runner_obj, broker, env_id, _dir = _build(tmp_path)
    verbs = [verb for verb, _params in broker.calls]
    assert "place_nonce" not in verbs
    assert "http_probe" not in verbs
    assert "snapshot" not in verbs
    conn = connect(tmp_path / "xentry.db")
    try:
        row = get_job(conn, env_id)
        assert row is not None
        assert row["verdict"] is None
        assert row["outcome"] is None
        validations = conn.execute(
            "SELECT COUNT(*) AS n FROM validations WHERE job_id=?", (env_id,)
        ).fetchone()
        assert validations["n"] == 0
    finally:
        conn.close()


def test_destroying_a_rebuild_tears_down_and_closes_the_row(tmp_path: Path) -> None:
    runner, broker, env_id, attempt_dir = _build(tmp_path)
    runner.destroy_environment(env_id)
    assert broker.destroyed == [
        "xentry-job-attacker",
        "xentry-job-target",
        f"xentry-{env_id}",
    ]
    assert not (attempt_dir / "environment.json").exists()
    conn = connect(tmp_path / "xentry.db")
    try:
        row = get_job(conn, env_id)
        assert row is not None
        assert row["outcome"] == "cancelled"
        assert row["verdict"] == "not_run"
        assert row["cleanup_state"] == "done"
        assert list_environments(conn) == []
    finally:
        conn.close()


def test_destroying_a_rebuild_that_is_still_building_asks_the_worker_to_stop(
    tmp_path: Path,
) -> None:
    """Two things must not tear down the same VMs at once."""
    runner, broker, env_id = _queue_build(tmp_path)
    # Queued but never run, so there is no environment.json and the worker
    # would still be holding whatever it had created.
    runner.destroy_environment(env_id)
    assert broker.destroyed == []
    conn = connect(tmp_path / "xentry.db")
    try:
        assert is_cancel_requested(conn, env_id)
        # Still listed: the worker's own teardown closes the row.
        assert [row["id"] for row in list_environments(conn)] == [env_id]
    finally:
        conn.close()


def test_a_rebuild_cannot_be_destroyed_twice(tmp_path: Path) -> None:
    runner, broker, env_id, _dir = _build(tmp_path)
    runner.destroy_environment(env_id)
    before = list(broker.destroyed)
    with pytest.raises(RunnerFailure) as excinfo:
        runner.destroy_environment(env_id)
    assert excinfo.value.code == "environment_gone"
    assert broker.destroyed == before


def test_a_job_cannot_be_destroyed_through_the_environment_path(
    tmp_path: Path,
) -> None:
    """Otherwise this would be an unauthenticated teardown of a running job."""
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, _attempt, _dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
    )
    conn.commit()
    conn.close()
    broker = FakeBroker()
    with pytest.raises(RunnerFailure) as excinfo:
        _runner(tmp_path, broker).destroy_environment(job_id)
    assert excinfo.value.code == "unknown_environment"
    assert broker.destroyed == []


def test_a_restart_destroys_a_rebuilt_environment(tmp_path: Path) -> None:
    """The user asked for these to be transient: an app restart clears them."""
    _runner_obj, _broker, env_id, _dir = _build(tmp_path)

    class ManagedBroker(FakeBroker):
        def call(
            self, verb: str, params: dict[str, object] | None = None, **kwargs: object
        ) -> object:
            if verb == "list_managed":
                return {
                    "domains": [
                        {"name": f"xentry-{env_id}-target", "state": "running"},
                        {"name": f"xentry-{env_id}-attacker", "state": "running"},
                    ],
                    "networks": [{"name": f"xentry-{env_id}", "active": True}],
                }
            return super().call(verb, params or {}, **kwargs)

    restarted = ManagedBroker()
    assert _runner(tmp_path, restarted).recover_interrupted() == [env_id]
    assert restarted.destroyed == [
        f"xentry-{env_id}-attacker",
        f"xentry-{env_id}-target",
        f"xentry-{env_id}",
    ]
    conn = connect(tmp_path / "xentry.db")
    try:
        row = get_job(conn, env_id)
        assert row is not None
        assert row["outcome"] == "interrupted"
    finally:
        conn.close()


def test_a_derived_job_is_rebuildable_while_its_facts_survive(tmp_path: Path) -> None:
    """The verified apache run is the case this exists for.

    CVE-2021-41773 reproduced as a DERIVED target, and the dropdown would not
    offer it: target_id is "generic", which has no checked-in TargetInstance to
    look up. The facts the check admitted are stored though, and so is the
    release that answered, so the rebuild replays both instead of looking
    anything up - no extractor call, no dated-index query.

    What it cannot survive is the retention sweep, so the offer is conditional
    on the facts still being there. That keeps the rule the old exclusion was
    protecting: never offer a rebuild that fails on the click.
    """
    from tests.test_generic_target import _facts
    from xentry import release, sourcestore

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    try:
        job_id, attempt_id, _dir = create_job(
            conn,
            data_dir=tmp_path,
            poc_url="https://github.com/blasty/CVE-2021-41773",
            cve_url="https://example.com/cve",
        )
        check_id = "c" * 32
        conn.execute(
            "UPDATE jobs SET cve_id=?, target_id=?, check_id=? WHERE id=?",
            ("CVE-2021-41773", "generic", check_id, job_id),
        )
        record_outcome(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            outcome="completed",
            verdict="reproduced",
            authority="guest_attested+llm_assessed",
            reason_code="nonce_observed_with_matching_evidence",
        )
        conn.commit()

        # Nothing stored yet: not offered, exactly as before.
        assert _rebuild_candidates(conn, tmp_path) == []

        facts = _facts(
            cve_id="CVE-2021-41773",
            product="Apache HTTP Server",
            affected_range="2.4.49",
            setup_packages=["apache2"],
            setup_units=["apache2"],
            ports=[80],
        )
        sourcestore.save_facts(tmp_path, check_id, facts.model_dump_json())
        offered = _rebuild_candidates(conn, tmp_path)
        assert [item["cve_id"] for item in offered] == ["CVE-2021-41773"]
        assert offered[0]["check_id"] == check_id
    finally:
        conn.close()

    # And the resolution round-trips, so the rebuild provisions the suite the
    # run used rather than whichever release the fallback happens to be.
    resolution = release.Resolution(
        release=release.RELEASES[0],
        package="apache2",
        prefix="2.4.49",
        version="2.4.49-4",
        exact=True,
    )
    sourcestore.save_resolution(tmp_path, "c" * 32, release.dump(resolution))
    back = release.restore(sourcestore.load_resolution(tmp_path, "c" * 32))
    assert back is not None
    assert back.release.suite == release.RELEASES[0].suite
    assert (back.package, back.prefix, back.exact) == ("apache2", "2.4.49", True)
    # A store that has been pruned, or predates this, yields None rather than a
    # half-real target - the caller then falls back explicitly.
    assert release.restore(sourcestore.load_resolution(tmp_path, "d" * 32)) is None


def _derived_source(tmp_path: Path) -> str:
    """A completed DERIVED job, with the facts and resolution a rebuild needs."""
    from tests.test_generic_target import _facts
    from tests.test_url_approval import _fetched
    from xentry import release, sourcestore

    check_id = "e" * 32
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, attempt_id, _dir = create_job(
            conn,
            data_dir=tmp_path,
            poc_url="https://github.com/blasty/CVE-2021-41773",
            cve_url="https://example.com/cve",
        )
        conn.execute(
            "UPDATE jobs SET cve_id=?, target_id=?, check_id=? WHERE id=?",
            ("CVE-2021-41773", "generic", check_id, job_id),
        )
        record_outcome(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            outcome="completed",
            verdict="reproduced",
            authority="guest_attested+llm_assessed",
            reason_code="nonce_observed_with_matching_evidence",
        )
        conn.commit()
    finally:
        conn.close()
    sourcestore.save_facts(
        tmp_path,
        check_id,
        _facts(
            cve_id="CVE-2021-41773",
            product="Apache HTTP Server",
            affected_range="2.4.49",
            setup_packages=["apache2"],
            setup_units=["apache2"],
            ports=[80],
            # The real blasty facts: apache2 as packaged is NOT vulnerable
            # until its own 000-default.conf is placed, so derive refuses
            # outright without the approved file - which is exactly what the
            # first working rebuild failed on.
            place="apache-site",
        ).model_dump_json(),
    )
    sourcestore.save(
        tmp_path,
        check_id,
        {
            # A real publication date: the derived path provisions from one
            # day BEFORE the advisory, so an undated body is refused with
            # "no snapshot serial for an undated advisory".
            "cve": _fetched(
                "https://example.com/cve",
                b"datePublished: 2021-10-05T08:40:12.000Z\n",
            ),
            "poc": _fetched("https://example.com/poc", b"readme"),
        },
    )
    sourcestore.add(
        tmp_path,
        check_id,
        "artifact0",
        _fetched(
            "https://raw.githubusercontent.com/blasty/CVE-2021-41773/HEAD/000-default.conf",
            b"<VirtualHost *:80>\n\t<Directory />\n\t\tRequire all granted\n"
            b"\t</Directory>\n</VirtualHost>\n",
        ),
    )
    sourcestore.save_resolution(
        tmp_path,
        check_id,
        release.dump(
            release.Resolution(
                release=release.RELEASES[0],
                package="apache2",
                prefix="2.4.49",
                version="2.4.49-4",
                exact=True,
            )
        ),
    )
    return job_id


def test_a_derived_rebuild_selects_its_target_and_builds(tmp_path: Path) -> None:
    """The rebuild RUNS, not just type-checks.

    The first version of this feature shipped with self._job.poc_url in
    derived_target - an attribute _JobLocal never had, since it holds only a
    deadline and a secrets list. Every static check passed: ruff, mypy, and an
    install script that grepped the source for the right call. The rebuild
    then died at step 1 with

        harness_error: '_JobLocal' object has no attribute 'poc_url'

    which tells a reader nothing about what was wrong. Only running the path
    catches that, so this test runs it.
    """
    source = _derived_source(tmp_path)
    broker = FakeBroker()
    runner = _runner(tmp_path, broker)
    env_id = runner.build_environment(source)
    item = runner._queue.get_nowait()
    assert item is not None
    assert item.environment is not None
    # The plan carries the check, which is where the facts live.
    assert item.environment.target_id == "generic"
    assert item.environment.check_id == "e" * 32
    runner.run_job(
        item.job_id,
        item.cve_url,
        item.poc_url,
        item.attempt_id,
        item.expected_bundle,
        environment=item.environment,
    )
    conn = connect(tmp_path / "xentry.db")
    try:
        steps = conn.execute(
            "SELECT name, state, detail FROM job_steps WHERE job_id=? ORDER BY seq",
            (env_id,),
        ).fetchall()
        first = dict(steps[0])
        assert first["name"] == "select_target", first
        assert first["state"] == "passed", first["detail"]
        # And the target it chose is the derived one, named for its CVE rather
        # than for a checked-in instance it does not have.
        row = dict(conn.execute("SELECT * FROM jobs WHERE id=?", (env_id,)).fetchone())
        assert row["cve_id"] == "CVE-2021-41773"
        assert row["target_id"] == "generic"
        # The approved config is staged, from the same store, in the order the
        # job used. Without it derive refuses and the rebuild dies at step 1
        # with "it needs a file placed as apache-site".
        names = [str(dict(step)["name"]) for step in steps]
        assert "stage_approved" in names, names
        assert names.index("stage_approved") < names.index("provision"), names
    finally:
        conn.close()
