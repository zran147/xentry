"""Harness mode, first slice: selectable, recorded, visible.

The mode does nothing yet - a harness job still provisions from the reviewed
script - so there is no behaviour to test. What there is to test is the record,
and three of these four failures are silent: a `kind` nobody writes, a kind the
job list filters away, and a page that shows two different claims identically.

The one that bites is the in-flight count. `kind='experiment'` is kept out of
`list_jobs` and `count_live_jobs` on purpose (runner.py, submit_experiment:
"so it never appears in the job list, is never counted as a job in flight").
A harness job holds a real VM, so inheriting that invisibility would let two
run at once with neither counted and neither releasable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_runner import POC_URL, FakeBroker, fake_extract, fake_fetch, fake_validate
from xentry.db import init_db
from xentry.jobstore import (
    count_live_jobs,
    create_job,
    get_job,
    list_environments,
    list_experiments,
    list_jobs,
)
from xentry.runner import JobRunner
from xentry.web.app import build_app

HARNESS_KIND = "harness_job"


def _runner(tmp_path: Path) -> JobRunner:
    return JobRunner(
        db_path=tmp_path / "xentry.db",
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: FakeBroker(),  # type: ignore[arg-type,return-value]
    )


def _app(tmp_path: Path, runner: object | None = None) -> object:
    return build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=runner,  # type: ignore[arg-type]
    )


# ------------------------------------------------------- 1: the switch ---


def test_the_submit_page_offers_the_switch_and_it_is_off(tmp_path: Path) -> None:
    """Rendered, labelled, and unchecked.

    Two failures in one: a switch that does not render at all, and a switch
    that renders already on - which would silently send every submission down
    the harness route, including the operator's next ordinary job.
    """
    with TestClient(_app(tmp_path)) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert 'id="harness-switch"' in page.text
        # The label the ADR specifies, verbatim, because "harness" alone does
        # not say which way is which.
        assert "off for no harness, on for with harness" in page.text
        # The input's own attributes, isolated from the rest of the form: a
        # `checked` anywhere else on the page would satisfy a bare substring.
        start = page.text.index('id="harness-switch"')
        tag = page.text[page.text.rindex("<input", 0, start): page.text.index(">", start)]
        assert "checked" not in tag, tag
        assert 'type="checkbox"' in tag


# ------------------------------------------- 2: recorded as harness_job ---


def test_a_harness_submission_is_recorded_as_its_own_kind(tmp_path: Path) -> None:
    """The switch reaches the row, and off still means kind='job'.

    Without the second half this passes just as well if `kind` is hard-coded
    to 'harness_job' for everything.
    """
    init_db(tmp_path / "xentry.db").close()
    runner = _runner(tmp_path)
    harness_id = runner.submit("https://example.com/cve", POC_URL, harness=True)
    plain_id = runner.submit("https://example.com/cve", POC_URL)
    conn = init_db(tmp_path / "xentry.db")
    try:
        assert (get_job(conn, harness_id) or {})["kind"] == HARNESS_KIND
        assert (get_job(conn, plain_id) or {})["kind"] == "job"
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("body", "expected"),
    [({"harness": True}, True), ({"harness": False}, False), ({}, False)],
)
def test_the_submit_endpoint_passes_the_switch_through(
    tmp_path: Path, body: dict[str, bool], expected: bool
) -> None:
    """Including the omitted case.

    A client that predates the switch must get the reviewed route, so the
    field has to default off rather than be required - and a required field
    would turn every old caller into a 422 instead.
    """
    from tests.test_web import FakeRunner

    runner = FakeRunner()
    app = _app(tmp_path, runner)
    with TestClient(app) as client:
        client.get("/")
        conn = init_db(tmp_path / "data" / "xentry.db")
        try:
            # A claimable check, written directly: the link check itself is
            # identical for both routes and has its own tests.
            conn.execute(
                "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
                "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    "chk-1",
                    "https://example.com/cve",
                    POC_URL,
                    "CVE-2026-109618",
                    "php2shell",
                    hashlib.sha256(b"bundle").hexdigest(),
                    "2026-11-18T00:00:00+00:00",
                    "2099-01-01T00:00:00+00:00",
                ),
            )
            conn.commit()
        finally:
            conn.close()
        posted = client.post(
            "/api/jobs",
            json={
                "cve_url": "https://example.com/cve",
                "poc_url": POC_URL,
                "check_id": "chk-1",
                **body,
            },
            headers={"X-Xentry-CSRF": app.state.token},  # type: ignore[attr-defined]
        )
        assert posted.status_code == 200, posted.text
        assert runner.harnessed == [expected]


# ------------------------------------- 3: the queries that would hide it ---


def test_a_harness_job_is_listed_and_counted_like_any_other_job(
    tmp_path: Path,
) -> None:
    """The in-flight count is the one that holds a VM.

    `list_jobs` and `count_live_jobs` both filtered on kind='job'. A harness
    job dropped by either is invisible to the restart gate, so two could hold
    a target VM at once. The experiment and environment rows are here to prove
    the fix widened the filter rather than removed it.
    """
    conn = init_db(tmp_path / "xentry.db")
    try:
        job_id, _a, _d = create_job(
            conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
        )
        harness_id, _ha, _hd = create_job(
            conn,
            data_dir=tmp_path,
            poc_url=POC_URL,
            cve_url="https://example.com/cve",
            kind=HARNESS_KIND,
        )
        exp_id, _ea, _ed = create_job(
            conn, data_dir=tmp_path, poc_url="", cve_url="https://example.com/cve",
            kind="experiment",
        )
        env_id, _na, _nd = create_job(
            conn, data_dir=tmp_path, poc_url=POC_URL, kind="environment",
        )
        conn.commit()

        listed = {row["id"] for row in list_jobs(conn)}
        assert listed == {job_id, harness_id}
        # Two jobs in flight, one of them the harness route. One would mean
        # the harness job is uncounted; three would mean the experiment or the
        # environment leaked in.
        assert count_live_jobs(conn) == 2
        # ... and the kinds that are hidden on purpose still are.
        assert [row["id"] for row in list_experiments(conn)] == [exp_id]
        assert [row["id"] for row in list_environments(conn)] == [env_id]
    finally:
        conn.close()


def test_a_lone_harness_job_is_one_job_in_flight(tmp_path: Path) -> None:
    """On its own, with nothing else in the database to carry the count.

    The previous test counts two and would still pass if the filter matched
    kind='job' and happened to see the harness row some other way. This one
    has only the harness row, so zero means it is uncounted.
    """
    conn = init_db(tmp_path / "xentry.db")
    try:
        create_job(
            conn,
            data_dir=tmp_path,
            poc_url=POC_URL,
            cve_url="https://example.com/cve",
            kind=HARNESS_KIND,
        )
        conn.commit()
        assert count_live_jobs(conn) == 1
        assert len(list_jobs(conn)) == 1
    finally:
        conn.close()


# -------------------------------------------- 4: the route on the page ---


def _job_page(tmp_path: Path, kind: str) -> str:
    app = _app(tmp_path)
    with TestClient(app) as client:
        client.get("/")
        conn = init_db(tmp_path / "data" / "xentry.db")
        try:
            job_id, _a, _d = create_job(
                conn, data_dir=tmp_path / "data", poc_url=POC_URL, kind=kind
            )
            conn.commit()
        finally:
            conn.close()
        page = client.get(f"/jobs/{job_id}")
        assert page.status_code == 200
        return page.text


def test_the_job_page_names_the_route_that_produced_it(tmp_path: Path) -> None:
    """Both routes, because a label only one of them carries proves nothing.

    ADR 0003: a harness job and a fixed-script job can both end
    verdict=reproduced and are not the same claim. If the page does not say
    which, the history holds two claims spelled identically.
    """
    harness = _job_page(tmp_path / "h", HARNESS_KIND)
    assert "<dt>Route</dt>" in harness
    assert "harness - the model built the target itself" in harness

    plain = _job_page(tmp_path / "p", "job")
    assert "<dt>Route</dt>" in plain
    assert "no harness - a reviewed provisioning script" in plain
    assert "the model built the target itself" not in plain


def test_the_route_cell_is_not_overwritten_by_the_live_poll(tmp_path: Path) -> None:
    """No data-field="kind" on the Route cell.

    updateFacts() in app.js replaces the text of any [data-field=X] with the
    raw value of job.X from /api/jobs/{id}. Tagging this cell would have the
    sentence survive the first render and then turn into "harness_job" a
    second later - visible only to someone watching a running job.
    """
    assert 'data-field="kind"' not in _job_page(tmp_path, HARNESS_KIND)


def test_a_held_harness_job_appears_on_the_running_vms_page(tmp_path: Path) -> None:
    """Otherwise its VM is up with no way to release it.

    list_held_jobs is the third kind='job' filter, and the Running VMs page
    calls it with the default. That page drives the release button and the
    login details, so a held harness job would have held memory indefinitely
    with the UI showing nothing to release - the failure only visible to
    whoever noticed the host was short of RAM.

    An explicit kind= still asks for exactly that kind, which is what keeps
    the experiment page from mixing experiments in with jobs.
    """
    from xentry.jobstore import list_held_jobs, record_artifact

    held_file = tmp_path / "held-vms.json"
    held_file.write_text("{}", encoding="utf-8")
    conn = init_db(tmp_path / "xentry.db")
    try:
        by_kind: dict[str, str] = {}
        for kind in ("job", "harness_job", "experiment"):
            job_id, attempt_id, _dir = create_job(
                conn, data_dir=tmp_path, poc_url=POC_URL, kind=kind
            )
            record_artifact(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                kind="held_vms",
                path=held_file,
                sha256=hashlib.sha256(b"{}").hexdigest(),
                size=2,
            )
            by_kind[kind] = job_id

        ids = {row["id"] for row in list_held_jobs(conn)}
        assert by_kind["job"] in ids
        assert by_kind["harness_job"] in ids, "the harness job's VM is unreleasable"
        # The widening must not let the experiment page's VMs leak in here.
        assert by_kind["experiment"] not in ids
        # And asking for experiments explicitly still returns only those.
        only = {row["id"] for row in list_held_jobs(conn, kind="experiment")}
        assert only == {by_kind["experiment"]}
    finally:
        conn.close()
