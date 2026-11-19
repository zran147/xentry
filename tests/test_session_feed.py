"""The live feed: the session endpoint, the cursor, and the chain under it.

The feed is the only way to watch a harness job while it runs, and three of
these failures are silent. A cursor that does not advance replays the whole
session on every poll, which looks like a model repeating itself. A cursor that
advances too far drops records nobody will ever know were written. And a writer
that bypasses `events.append` breaks the hash chain, which is the one property
that makes the card worth reading: ADR 0003 asks the record to show that the
recorded sequence of commands is the sequence that ran.

So the chain is checked with `events.verify`, and then checked again after a
record is spliced out - a verify that cannot fail proves nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.test_web import POC_URL, FakeRunner
from xentry import events
from xentry.db import init_db
from xentry.jobstore import begin_step, create_job, session_event
from xentry.web.app import build_app

CVE_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-109618"


def _app(tmp_path: Path) -> object:
    return build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )


def _harness_job(tmp_path: Path, *, with_provision: bool = False) -> tuple[str, Path]:
    """A harness job on disk, with the attempt directory it writes into."""
    conn = init_db(tmp_path / "data" / "xentry.db")
    try:
        job_id, attempt_id, attempt_dir = create_job(
            conn,
            data_dir=tmp_path / "data",
            poc_url=POC_URL,
            cve_url=CVE_URL,
            kind="harness_job",
        )
        if with_provision:
            begin_step(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                seq=6,
                name="provision",
                step_id="setup-generic",
            )
        conn.commit()
    finally:
        conn.close()
    return job_id, attempt_dir


def _write(tmp_path: Path, job_id: str, records: list[tuple[str, dict[str, object]]]) -> None:
    conn = init_db(tmp_path / "data" / "xentry.db")
    try:
        for kind, payload in records:
            session_event(conn, job_id, kind, payload)
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------- 1: the cursor ---------


def test_the_endpoint_serves_only_the_events_after_the_cursor(tmp_path: Path) -> None:
    """And the cursor it hands back is the one that produces nothing twice.

    A cursor that does not advance is the failure that looks like a working
    feed: every poll returns the whole session again, and the card grows a
    duplicate of everything already in it.
    """
    job_id, _dir = _harness_job(tmp_path)
    _write(
        tmp_path,
        job_id,
        [
            ("reasoning", {"text": "the archive may carry 5.0.14"}),
            ("tool_call", {"verb": "free_exec", "params": {"command": "apt-get update"}}),
            ("tool_result", {"verb": "free_exec", "status": 0, "sha256": "a" * 64, "body": "ok"}),
        ],
    )
    with TestClient(_app(tmp_path)) as client:
        first = client.get(f"/api/jobs/{job_id}/session")
        assert first.status_code == 200, first.text
        body = first.json()
        assert [item["type"] for item in body["items"]] == [
            "session_reasoning",
            "session_tool_call",
            "session_tool_result",
        ]
        cursor = body["cursor"]

        # Nothing new: the same cursor must come back with an empty page.
        again = client.get(f"/api/jobs/{job_id}/session", params={"cursor": cursor}).json()
        assert again["items"] == []
        assert again["cursor"] == cursor

        _write(tmp_path, job_id, [("declaration", {"declaration": "ready", "script": "/tmp/p.sh"})])
        tail = client.get(f"/api/jobs/{job_id}/session", params={"cursor": cursor}).json()
        assert [item["type"] for item in tail["items"]] == ["session_declaration"]
        assert tail["cursor"] > cursor


def test_the_cursor_steps_over_the_records_that_are_not_the_session(tmp_path: Path) -> None:
    """The journal holds the runner's own events too, and they are filtered out.

    The cursor indexes the whole journal rather than the session, so a
    `step_started` written between two tool calls must not make the next poll
    re-serve the call before it - which is what a cursor counting only the
    records this route returns would do.
    """
    job_id, _dir = _harness_job(tmp_path)
    _write(tmp_path, job_id, [("reasoning", {"text": "first"})])
    with TestClient(_app(tmp_path)) as client:
        body = client.get(f"/api/jobs/{job_id}/session").json()
        # job_created is in the journal and is not a session event.
        assert [item["type"] for item in body["items"]] == ["session_reasoning"]
        assert body["cursor"] == 2
        cursor = body["cursor"]

        # A step transition, then one more session record.
        conn = init_db(tmp_path / "data" / "xentry.db")
        try:
            attempt = conn.execute(
                "SELECT id FROM attempts WHERE job_id=?", (job_id,)
            ).fetchone()
            begin_step(
                conn, job_id=job_id, attempt_id=str(attempt["id"]), seq=1, name="provision"
            )
            session_event(conn, job_id, "reasoning", {"text": "second"})
            conn.commit()
        finally:
            conn.close()

        tail = client.get(f"/api/jobs/{job_id}/session", params={"cursor": cursor}).json()
        assert [item["payload"]["text"] for item in tail["items"]] == ["second"]


def test_a_cursor_past_the_end_or_below_zero_cannot_replay(tmp_path: Path) -> None:
    """Nothing a client sends can make this endpoint serve a record twice.

    A negative cursor is a slice from the END in Python, which would quietly
    return the tail of the session to a caller who asked for everything.
    """
    job_id, _dir = _harness_job(tmp_path)
    _write(tmp_path, job_id, [("reasoning", {"text": f"step {n}"}) for n in range(4)])
    with TestClient(_app(tmp_path)) as client:
        assert client.get(f"/api/jobs/{job_id}/session", params={"cursor": 999}).json()["items"] == []
        everything = client.get(f"/api/jobs/{job_id}/session", params={"cursor": -3}).json()
        assert len(everything["items"]) == 4


def test_an_unknown_job_is_a_404(tmp_path: Path) -> None:
    """Not an empty feed: a mistyped id must not look like a quiet model."""
    with TestClient(_app(tmp_path)) as client:
        missing = client.get("/api/jobs/deadbeef/session")
        assert missing.status_code == 404
        assert missing.json()["detail"] == "unknown job"


def test_the_endpoint_writes_nothing(tmp_path: Path) -> None:
    """It is polled every couple of seconds; it may only read.

    Asserted on the journal's own bytes, because an endpoint that appended
    even one record per poll would grow the file it is reading.
    """
    job_id, attempt_dir = _harness_job(tmp_path)
    _write(tmp_path, job_id, [("reasoning", {"text": "only this"})])
    journal = attempt_dir / "events.jsonl"
    before = journal.read_bytes()
    with TestClient(_app(tmp_path)) as client:
        for _ in range(3):
            assert client.get(f"/api/jobs/{job_id}/session").status_code == 200
    assert journal.read_bytes() == before


# ------------------------------------------------- 2: the chain ----------


def test_the_chain_still_verifies_after_a_whole_session(tmp_path: Path) -> None:
    """Every kind, through the public writer, and the chain holds.

    This is the property the card's claim rests on. The second half is what
    gives the first half teeth: a record spliced out of the middle - exactly
    the edit someone covering up a command would make - must fail verify.
    """
    job_id, attempt_dir = _harness_job(tmp_path)
    _write(
        tmp_path,
        job_id,
        [
            ("reasoning", {"text": "redis 5.0.14 is what the advisory names"}),
            ("tool_call", {"verb": "free_exec", "params": {"command": "apt-get install redis"}}),
            ("tool_result", {"verb": "free_exec", "status": 0, "sha256": "b" * 64, "body": "done"}),
            ("readiness", {"passed": False, "reason_code": "port_closed", "detail": "6379 shut"}),
            ("declaration", {"declaration": "give_up", "reason_code": "version_unavailable"}),
        ],
    )
    journal = attempt_dir / "events.jsonl"
    recorded = events.read(journal)
    assert [row["type"] for row in recorded][1:] == [
        "session_reasoning",
        "session_tool_call",
        "session_tool_result",
        "session_readiness",
        "session_declaration",
    ]
    # Every record carries the previous one's hash, so the sequence is the
    # sequence that ran.
    assert events.verify(journal)

    spliced = [row for row in recorded if row["type"] != "session_tool_call"]
    journal.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in spliced), encoding="utf-8"
    )
    assert not events.verify(journal), "a removed tool call must break the chain"


def test_the_writer_refuses_a_kind_the_feed_cannot_draw(tmp_path: Path) -> None:
    """The set is closed on purpose.

    An unrecognised kind would be written into the chain and then render as
    nothing at all, which is the one failure the reader cannot see.
    """
    job_id, attempt_dir = _harness_job(tmp_path)
    conn = init_db(tmp_path / "data" / "xentry.db")
    try:
        with pytest.raises(ValueError, match="session event kind"):
            session_event(conn, job_id, "tool_calls", {"verb": "free_exec"})
    finally:
        conn.close()
    assert [row["type"] for row in events.read(attempt_dir / "events.jsonl")] == ["job_created"]


def test_a_session_event_lands_in_the_attempts_journal(tmp_path: Path) -> None:
    """Through the attempt the job resolves to, not a path the caller passed.

    The writer takes a job id because that is what a model loop holds; the
    directory has to come from the attempt row, the way every other event's
    does, or two attempts of one job would write into the same file.
    """
    job_id, attempt_dir = _harness_job(tmp_path)
    _write(tmp_path, job_id, [("tool_call", {"verb": "snapshot", "params": {"vm_id": "t1"}})])
    records = events.read(attempt_dir / "events.jsonl")
    assert records[-1]["type"] == "session_tool_call"
    assert records[-1]["payload"]["verb"] == "snapshot"
    # Tagged with the attempt, like every other record in the file.
    assert records[-1]["payload"]["attempt_id"] == records[0]["payload"]["attempt_id"]


# ------------------------------------------------- 3: the card -----------


def test_the_provision_row_renders_the_feed_and_is_open_by_default(tmp_path: Path) -> None:
    """Inside the provision row of the Steps card, expanded.

    Two failures in one: a feed that renders in a card of its own, away from
    the step it belongs to, and a feed that renders collapsed - which makes a
    live session something the reader has to go and find.
    """
    job_id, _dir = _harness_job(tmp_path, with_provision=True)
    with TestClient(_app(tmp_path)) as client:
        page = client.get(f"/jobs/{job_id}")
        assert page.status_code == 200
        body = page.text
        assert 'id="session-feed"' in body

        # It is a detail row of the Steps table, under provision.
        start = body.index('id="session-feed"')
        row = body.rindex("<tr", 0, start)
        assert 'data-detail="session:provision"' in body[row:start]
        # The provision step row comes first, so the feed hangs off it.
        assert body.rindex('data-step="provision"', 0, row) > 0
        # Open: no hidden attribute on the row the browser toggles. app.js
        # treats an unknown key as open, so the server must agree.
        assert "hidden" not in body[row:start]

        # And the page tells the browser which route this is, so it knows
        # there is a session to poll for.
        assert 'data-kind="harness_job"' in body


def test_a_plain_job_renders_no_session_card(tmp_path: Path) -> None:
    """Only a harness job has a session.

    Without this the feed is an empty black box on every job page ever run,
    promising a live session that no non-harness job will ever write.
    """
    conn = init_db(tmp_path / "data" / "xentry.db")
    try:
        job_id, attempt_id, _dir = create_job(
            conn, data_dir=tmp_path / "data", poc_url=POC_URL, cve_url=CVE_URL
        )
        begin_step(conn, job_id=job_id, attempt_id=attempt_id, seq=6, name="provision")
        conn.commit()
    finally:
        conn.close()
    with TestClient(_app(tmp_path)) as client:
        body = client.get(f"/jobs/{job_id}").text
        assert 'id="session-feed"' not in body
        assert 'data-detail="session:provision"' not in body
