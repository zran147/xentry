"""Rendered-HTML tests for the audit and job page cards.

Grepping the templates proves nothing here: a Jinja comment matches the same
string a rendered paragraph would, and three of these four changes are about
what a reader actually SEES. So every assertion below is made against the
output of env.get_template(...).render(...), and StrictUndefined is on so a
context key this page needs cannot be silently empty.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import jinja2

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src" / "xentry" / "web" / "templates"

JOB = {
    "id": "abcdef0123456789aa",
    "target_id": "php2shell",
    "cve_id": "CVE-2026-109618",
    "state": "completed",
    "verdict": "reproduced",
    "authority": "runner_observed+llm_assessed",
    "reason_code": "nonce_observed",
    "cleanup_state": "done",
    "created_at": "2026-11-17T07:00:00+00:00",
    "started_at": "2026-11-17T07:00:05+00:00",
    "finished_at": "2026-11-17T07:04:05+00:00",
    "outcome": "completed",
    "poc_url": "https://github.com/o/r",
    "check_id": "",
}
PROVES = ["the nonce is readable by the PHP web user"]
NOT_PROVES = ["this is not a risk assessment"]


def _env() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        undefined=jinja2.StrictUndefined,
        autoescape=True,
    )
    env.globals["asset_v"] = lambda: "v"
    env.globals["url_for"] = lambda *a: "/"
    return env


def _artifact(kind: str, path: str, **over: Any) -> dict[str, Any]:
    row = {
        "id": f"art-{abs(hash((kind, path))) % 10**8}",
        "attempt_id": "att-1",
        "kind": kind,
        # The runner records an absolute path; the bundle and the page show the
        # base name. Both shapes go through these tests.
        "path": f"/var/lib/xentry/jobs/j/attempt-0/{path}",
        "sha256": "a" * 64,
        "bytes": 1234,
    }
    row.update(over)
    return row


# Every kind= / name pair the runner actually writes, read off the
# record_artifact() calls in src/xentry/runner.py. Nothing is invented: a file
# the runner does not produce has no row here.
# Short on purpose: a label that wraps makes its row taller than every other
# row, and the detail these used to carry after a colon was always in the file
# name beside them.
RECORDED = [
    ("evidence", "cve.html", "Advisory record"),
    ("poc", "poc.html", "PoC page"),
    ("evidence", "citations-dropped.txt", "Citations dropped"),
    ("evidence", "criteria.json", "Success criteria"),
    ("evidence", "provision-inputs.json", "Provisioning inputs"),
    ("evidence", "provision-commands.txt", "Provision transcript"),
    ("evidence", "real_actor-commands.txt", "PoC run transcript"),
    ("setup_script", "setup.sh", "Setup script"),
    ("poc", "app-source.tar.gz", "Application source"),
    ("poc", "poc-generic.tar.gz", "PoC archive"),
    ("poc", "exploit-0.py", "Model-authored exploit"),
    ("package", "libexpat1_2.4.8-1_amd64.deb", "Operator-approved package"),
    ("held_vms", "held-vms.json", "Held VM record"),
]

LLM_KINDS = (
    "llm_extract_prompt",
    "llm_extract_response",
    "llm_validate_prompt",
    "llm_validate_response",
    "llm_pocgen_prompt",
    "llm_pocgen_response",
    "llm_reasoning_response",
    "llm_extract.reasoning_response",
    "llm_validate.reasoning_response",
)


def _bundle_artifact(kind: str, name: str, **over: Any) -> dict[str, Any]:
    """A row as bundle.py hands it to the audit page.

    It pops `path` and keeps only the base name under `name`, so a fixture
    built like the job page's rows tests a shape the audit page never sees.
    """
    row = {
        "id": f"art-{name}",
        "attempt_id": "att-1",
        "kind": kind,
        "name": name,
        "sha256": "a" * 64,
        "bytes": 1234,
    }
    row.update(over)
    return row


def _render_job(artifacts: list[dict[str, Any]]) -> str:
    return _env().get_template("job.html").render(
        job=JOB,
        steps=[],
        validations=[],
        artifacts=artifacts,
        media={},
        commands={},
        plan=[],
        links={"cve_text": "", "cve_href": "", "poc_text": "", "poc_href": ""},
        csrf="tok",
    )


def _render_audit(
    llm: list[dict[str, Any]] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
) -> str:
    bundle = {
        "format": "xentry-bundle-1",
        "manifest_sha256": "b" * 64,
        "job": JOB,
        "steps": [],
        "broker_calls": [],
        "nonces": [],
        "artifacts": artifacts if artifacts is not None else [],
        "events": [],
        "validations": [
            {
                "validator_model": "deepseek-chat",
                "validator_prompt_hash": "c" * 64,
                "verdict": "reproduced",
                "authority": "runner_observed+llm_assessed",
                "reason_code": "nonce_observed",
                "runner_nonce_observed": 1,
                "null_actor_observed_nonce": 0,
            }
        ],
    }
    return _env().get_template("audit.html").render(
        bundle=bundle,
        llm=llm if llm is not None else [],
        proves=PROVES,
        not_proves=NOT_PROVES,
        csrf="tok",
    )


def _section(html: str, heading: str) -> str:
    """The one <section class="panel"> that carries this <h2>."""
    panels = re.split(r'(?=<section class="panel")', html)
    found = [p for p in panels if f"<h2>{heading}" in p]
    assert len(found) == 1, f"expected one {heading!r} panel, got {len(found)}"
    return found[0]


# ------------------------------------------------- 1: no blurb on model calls ---


def test_model_calls_card_renders_no_description() -> None:
    llm = [
        {
            "stage": "validate",
            "prompt": "QUESTION-MARKER",
            "response": "ANSWER-MARKER",
            "prompt_sha256": "d" * 64,
            "response_sha256": "e" * 64,
            "prompt_bytes": 15,
            "response_bytes": 13,
        },
        {
            "stage": "validate.reasoning",
            "prompt": "",
            "response": "THINKING-MARKER",
            "prompt_sha256": "",
            "response_sha256": "f" * 64,
            "prompt_bytes": 0,
            "response_bytes": 15,
        },
    ]
    html = _render_audit(llm)
    card = _section(html, "Model calls")
    # The prose is gone from the RENDERED page. It survives as a Jinja comment,
    # which is why this reads the render and not the file.
    assert "no tool calls to show" not in html
    assert "the model's own thinking" not in html
    assert "single request and a single reply" not in html
    assert "<p class=\"muted\">" not in card
    # ... and the card still does its job.
    assert "<h2>Model calls</h2>" in card
    assert 'id="stage-validate"' in card
    assert "QUESTION-MARKER" in card
    assert "ANSWER-MARKER" in card
    assert "<summary>Reasoning" in card
    assert "THINKING-MARKER" in card


def test_model_calls_card_keeps_its_no_transcript_line() -> None:
    card = _section(_render_audit([]), "Model calls")
    assert "No transcript recorded" in card


# ------------------------------- 2: criteria inside Validation, collapsed ---


def test_success_criteria_live_in_the_validation_card_closed() -> None:
    html = _render_audit()
    # No panel of its own any more.
    assert "<h2>Success criteria</h2>" not in html
    card = _section(html, "Validation")
    assert "<summary>Success criteria</summary>" in card
    assert PROVES[0] in card
    assert NOT_PROVES[0] in card
    # The claims are inside the <details>, and that <details> is closed.
    details = card[card.index("<details"): card.index("</details>")]
    opening = details[: details.index(">") + 1]
    assert "open" not in opening, opening
    assert PROVES[0] in details
    assert NOT_PROVES[0] in details
    # Nothing in the bundle's own validation row was lost to make room.
    assert "nonce_observed" in card
    assert "deepseek-chat" in card


def test_criteria_details_still_renders_the_empty_case() -> None:
    env = _env()
    html = env.get_template("audit.html").render(
        bundle={
            "format": "x",
            "manifest_sha256": "b" * 64,
            "job": JOB,
            "steps": [],
            "broker_calls": [],
            "nonces": [],
            "artifacts": [],
            "events": [],
            "validations": [],
        },
        llm=[],
        proves=[],
        not_proves=[],
        csrf="tok",
    )
    card = _section(html, "Validation")
    assert "No criteria recorded for this target." in card
    assert "No validation row." in card


# --------------------------------- 3: no llm rows in the evidence card ---


def test_evidence_card_drops_every_llm_row() -> None:
    artifacts = [_artifact(kind, f"llm/{kind}.txt") for kind in LLM_KINDS]
    artifacts.append(_artifact("evidence", "provision-commands.txt"))
    html = _render_job(artifacts)
    card = _section(html, "Evidence")
    for kind in LLM_KINDS:
        assert kind not in card, kind
    # A real kind added later with the same prefix goes too, without an edit.
    assert "llm_" not in card
    # ... and the non-llm row is still there.
    assert "Provision transcript" in card
    assert "provision-commands.txt" in card


def test_evidence_card_says_so_when_only_llm_rows_exist() -> None:
    card = _section(_render_job([_artifact("llm_extract_response", "llm/x.txt")]), "Evidence")
    assert "No recorded artifacts yet." in card
    assert "llm_extract_response" not in card


def test_evidence_card_empty_without_artifacts() -> None:
    card = _section(_render_job([]), "Evidence")
    assert "No recorded artifacts yet." in card


# --------------------------------- 4: rows named after what they are ---


def test_every_recorded_kind_gets_a_label_that_says_what_it_is() -> None:
    artifacts = [_artifact(kind, name) for kind, name, _label in RECORDED]
    card = _section(_render_job(artifacts), "Evidence")
    for kind, name, label in RECORDED:
        # A table cell now, not link text: the label describes the row and the
        # actions are buttons of their own.
        assert f">{label}</td>" in card, f"{kind}/{name} -> {label}"
        # The file name stays on the row, so the trail still names the bytes.
        assert f'<td class="mono muted">{name}</td>' in card, name
    # The bare kind is not the description of anything that has a label.
    for kind in ("evidence", "poc", "setup_script", "held_vms"):
        assert f">{kind}</td>" not in card, kind


def test_label_falls_back_to_the_kind_for_an_unknown_file() -> None:
    card = _section(_render_job([_artifact("evidence", "something-new.txt")]), "Evidence")
    # Not an invented description: the kind, plus the name that identifies it.
    assert ">Recorded evidence</td>" in card
    assert "something-new.txt" in card


def test_rows_keep_their_digest_size_and_download_links() -> None:
    artifact = _artifact("evidence", "cve.html")
    html = _render_job([artifact])
    card = _section(html, "Evidence")
    assert f"/api/jobs/{JOB['id']}/evidence/{artifact['id']}?view=download" in card
    assert "a" * 16 in card
    # Thousands separated and right-aligned, because a size is a quantity:
    # 35,297 B should line up under 1,200 B on the digits.
    assert '<td class="num">1,234 B</td>' in card
    # Both actions are BUTTONS, not link text - they were easy to miss and
    # awkward to hit at link size, which is what prompted this.
    assert card.count('class="button secondary"') == 2
    assert ">View</a>" in card
    assert ">Download</a>" in card
    # And Download names the file it saves, rather than the artifact id.
    assert 'download="cve.html"' in card
    # No absolute host path reaches the page, only the base name.
    assert "/var/lib/xentry" not in html


def test_rendered_view_offered_only_where_media_says_html() -> None:
    artifact = _artifact("evidence", "cve.html")
    card = _section(_render_job([artifact]), "Evidence")
    assert "?view=render" not in card
    html = _env().get_template("job.html").render(
        job=JOB,
        steps=[],
        validations=[],
        artifacts=[artifact],
        media={artifact["id"]: "html"},
        commands={},
        plan=[],
        links={"cve_text": "", "cve_href": "", "poc_text": "", "poc_href": ""},
        csrf="tok",
    )
    assert "?view=render" in _section(html, "Evidence")


def test_a_row_without_a_path_still_renders() -> None:
    """A row from before path was selected, or any row missing it."""
    row = _artifact("evidence", "cve.html")
    row.pop("path")
    card = _section(_render_job([row]), "Evidence")
    assert ">Recorded evidence</td>" in card
    # With no path there is no file name, so the kind fills that cell rather
    # than leaving it blank - an empty column reads as a rendering fault.
    assert '<td class="mono muted">evidence</td>' in card


# ------------------------------------------------- the two pages together ---


def test_the_live_app_renders_both_pages_with_real_rows(tmp_path: Path) -> None:
    """End to end through the app, so the context keys are the real ones.

    The template tests above build their own context; this one proves the
    handlers still supply what the templates now read - the artifact path in
    particular, which list_artifacts had to start returning.
    """
    import hashlib

    from fastapi.testclient import TestClient

    from xentry.db import init_db
    from xentry.jobstore import create_job, record_artifact, set_plan
    from xentry.web.app import build_app

    db_path = tmp_path / "data" / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
        conn,
        data_dir=tmp_path / "data",
        poc_url="https://github.com/o/r",
        cve_url="https://example.com/cve",
    )
    set_plan(
        conn,
        job_id,
        cve_id="CVE-2026-109618",
        target_id="php2shell",
        bundle_sha256="d" * 64,
    )
    llm_dir = Path(attempt_dir) / "llm"
    llm_dir.mkdir(parents=True, exist_ok=True)
    body = b"PROMPT-MARKER"
    (llm_dir / "validate.prompt.txt").write_bytes(body)
    record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="llm_validate_prompt",
        path=llm_dir / "validate.prompt.txt",
        sha256=hashlib.sha256(body).hexdigest(),
        size=len(body),
    )
    trace = b"+ apt-get install -y php\n"
    (Path(attempt_dir) / "provision-commands.txt").write_bytes(trace)
    record_artifact(
        conn,
        job_id=job_id,
        attempt_id=attempt_id,
        kind="evidence",
        path=Path(attempt_dir) / "provision-commands.txt",
        sha256=hashlib.sha256(trace).hexdigest(),
        size=len(trace),
    )
    conn.commit()
    conn.close()

    app = build_app(
        data_dir=tmp_path / "data",
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
    )
    with TestClient(app) as client:
        page = client.get(f"/jobs/{job_id}")
        assert page.status_code == 200
        card = _section(page.text, "Evidence")
        assert "Provision transcript" in card
        assert "llm_validate_prompt" not in card
        assert str(tmp_path) not in page.text

        audit = client.get(f"/jobs/{job_id}/audit")
        assert audit.status_code == 200
        assert "no tool calls to show" not in audit.text
        assert "<summary>Success criteria</summary>" in _section(audit.text, "Validation")
        assert "PROMPT-MARKER" in audit.text


def test_a_finished_but_held_job_reports_held(tmp_path) -> None:
    """A held job's outcome is NULL, so it used to report "running".

    The runner finishes every step, keeps the VMs up and waits for a release.
    Until that release the outcome is unrecorded, so the page said "running"
    about a job where nothing was progressing - and the only hint that it was
    holding the host's one job slot was the Running VMs page.

    The flag is popped from the row rather than returned, so there is one
    source of truth about the state and not two.
    """
    import sqlite3

    from xentry import db
    from xentry.jobstore import HELD_EXISTS, create_job, get_job, list_jobs

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.migrate(conn)

    job_id, attempt, _ = create_job(
        conn, data_dir=tmp_path, poc_url="https://example.invalid/p",
        cve_url="https://example.invalid/c",
    )
    conn.execute("UPDATE jobs SET started_at=? WHERE id=?",
                 ("2026-11-17T03:00:00+00:00", job_id))
    conn.commit()

    # Running: started, no outcome, no held record.
    assert get_job(conn, job_id)["state"] == "running"

    conn.execute(
        "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
        "VALUES (?,?,?,?,?,?,?)",
        ("h" * 32, job_id, attempt, "held_vms", "/held-vms.json", "0" * 64, 2),
    )
    conn.commit()

    # Held: every step done, VMs still up, outcome not yet recorded.
    job = get_job(conn, job_id)
    assert job["state"] == "held"
    assert "has_held" not in job, "the flag must not leak into the API"
    assert [j["state"] for j in list_jobs(conn)] == ["held"]

    # Released: the outcome is recorded and the state follows it, even though
    # the held_vms artifact remains as evidence of what was kept.
    conn.execute("UPDATE jobs SET outcome='completed' WHERE id=?", (job_id,))
    conn.commit()
    assert get_job(conn, job_id)["state"] == "completed"

    # The subquery is shared by both readers, so they cannot disagree.
    assert "held_vms" in HELD_EXISTS


def test_the_held_pill_is_styled_and_js_knows_it_is_not_an_outcome() -> None:
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "src/xentry/web/static"
    css = (root / "style.css").read_text()
    js = (root / "app.js").read_text()

    assert '.pill[data-status="held"]' in css
    # Not in the set of states that end a job: the teardown watcher must keep
    # polling while a job is held.
    assert 'const FINISHED = new Set(["completed", "failed", "cancelled", "interrupted"])' in js
    code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
    assert '"held"' not in code.split("const FINISHED")[1].split("]")[0]


def test_only_a_bracketed_check_id_offers_its_transcript() -> None:
    """A path contains 32 hex characters too, and it is the JOB id.

    The net-define failure rendered as

        ('net-define', '/var/lib/xentry/jobs/7132a1d9...928/network.xml')
        show what the model answered (failed: no transcript for that check)

    because the scan matched any 32 hex characters and found the job id in the
    path. A refusal names its check in brackets - "[c7b13dfb...]" - and that
    is the only shape that means "a transcript exists under this id".

    The offer also withdraws itself on a 404 instead of inviting another
    click, and the label is restored from what it was before the click rather
    than appended to, which is what produced "(failed: ...) (failed: ...)".
    """
    import pathlib
    import re

    js = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src/xentry/web/static/app.js"
    ).read_text()
    code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))

    in_text = re.search(r"const CHECK_IN_TEXT = /(.+)/;", code).group(1)
    scan = re.compile(in_text.replace("\\\\", "\\"))
    # The failure that caused this.
    path_failure = (
        "('net-define', '/var/lib/xentry/jobs/"
        "7132a1d9835b4b268732247b72f73928/network.xml')"
    )
    assert scan.search(path_failure) is None, "a job id in a path must not match"
    # A real refusal still does.
    real = "validator_error [c7b13dfbbc184bf2b436ff1ff7e208b1]: invalid JSON"
    found = scan.search(real)
    assert found and found.group(1) == "c7b13dfbbc184bf2b436ff1ff7e208b1"
    # And an unrelated error offers nothing.
    assert scan.search("E: Unable to locate package apache2") is None

    # The explicit attribute still accepts a bare id, since the server hands
    # that one over deliberately.
    bare = re.compile(re.search(r"const CHECK_ID = /(.+)/;", code).group(1))
    assert bare.match("262eb4d482674cfcaad13524ee8a822f")
    assert not bare.match("/var/lib/x/7132a1d9835b4b268732247b72f73928/y")

    # A 404 removes the button rather than relabelling it forever.
    assert "button.remove();" in code
    assert "/no transcript/i.test" in code
    assert "(failed: ${error.message})" not in code


def test_each_caret_carries_its_length() -> None:
    """A closed caret should say whether opening it is worth it.

    Reasoning already showed its byte count beside the title; Question and
    Response did not, so the only sizes on the page were in the facts list
    above them - which is not where you are looking when deciding whether to
    expand a transcript.
    """
    html = _render_audit([
        {
            "stage": "extract",
            "prompt": "q" * 10,
            "response": "r" * 20,
            "prompt_sha256": "a" * 64,
            "response_sha256": "b" * 64,
            "prompt_bytes": 10,
            "response_bytes": 20,
        },
        {
            "stage": "extract.reasoning",
            "prompt": "",
            "response": "thinking",
            "prompt_sha256": "",
            "response_sha256": "c" * 64,
            "prompt_bytes": 0,
            "response_bytes": 8,
        },
    ])
    card = _section(html, "Model calls")
    assert '<summary>Question <span class="muted">· 10 bytes</span></summary>' in card
    assert '<summary>Response <span class="muted">· 20 bytes</span></summary>' in card
    # Reasoning keeps the form the other two now copy.
    assert "Reasoning" in card and "· 8 bytes" in card


def test_the_audit_artifacts_card_is_the_same_table() -> None:
    """The one card that lists EVERY artifact was the least legible.

    It showed a kind, a truncated hash, a size and the word "download". It now
    uses the same macro as the job page's Evidence card, so a new artifact
    kind is described once and both cards cannot drift apart again.
    """
    # THE BUNDLE'S OWN SHAPE, not the job page's. bundle.py pops `path` and
    # stores the base name as `name`; a fixture carrying `path` here passed
    # while the live page showed "Recorded evidence" on every row, because the
    # macro found no file name and fell back to the kind.
    html = _render_audit(artifacts=[
        _bundle_artifact("evidence", "cve.html"),
        _bundle_artifact("llm_extract_prompt", "extract.prompt.txt"),
    ])
    card = _section(html, "Artifacts")
    assert 'table class="evidence"' in card
    assert ">View</a>" in card
    assert ">Download</a>" in card
    # Unlike the job page it hides nothing: llm_* rows are the point of the
    # audit bundle, and the job page drops them only because this page has
    # them with their hashes and reasoning.
    assert "extract.prompt.txt" in card
    # And a real description, not the kind: this is what the live page got
    # wrong while the fixture said otherwise.
    assert ">Advisory record</td>" in card
    assert ">Recorded evidence</td>" not in card
    # And it claims no format, because this page has no sniffed media map -
    # a label must not guess what the bytes are.
    assert "(JSON)" not in card
    assert "(HTML)" not in card
    # A Rendered button would 409 here for the same reason.
    assert "?view=render" not in card


def test_the_action_buttons_do_not_set_the_row_height() -> None:
    """They did, and that is why the rows read as too tall.

    body is `font: 15px/1.5`, and line-height inherits as a NUMBER - so a
    12px button took 12 x 1.5 = 18px of line box, plus 4+4 padding and 2px of
    border: a 28px control inside a cell with 7px padding, for a 42px row.

    An explicit line-height takes the control to 1 + 16 + 1 + 2 = 20px, below
    the 22.5px line box of the 15px label beside it, so the text sets the row
    height instead. The arithmetic is asserted rather than described, because
    a later edit that drops the explicit line-height reinflates the row
    silently.
    """
    import pathlib
    import re

    css = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src/xentry/web/static/style.css"
    ).read_text()

    block = css[css.index("table.evidence td.actions .button {") :]
    block = block[: block.index("}")]

    def value(prop: str) -> str:
        found = re.search(rf"{prop}:\s*([^;]+);", block)
        assert found, f"{prop} is not set on the action buttons"
        return found.group(1).strip()

    # An explicit line-height in px, not inherited as a multiplier.
    line_height = value("line-height")
    assert line_height.endswith("px"), line_height
    pad_y = int(value("padding").split()[0].removesuffix("px"))
    height = int(line_height.removesuffix("px")) + 2 * pad_y + 2  # + 1px borders

    # The cell's own line box, from the body font and the cell padding.
    body = css[css.index("body {") :]
    body = body[: body.index("}")]
    font = re.search(r"font:\s*(\d+)px/([\d.]+)", body)
    assert font, "the body font shorthand changed shape"
    text_box = float(font.group(1)) * float(font.group(2))

    assert height < text_box, (
        f"the buttons are {height}px against a {text_box}px line box, so they"
        " still set the row height"
    )
    # And a pill, which is what makes a short control look deliberate.
    assert value("border-radius") in ("999px", "9999px")


def test_a_label_cannot_wrap_and_the_buttons_sit_on_the_centre_line() -> None:
    """Both of these made rows uneven, for different reasons.

    A label that wraps is taller than its neighbours, so the labels are short
    and the column is pinned to one line with an ellipsis as a backstop.

    The pills looked bottom-aligned because `.button` is inline-flex, and an
    inline-level box aligns on ITS OWN baseline - the baseline of the text
    inside the pill. Against a 22.5px line box that puts a 20px control low in
    the row, however much vertical-align the CELL carries. The alignment has
    to be on the box itself.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    css = (root / "src/xentry/web/static/style.css").read_text()

    button = css[css.index("table.evidence td.actions .button {") :]
    button = button[: button.index("}")]
    assert "vertical-align: middle" in button

    what = css[css.index("table.evidence td.what {") :]
    what = what[: what.index("}")]
    for prop in ("white-space: nowrap", "overflow: hidden", "text-overflow: ellipsis"):
        assert prop in what, prop

    # Every label must fit the column it is pinned to, or the ellipsis hides
    # something a reader needed.
    macro = (root / "src/xentry/web/templates/_evidence.html").read_text()
    labels = re.findall(r'^\s*"[^"]+":\s*"([^"]+)",\s*$', macro, re.MULTILINE)
    assert labels, "the label map changed shape"
    budget = int(re.search(r"max-width:\s*(\d+)ch", what).group(1))
    # Allow for the sniffed " (JSON)" suffix the job page appends.
    too_long = [l for l in labels if len(l) + len(" (JSON)") > budget]
    assert not too_long, f"longer than {budget}ch with a format suffix: {too_long}"
