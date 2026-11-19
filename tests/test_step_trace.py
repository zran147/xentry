"""The per-command trace of a guest step, and how the web app serves it."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from broker.runtime import GUEST_TRACE_DIR, GUEST_TRACE_REL, step_command
from xentry.db import MIGRATIONS
from xentry.runner import JobRunner, _JobLocal
from xentry.web.app import _provision_plan, _step_commands

# Read from disk, not written down: a new migration used to break tests
# that only wanted "the newest one".
LATEST_MIGRATION = max(int(p.name.split("_", 1)[0]) for p in MIGRATIONS.glob("*.sql"))


def test_command_enables_the_trace_and_quotes_arguments() -> None:
    command = step_command(
        "/var/lib/xentry/steps/setup-php.sh", ["http://m/x", "a b"], "setup-php", True
    )
    assert "BASH_XTRACEFD=9" in command
    assert "bash -x" in command
    assert command.endswith(f"9>{GUEST_TRACE_DIR}/setup-php.trace")
    assert "'a b'" in command


def test_trace_path_is_reachable_by_copy_out() -> None:
    # copy_out joins a relative guest path onto /home/xentry-guest, so the
    # trace has to sit under that directory or it cannot be read back.
    assert GUEST_TRACE_DIR == f"/home/xentry-guest/{GUEST_TRACE_REL}"


def _run(script_body: str, tmp_path: Path) -> tuple[subprocess.CompletedProcess[str], Path]:
    script = tmp_path / "step.sh"
    script.write_text(script_body, encoding="utf-8")
    home = tmp_path / "home"
    # The broker's root prep session creates this and hands it to the step's
    # user; the command itself no longer does, which is the fix for the
    # readiness regression.
    home.mkdir(exist_ok=True)
    command = step_command(str(script), ["one", "two"], "a-step", True).replace(
        GUEST_TRACE_DIR, str(home)
    )
    done = subprocess.run(["bash", "-c", command], capture_output=True, text=True, check=False)
    return done, home / "a-step.trace"


def test_trace_does_not_disturb_stdout_stderr_or_exit_code(tmp_path: Path) -> None:
    # The failure message the app reports comes from stderr, so the trace must
    # not leak into it.
    done, trace = _run(
        'set -euo pipefail\necho "to stdout"\necho "to stderr" >&2\nexit 7\n', tmp_path
    )
    assert done.returncode == 7
    assert done.stdout.strip() == "to stdout"
    assert done.stderr.strip() == "to stderr"
    lines = trace.read_text(encoding="utf-8").splitlines()
    assert "+ echo 'to stdout'" in lines
    assert "+ exit 7" in lines


def test_trace_records_each_command_in_order(tmp_path: Path) -> None:
    done, trace = _run("set -eu\ntrue\nmkdir -p ./d\nrmdir ./d\n", tmp_path)
    assert done.returncode == 0
    traced = [line.lstrip("+ ") for line in trace.read_text(encoding="utf-8").splitlines()]
    assert traced == ["set -eu", "true", "mkdir -p ./d", "rmdir ./d"]


def test_step_arguments_reach_the_script(tmp_path: Path) -> None:
    done, _ = _run('set -eu\necho "$1-$2"\n', tmp_path)
    assert done.stdout.strip() == "one-two"


# ----------------------------------------------------------------- app ---


def test_provision_commands_strips_markers_and_blanks(tmp_path: Path) -> None:
    (tmp_path / "provision-commands.txt").write_text(
        "+ set -euo pipefail\n\n++ nested call\n+ make -j4\n   \n", encoding="utf-8"
    )
    assert _step_commands({"attempt_dir": str(tmp_path)}) == {
        "provision": ["set -euo pipefail", "nested call", "make -j4"]
    }


def test_provision_commands_returns_the_tail_only(tmp_path: Path) -> None:
    (tmp_path / "provision-commands.txt").write_text(
        "".join(f"+ step {n}\n" for n in range(500)), encoding="utf-8"
    )
    commands = _step_commands({"attempt_dir": str(tmp_path)}, limit=10)
    assert commands["provision"] == [f"step {n}" for n in range(490, 500)]


def test_provision_commands_is_empty_when_absent(tmp_path: Path) -> None:
    assert _step_commands({"attempt_dir": str(tmp_path)}) == {}
    assert _step_commands({}) == {}


# ----------------------------------------------------------- collection ---


class StubClient:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
        self.calls.append((verb, dict(params)))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _collect(client: object, sink: Path, secrets: list[str] | None = None) -> None:
    runner = JobRunner.__new__(JobRunner)
    # Per-thread now, so a second worker cannot see this job's nonces. The
    # collected trace is redacted on the way out, because the actor steps run
    # with a nonce on the command line.
    runner._job = _JobLocal()
    runner._job.secrets = secrets or []
    runner._collect_step_trace(client, "vm-1", "a-step", sink)


def test_collect_writes_the_trace_and_asks_for_the_right_path(tmp_path: Path) -> None:
    guest = tmp_path / "guest.trace"
    guest.write_text("+ make -j4\n", encoding="utf-8")
    client = StubClient({"path": str(guest)})
    sink = tmp_path / "provision-commands.txt"
    _collect(client, sink)
    assert sink.read_text(encoding="utf-8") == "+ make -j4\n"
    assert client.calls == [
        ("copy_out", {"vm_id": "vm-1", "guest_path": f"{GUEST_TRACE_REL}/a-step.trace"})
    ]


def test_collect_is_silent_when_the_broker_refuses(tmp_path: Path) -> None:
    # A step that failed before writing a trace must not be turned into a
    # harness error by the collection.
    sink = tmp_path / "provision-commands.txt"
    _collect(StubClient(RuntimeError("no such file")), sink)
    assert not sink.exists()


def test_collect_is_silent_when_the_file_is_gone(tmp_path: Path) -> None:
    sink = tmp_path / "provision-commands.txt"
    _collect(StubClient({"path": str(tmp_path / "absent.trace")}), sink)
    assert not sink.exists()


# ------------------------------------------------------------------ plan ---

SCRIPT = """#!/usr/bin/env bash
# a comment
set -euo pipefail

mirror_url="${1:?mirror_url}"
curl -fsS --retry 3 \\
  "$mirror_url/artifacts/x" \\
  -o /tmp/x
cat > /etc/conf <<'INI'
display_errors = On
# not a command: heredoc body
INI
make -j4
"""


def _plan(tmp_path: Path, text: str = SCRIPT) -> list[str]:
    (tmp_path / "setup.sh").write_text(text, encoding="utf-8")
    return _provision_plan({"attempt_dir": str(tmp_path)})


def test_plan_joins_continuations(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    joined = [c for c in plan if c.startswith("curl")]
    assert joined == ['curl -fsS --retry 3 "$mirror_url/artifacts/x" -o /tmp/x']


def test_plan_skips_comments_and_blanks(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    assert not any(c.startswith("#") for c in plan)
    assert "" not in plan


def test_plan_skips_heredoc_bodies(tmp_path: Path) -> None:
    # A heredoc body is data the script writes out, not a command.
    plan = _plan(tmp_path)
    assert "display_errors = On" not in plan
    assert "# not a command: heredoc body" not in plan
    assert "INI" not in plan
    assert plan[-1] == "make -j4"


def test_plan_keeps_source_order(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    assert plan[0] == "set -euo pipefail"
    assert plan.index("make -j4") == len(plan) - 1


def test_plan_is_empty_without_a_script(tmp_path: Path) -> None:
    assert _provision_plan({"attempt_dir": str(tmp_path)}) == []
    assert _provision_plan({}) == []


def test_plan_matches_the_real_php_script(tmp_path: Path) -> None:
    # The shipped script must parse into something usable, not one blob.
    repo = Path(__file__).resolve().parents[1]
    (tmp_path / "setup.sh").write_bytes((repo / "targets" / "php2shell" / "setup.sh").read_bytes())
    plan = _provision_plan({"attempt_dir": str(tmp_path)})
    assert len(plan) > 20
    assert plan[0] == "set -euo pipefail"
    assert any(c.startswith("./configure") for c in plan)
    assert any(c.startswith("make -j") for c in plan)
    # the zz-poc.ini heredoc body must not appear as a command
    assert not any(c.startswith("display_errors") for c in plan)


# -------------------------------------------------------------- copy_out ---


def test_copy_out_result_is_readable_by_the_app(tmp_path: Path, monkeypatch) -> None:
    """The broker unit's UMask=0077 masks mkdir's mode, so modes are explicit.

    Without this the trace lands 0700/0600 root-owned and the app, which is the
    only consumer of copy_out, cannot read it.
    """
    import stat as stat_mod

    from broker import runtime as rt

    class FakeSSH:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def wait(self, timeout: float) -> None:
            pass

        def get(self, remote: str, local: Path) -> None:
            Path(local).write_text("+ make -j4\n", encoding="utf-8")

    monkeypatch.setattr(rt, "SSHTransport", FakeSSH)
    monkeypatch.setattr(
        rt.BrokerRuntime,
        "_vm_state",
        lambda self, vm_id: {"job_id": "job-1", "guest_ip": "10.0.0.10", "role": "target"},
    )
    broker = rt.BrokerRuntime.__new__(rt.BrokerRuntime)
    broker.jobs_root = tmp_path / "jobs"

    result = broker.copy_out("vm-1", f"{GUEST_TRACE_REL}/setup-php.trace")
    local = Path(str(result["path"]))
    assert local.read_text(encoding="utf-8") == "+ make -j4\n"
    assert stat_mod.S_IMODE(local.stat().st_mode) == 0o640
    assert stat_mod.S_IMODE(local.parent.stat().st_mode) == 0o750
    assert stat_mod.S_IMODE((tmp_path / "jobs" / "job-1" / "out").stat().st_mode) == 0o750


# ------------------------------------------------------------- template ---

JOB = {
    "id": "abcdef0123456789",
    "target_id": "php2shell",
    "cve_id": "CVE-2026-109618",
    "state": "running",
    "verdict": None,
    "authority": None,
    "reason_code": None,
    "cleanup_state": "pending",
    "created_at": "2026-11-12T07:00:00+00:00",
    "started_at": "2026-11-12T07:00:05+00:00",
    "finished_at": None,
    "outcome": None,
    "poc_url": "https://github.com/o/r",
}
LINKS = {"cve_text": "", "cve_href": "", "poc_text": "", "poc_href": ""}


def _render(**context: object) -> str:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    repo = Path(__file__).resolve().parents[1]
    env = Environment(
        loader=FileSystemLoader(str(repo / "src" / "xentry" / "web" / "templates")),
        undefined=StrictUndefined,
        autoescape=True,
    )
    base: dict[str, object] = {
        "job": JOB,
        "steps": [],
        "validations": [],
        "artifacts": [],
        "plan": [],
        "links": LINKS,
        "csrf": "tok",
        "held": [],
        "asset_v": lambda: "1",
        "media": {},
        "commands": {},
    }
    base.update(context)
    return env.get_template("job.html").render(**base)


def test_job_page_hangs_the_plan_off_the_provision_row() -> None:
    steps = [
        {
            "seq": 5,
            "name": "create_target",
            "step_id": None,
            "state": "passed",
            "reason_code": None,
            "started_at": "t",
            "finished_at": "t",
        },
        {
            "seq": 6,
            "name": "provision",
            "step_id": "setup-php",
            "state": "running",
            "reason_code": None,
            "started_at": "t",
            "finished_at": None,
        },
    ]
    html = _render(steps=steps, plan=["set -eu", "make -j4"])
    assert 'data-step="provision"' in html
    assert 'class="step-detail" data-detail="cmd:provision"' in html
    assert "2 commands" in html
    assert "not yet run" in html
    assert 'class="cmdblock"' in html
    assert '<span class="name">setup-php.sh</span>' in html
    assert 'class="cmdlog planned"' in html
    # The detail row must follow the provision row, not precede it.
    assert html.index('data-step="provision"') < html.index('data-detail="cmd:provision"')
    # No standalone region any more.
    assert 'id="provision-log"' not in html


def test_job_page_shows_the_trace_once_it_exists() -> None:
    steps = [
        {
            "seq": 6,
            "name": "provision",
            "step_id": "setup-php",
            "state": "passed",
            "reason_code": None,
            "started_at": "t",
            "finished_at": "t",
        },
    ]
    html = _render(steps=steps, commands={"provision": ["+ set -eu"]}, plan=["set -eu", "ignored"])
    assert "1 command " in html
    assert "not yet run" not in html
    assert 'class="cmdlog"' in html
    assert "planned" not in html
    assert "ignored" not in html


def test_job_page_omits_the_detail_row_without_commands() -> None:
    steps = [
        {
            "seq": 6,
            "name": "provision",
            "step_id": "setup-php",
            "state": "running",
            "reason_code": None,
            "started_at": "t",
            "finished_at": None,
        },
    ]
    html = _render(steps=steps)
    assert "step-detail" not in html


def test_job_page_renders_without_a_provision_step() -> None:
    steps = [
        {
            "seq": 1,
            "name": "fetch",
            "step_id": None,
            "state": "passed",
            "reason_code": None,
            "started_at": "t",
            "finished_at": "t",
        },
    ]
    html = _render(steps=steps, plan=["set -eu"])
    assert "step-detail" not in html
    assert 'data-step="fetch"' in html


# ---------------------------------------------------------- asset version ---


def test_asset_version_follows_the_files(tmp_path: Path, monkeypatch) -> None:
    """A stale ?v= served a cached script after a deploy; this is the guard.

    From the CONTENT now, not from mtimes, which had two holes: the file list
    was hand-written, so a third asset was invisible to the key, and
    int(st_mtime) has one-second resolution, so two writes in the same second
    shared one. With Cache-Control immutable on /static this string is the
    only thing that expires a cached asset, so it has to be right.
    """
    import os

    from xentry.web import app as web

    static = tmp_path / "static"
    static.mkdir()
    (static / "app.js").write_text("// one", encoding="utf-8")
    (static / "style.css").write_text("/* one */", encoding="utf-8")
    monkeypatch.setattr(web, "STATIC", static)
    first = web.asset_version()

    # A redeploy changes one file; the key moves with it.
    (static / "app.js").write_text("// two", encoding="utf-8")
    second = web.asset_version()
    assert second != first

    # The same bytes written again, in the same second, keep the same key -
    # and an mtime key would have changed here for no reason.
    os.utime(static / "app.js", None)
    assert web.asset_version() == second

    # Touching a file without changing it does not move the key either; only
    # content does.
    os.utime(static / "style.css", (0, 1))
    assert web.asset_version() == second

    # A THIRD asset moves it, which the hand-written list could never see.
    (static / "chart.js").write_text("// chart", encoding="utf-8")
    third = web.asset_version()
    assert third != second

    # And a change in that third file alone still moves it.
    (static / "chart.js").write_text("// chart two", encoding="utf-8")
    assert web.asset_version() != third


def test_asset_version_survives_missing_files(tmp_path: Path, monkeypatch) -> None:
    from xentry.web import app as web

    monkeypatch.setattr(web, "STATIC", tmp_path / "absent")
    # A digest of nothing, not a crash: the page still renders.
    assert len(web.asset_version()) == 16


def test_base_template_uses_the_derived_version() -> None:
    repo = Path(__file__).resolve().parents[1]
    base = (repo / "src" / "xentry" / "web" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "asset_v()" in base
    # No hand-maintained number left to forget.
    assert "?v=6" not in base


def test_command_block_scrolls_and_is_not_italic() -> None:
    """Guards two requirements this environment cannot verify by rendering.

    Nothing here draws the page, so these assert the rules are present, not
    that they lay out correctly. They exist because both were asked for
    explicitly: a visible scrollbar instead of content running off the edge,
    and no italics on code.
    """
    repo = Path(__file__).resolve().parents[1]
    css = (repo / "src" / "xentry" / "web" / "static" / "style.css").read_text(encoding="utf-8")
    cell = css[css.index("tr.step-detail > td") : css.index(".cmdblock {")]
    block = css[css.index(".cmdblock {") :]

    assert "font-style: italic" not in block
    # Without this the cell grows to fit the longest line and the whole table
    # overflows instead of the block scrolling.
    assert "max-width: 0" in cell
    assert "overflow: auto" in block
    assert "min-width: 0" in block
    # An always-visible bar, not a fading overlay.
    assert "scrollbar-width: thin" in block
    assert "::-webkit-scrollbar" in block


def test_an_untraced_step_runs_exactly_as_it_did_before() -> None:
    """The regression guard.

    Tracing every step put a root-owned directory in the actor's home, and the
    next step running as xentry-guest could not create its trace file there, so
    the redirect failed and the script never ran - every job died at readiness
    with target_unhealthy. Only the step whose trace is collected asks for one;
    every other command has to be byte-identical to the untraced form.
    """
    plain = step_command("/var/lib/xentry/steps/readiness-php.sh", [], "readiness-php")
    assert plain == "bash /var/lib/xentry/steps/readiness-php.sh"
    assert "BASH_XTRACEFD" not in plain
    assert "9>" not in plain
    assert "mkdir" not in plain
    assert GUEST_TRACE_DIR not in plain


def test_an_untraced_step_still_gets_its_arguments() -> None:
    plain = step_command("/s.sh", ["http://m/x", "a b"], "a-step")
    assert plain == "bash /s.sh http://m/x 'a b'"


def test_a_traced_step_redirects_to_one_quoted_path() -> None:
    traced = step_command("/s.sh", [], "a-step", True)
    assert traced.endswith(f" 9>{GUEST_TRACE_DIR}/a-step.trace")
    # The path has to be a single shell word, not two adjacent quoted ones.
    assert traced.count("9>") == 1
    assert "'" not in traced.split("9>")[1]


def test_the_trace_directory_is_not_created_by_the_step_itself() -> None:
    # It is prepared by the broker's root session and handed to the step's
    # user; created by the step, a root step would lock out every later one.
    traced = step_command("/s.sh", [], "a-step", True)
    assert "mkdir" not in traced
    assert "install -d" not in traced


# ------------------------------------------------------------- evidence ---

NVD_JSON = b'{"resultsPerPage":1,"vulnerabilities":[]}'
NVD_HTML = b'<!doctype html>\n<html lang="en"><head><title>NVD</title></head></html>'
TRACE_TXT = b"+ set -euo pipefail\n+ make -j4\n"


def test_media_is_classified_by_content_not_name(tmp_path: Path) -> None:
    from xentry.web.app import evidence_media

    # The CVE artifact is still written as cve.html but now holds JSON.
    as_html = tmp_path / "cve.html"
    as_html.write_bytes(NVD_JSON)
    assert evidence_media(as_html) == "json"

    real_html = tmp_path / "page.html"
    real_html.write_bytes(NVD_HTML)
    assert evidence_media(real_html) == "html"

    text = tmp_path / "provision-commands.txt"
    text.write_bytes(TRACE_TXT)
    assert evidence_media(text) == "text"

    assert evidence_media(tmp_path / "absent") == "text"


class _NoRunner:
    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


def _evidence_client(tmp_path: Path, content: bytes, name: str):
    from starlette.testclient import TestClient

    from xentry.db import init_db
    from xentry.web.app import build_app

    data = tmp_path / "data"
    data.mkdir()
    db_path = data / "xentry.db"
    conn = init_db(db_path)
    artifact = tmp_path / name
    artifact.write_bytes(content)
    conn.execute(
        "INSERT INTO jobs(id, target_id, poc_url, created_at, attempt_dir) VALUES (?,?,?,?,?)",
        ("job-1", "php2shell", "https://example.com/poc", "now", str(tmp_path)),
    )
    conn.execute(
        "INSERT INTO attempts(id, job_id, attempt_no, attempt_dir, started_at) VALUES (?,?,?,?,?)",
        ("att-1", "job-1", 0, str(tmp_path), "now"),
    )
    conn.execute(
        "INSERT INTO artifacts(id, job_id, attempt_id, kind, path, sha256, bytes) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            "art-1",
            "job-1",
            "att-1",
            "evidence",
            str(artifact),
            hashlib.sha256(content).hexdigest(),
            len(content),
        ),
    )
    conn.commit()
    conn.close()
    app = build_app(
        data_dir=data,
        db_path=db_path,
        broker_socket=tmp_path / "broker.sock",
        runner=_NoRunner(),  # type: ignore[arg-type]
    )
    return TestClient(app)


URL = "/api/jobs/job-1/evidence/art-1"


def test_json_evidence_opens_in_the_browser(tmp_path: Path) -> None:
    with _evidence_client(tmp_path, NVD_JSON, "cve.html") as client:
        response = client.get(URL)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "attachment" not in response.headers.get("content-disposition", "")
    assert response.content == NVD_JSON


def test_text_evidence_opens_as_plain_text(tmp_path: Path) -> None:
    with _evidence_client(tmp_path, TRACE_TXT, "provision-commands.txt") as client:
        response = client.get(URL)
    assert response.headers["content-type"].startswith("text/plain")
    assert "attachment" not in response.headers.get("content-disposition", "")


def test_html_evidence_is_shown_as_source_by_default(tmp_path: Path) -> None:
    # Fetched HTML is never executed unless it is explicitly rendered.
    with _evidence_client(tmp_path, NVD_HTML, "cve.html") as client:
        response = client.get(URL)
    assert response.headers["content-type"].startswith("text/plain")


def test_html_evidence_renders_sandboxed(tmp_path: Path) -> None:
    with _evidence_client(tmp_path, NVD_HTML, "cve.html") as client:
        response = client.get(URL, params={"view": "render"})
    assert response.headers["content-type"].startswith("text/html")
    # sandbox with no allow- token: no scripts, opaque origin, so the document
    # cannot reach this app's cookies.
    assert response.headers["content-security-policy"] == "sandbox"
    assert "attachment" not in response.headers.get("content-disposition", "")


def test_only_html_can_be_rendered(tmp_path: Path) -> None:
    with _evidence_client(tmp_path, NVD_JSON, "cve.html") as client:
        response = client.get(URL, params={"view": "render"})
    assert response.status_code == 409


def test_download_still_works(tmp_path: Path) -> None:
    with _evidence_client(tmp_path, NVD_JSON, "cve.html") as client:
        response = client.get(URL, params={"view": "download"})
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["content-type"] == "application/octet-stream"


def test_other_responses_keep_the_strict_policy(tmp_path: Path) -> None:
    # setdefault must not have loosened the policy everywhere else.
    with _evidence_client(tmp_path, NVD_JSON, "cve.html") as client:
        response = client.get("/")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "sandbox" not in response.headers["content-security-policy"]


def test_a_tampered_artifact_is_still_refused(tmp_path: Path) -> None:
    with _evidence_client(tmp_path, NVD_JSON, "cve.html") as client:
        (tmp_path / "cve.html").write_bytes(b'{"tampered":true}')
        response = client.get(URL)
    assert response.status_code == 409


# ------------------------------------------------------- citation quotes ---


def test_a_multiline_quote_from_json_evidence_verifies() -> None:
    """The reason job 8f6bf40c7ebc failed.

    The CVE artifact is NVD's JSON now, which stores a multi-line description
    with escaped newlines. The model quotes the prose it decoded, so a raw
    substring match can never find it.
    """
    import json as json_mod

    from xentry.extract import _quote_present

    description = "line one\nline two\nline three"
    artifact = json_mod.dumps(
        {"vulnerabilities": [{"cve": {"descriptions": [{"value": description}]}}]}
    )
    assert description not in artifact
    assert _quote_present(description, artifact)


def test_a_quote_that_is_not_in_the_json_is_still_refused() -> None:
    import json as json_mod

    from xentry.extract import _quote_present

    artifact = json_mod.dumps({"descriptions": [{"value": "what the record says"}]})
    assert not _quote_present("something the model invented", artifact)


def test_raw_quotes_still_match_a_non_json_artifact() -> None:
    from xentry.extract import _quote_present

    assert _quote_present("hello", "say hello there")
    assert not _quote_present("goodbye", "say hello there")


def test_verify_refs_accepts_a_json_citation() -> None:
    import json as json_mod

    from xentry.extract import ArtifactText, _verify_refs
    from xentry.models import EvidenceRef

    # Long enough to be evidence, and spanning lines the way a description does.
    quote = "the first line of the description\nand the second line of it"
    text = json_mod.dumps({"descriptions": [{"value": quote}]})
    artifact = ArtifactText("cve", hashlib.sha256(text.encode()).hexdigest(), text)
    ref = EvidenceRef(
        artifact_id="cve", sha256=artifact.sha256, quote=quote, line_start=1, line_end=1
    )
    _verify_refs([ref], {"cve": artifact})


# --------------------------------------------------------- step detail ---


def test_a_failed_step_keeps_its_message(tmp_path: Path) -> None:
    from xentry.db import init_db
    from xentry.jobstore import begin_step, create_job, finish_step, list_steps

    conn = init_db(tmp_path / "xentry.db")
    job_id, attempt_id, _ = create_job(conn, data_dir=tmp_path, poc_url="u", cve_url="c")
    failed = begin_step(conn, job_id=job_id, attempt_id=attempt_id, seq=7, name="readiness")
    finish_step(conn, failed, state="failed", reason_code="target_unhealthy", detail="boom\nline2")
    passed = begin_step(conn, job_id=job_id, attempt_id=attempt_id, seq=8, name="later")
    finish_step(conn, passed, state="passed")
    steps = {step["seq"]: step for step in list_steps(conn, job_id)}
    conn.close()
    assert steps[7]["detail"] == "boom\nline2"
    # A step that passed has nothing to show.
    assert steps[8]["detail"] is None


def test_a_stored_message_never_carries_a_nonce() -> None:
    runner = JobRunner.__new__(JobRunner)
    runner._job = _JobLocal()
    runner._job.secrets = ["s3cr3t-nonce-value"]
    stored = runner._detail(RuntimeError("probe returned s3cr3t-nonce-value in the body"))
    assert "s3cr3t-nonce-value" not in stored
    assert "[REDACTED]" in stored


def test_a_stored_message_is_capped() -> None:
    # A step's stderr can be a whole build log; this is read in a table row.
    runner = JobRunner.__new__(JobRunner)
    runner._job = _JobLocal()
    runner._job.secrets = []
    assert len(runner._detail(RuntimeError("x" * 9000))) == 4000


def test_the_detail_column_arrives_with_migration_004(tmp_path: Path) -> None:
    import sqlite3 as sqlite

    from xentry.db import init_db

    migrations = Path(__file__).resolve().parents[1] / "migrations"
    upto_v3 = tmp_path / "m3"
    upto_v3.mkdir()
    for name in sorted(p.name for p in migrations.glob("00[123]_*.sql")):
        (upto_v3 / name).write_text(
            (migrations / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path, migrations_dir=upto_v3)
    try:
        assert conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 3
        with pytest.raises(sqlite.OperationalError):
            conn.execute("SELECT detail FROM job_steps")
    finally:
        conn.close()
    upgraded = init_db(db_path, migrations_dir=migrations)
    try:
        assert (
            upgraded.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            == LATEST_MIGRATION
        )
        # ADD COLUMN, so rows written before the migration simply read NULL.
        assert upgraded.execute("SELECT detail FROM job_steps").fetchall() == []
    finally:
        upgraded.close()


def test_job_page_hangs_the_message_off_a_failed_row() -> None:
    steps = [
        {
            "seq": 7,
            "name": "readiness",
            "step_id": "readiness-php",
            "state": "failed",
            "reason_code": "target_unhealthy",
            "started_at": "t",
            "finished_at": "t",
            "detail": "readiness.trace: Permission denied",
        }
    ]
    html = _render(steps=steps)
    assert 'data-detail="fail:7"' in html
    assert "readiness failed" in html
    assert "target_unhealthy" in html
    assert "Permission denied" in html
    assert html.index('data-step="readiness"') < html.index('data-detail="fail:7"')


def test_job_page_omits_the_message_row_when_there_is_none() -> None:
    steps = [
        {
            "seq": 7,
            "name": "readiness",
            "step_id": "readiness-php",
            "state": "failed",
            "reason_code": "target_unhealthy",
            "started_at": "t",
            "finished_at": "t",
            "detail": None,
        }
    ]
    assert "step-detail" not in _render(steps=steps)


def test_a_collected_trace_is_redacted(tmp_path: Path) -> None:
    """The run-poc trace carries the nonce on the command line."""
    guest = tmp_path / "guest.trace"
    guest.write_text("+ ./exp --marker s3cr3t-nonce\n", encoding="utf-8")
    sink = tmp_path / "real_actor-commands.txt"
    _collect(StubClient({"path": str(guest)}), sink, ["s3cr3t-nonce"])
    body = sink.read_text(encoding="utf-8")
    assert "s3cr3t-nonce" not in body
    assert "[REDACTED]" in body


def test_job_page_hangs_commands_off_a_traced_poc_step() -> None:
    steps = [
        {
            "seq": 15,
            "name": "real_actor",
            "step_id": "run-poc-php",
            "state": "passed",
            "reason_code": None,
            "started_at": "t",
            "finished_at": "t",
            "detail": None,
        }
    ]
    html = _render(steps=steps, commands={"real_actor": ["+ ./exp"]})
    assert 'data-detail="cmd:real_actor"' in html
    assert '<span class="name">run-poc-php.sh</span>' in html
    assert "1 command" in html
    # A trace is not a plan, so it is not dimmed.
    assert 'class="cmdlog"' in html


def test_a_fragment_is_rejected_as_a_fragment(tmp_path: Path) -> None:
    """Job 66e68dc2213a died on a two-character citation: "}`".

    It failed as "quote not found", which says nothing useful. A quote that
    short is not evidence of anything, so it is named for what it is.
    """
    from xentry.extract import MIN_QUOTE, ArtifactText, ExtractorError, _verify_refs
    from xentry.models import EvidenceRef

    text = "a paragraph with real content in it, long enough to cite"
    artifact = ArtifactText("poc", hashlib.sha256(text.encode()).hexdigest(), text)
    fragment = EvidenceRef(
        artifact_id="poc", sha256=artifact.sha256, quote="}`", line_start=1, line_end=1
    )
    with pytest.raises(ExtractorError, match="not something a reader could check"):
        _verify_refs([fragment], {"poc": artifact})

    # A real quote of sufficient length still passes. One character past the
    # floor, because the quote is measured AFTER stripping and text[:MIN_QUOTE]
    # happens to end in a space - which is the test's own edge, not the rule's.
    good = EvidenceRef(
        artifact_id="poc",
        sha256=artifact.sha256,
        quote=text[: MIN_QUOTE + 1],
        line_start=1,
        line_end=1,
    )
    _verify_refs([good], {"poc": artifact})


def test_a_missing_quote_names_the_artifact_and_the_text(tmp_path: Path) -> None:
    from xentry.extract import ArtifactText, ExtractorError, _verify_refs
    from xentry.models import EvidenceRef

    text = "what the artifact actually says, at some length"
    artifact = ArtifactText("cve", hashlib.sha256(text.encode()).hexdigest(), text)
    ref = EvidenceRef(
        artifact_id="cve",
        sha256=artifact.sha256,
        quote="something the model invented entirely",
        line_start=1,
        line_end=1,
    )
    with pytest.raises(ExtractorError, match="not found in artifact cve"):
        _verify_refs([ref], {"cve": artifact})


def test_the_prompt_states_the_minimum_quote_length() -> None:
    from xentry.extract import MIN_QUOTE, ArtifactText, _prompt

    prompt = _prompt([ArtifactText("cve", "a" * 64, "text")])
    assert str(MIN_QUOTE) in prompt
    assert "fragment" in prompt


def _refs(artifact: object, quotes: list[str]) -> list[object]:
    from xentry.models import EvidenceRef

    return [
        EvidenceRef(
            artifact_id=artifact.artifact_id,  # type: ignore[attr-defined]
            sha256=artifact.sha256,  # type: ignore[attr-defined]
            quote=quote,
            line_start=1,
            line_end=1,
        )
        for quote in quotes
    ]


def _facts(artifact: object, citations: list[str], evidence: list[str]) -> object:
    from xentry.models import Facts

    return Facts(
        cve_id="CVE-2026-109618",
        product="PHP",
        affected_range="8.4.0 ~ 8.4.26",
        version_evidence=_refs(artifact, evidence),  # type: ignore[arg-type]
        protocol="http",
        ports=[8088],
        auth_required=False,
        build_strategy="apache mod_php",
        poc_context="remote",
        citations=_refs(artifact, citations),  # type: ignore[arg-type]
    )


def _artifact(text: str) -> object:
    from xentry.extract import ArtifactText

    return ArtifactText("poc", hashlib.sha256(text.encode()).hexdigest(), text)


REAL = "a paragraph of real content long enough to be cited verbatim"
OTHER = "a second paragraph that is also long enough to cite properly"


def test_an_unverifiable_narrative_citation_is_dropped_not_fatal() -> None:
    """Job 66e68dc2213a died on one punctuation fragment among thirteen quotes."""
    from xentry.extract import verify_facts

    text = f"{REAL}\n{OTHER}"
    artifact = _artifact(text)
    facts = _facts(artifact, [REAL, "}`", OTHER], [REAL])
    verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]

    assert [ref.quote for ref in facts.citations] == [REAL, OTHER]  # type: ignore[attr-defined]
    assert len(facts.dropped_citations) == 1  # type: ignore[attr-defined]
    assert "not something a reader could check" in facts.dropped_citations[0]  # type: ignore[attr-defined]


def test_one_bad_version_citation_among_good_ones_is_dropped() -> None:
    """Fatal here was the biggest single source of evidence_insufficient.

    version_evidence may not be USED unverified, which is not the same as the
    whole CVE dying because the model invented one quote out of two. The good
    one still backs the range and the bad one is recorded as dropped.
    """
    from xentry.extract import verify_facts

    text = f"{REAL}\n{OTHER}"
    artifact = _artifact(text)
    invented = "invented text that is long enough to pass the floor"
    facts = _facts(artifact, [REAL], [OTHER, invented])
    verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]

    assert [ref.quote for ref in facts.version_evidence] == [OTHER]  # type: ignore[attr-defined]
    assert any(invented in reason for reason in facts.dropped_citations)  # type: ignore[attr-defined]


def test_losing_every_version_citation_is_fatal() -> None:
    # The affected range may not go unbacked: nothing verified means refused.
    from xentry.extract import ExtractorError, verify_facts

    artifact = _artifact(REAL)
    facts = _facts(artifact, [REAL], ["invented text that is long enough to pass"])
    with pytest.raises(ExtractorError, match="nothing backs the affected range"):
        verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]


def test_a_ten_character_line_that_names_the_port_is_evidence() -> None:
    """samba's CVE-2017-7494 died on `port = 445` at a floor of twelve."""
    from xentry.extract import verify_facts

    text = f"{REAL}\nport = 445"
    artifact = _artifact(text)
    facts = _facts(artifact, ["port = 445"], [REAL])
    verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]
    assert [ref.quote for ref in facts.citations] == ["port = 445"]  # type: ignore[attr-defined]
    assert facts.dropped_citations == []  # type: ignore[attr-defined]


def test_losing_every_citation_is_fatal() -> None:
    # Dropping the bad ones must not leave a job with no evidence at all.
    from xentry.extract import ExtractorError, verify_facts

    artifact = _artifact(REAL)
    facts = _facts(artifact, ["}`", "{{"], [REAL])
    with pytest.raises(ExtractorError, match="no citation could be verified"):
        verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]


def test_all_good_citations_leave_nothing_dropped() -> None:
    from xentry.extract import verify_facts

    text = f"{REAL}\n{OTHER}"
    artifact = _artifact(text)
    facts = _facts(artifact, [REAL, OTHER], [REAL])
    verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]
    assert facts.dropped_citations == []  # type: ignore[attr-defined]


# --------------------------------------------------- concurrency safety ---


def test_two_threads_do_not_share_one_jobs_secrets() -> None:
    """A nonce must never leak into another job's stored message.

    _secrets used to live on the runner instance, so a second worker would
    append to the same list and redact the wrong job's values.
    """
    import threading

    runner = JobRunner.__new__(JobRunner)
    runner._job = _JobLocal()
    runner._job.secrets = ["job-a-nonce"]
    seen: dict[str, object] = {}

    def other_worker() -> None:
        runner._job.secrets = ["job-b-nonce"]
        seen["b"] = runner._detail(RuntimeError("leaked job-b-nonce and job-a-nonce"))

    thread = threading.Thread(target=other_worker)
    thread.start()
    thread.join(timeout=5)

    # Each thread redacts its own job's nonce and never sees the other's list.
    assert runner._job.secrets == ["job-a-nonce"]
    assert "job-b-nonce" not in str(seen["b"])
    assert "job-a-nonce" in str(seen["b"]), "the other thread must not redact job a's nonce"


def test_two_threads_do_not_share_one_jobs_deadline() -> None:
    import threading

    runner = JobRunner.__new__(JobRunner)
    runner._job = _JobLocal()
    runner._job.deadline_at = 100.0
    observed: dict[str, object] = {}

    def other_worker() -> None:
        observed["before"] = runner._job.deadline_at
        runner._job.deadline_at = 999.0

    thread = threading.Thread(target=other_worker)
    thread.start()
    thread.join(timeout=5)
    assert observed["before"] is None, "a fresh worker starts from the defaults"
    assert runner._job.deadline_at == 100.0


def test_each_thread_has_its_own_transcript_sink() -> None:
    import threading

    from xentry import transcript

    mine: list[str] = []
    theirs: list[str] = []
    transcript.set_sink(lambda stage, prompt, response: mine.append(prompt))
    try:

        def other_worker() -> None:
            transcript.set_sink(lambda stage, prompt, response: theirs.append(prompt))
            transcript.record("extract", "job-b prompt", "ok")

        thread = threading.Thread(target=other_worker)
        thread.start()
        thread.join(timeout=5)

        transcript.record("extract", "job-a prompt", "ok")
    finally:
        transcript.set_sink(None)

    # Neither job's prompt is filed as the other's evidence.
    assert mine == ["job-a prompt"]
    assert theirs == ["job-b prompt"]


# ---------------------------------------------------- running vms page ---


def _render_vms(
    held: dict[str, object] | None = None,
    environments: list[dict[str, object]] | None = None,
    candidates: list[dict[str, object]] | None = None,
) -> str:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    repo = Path(__file__).resolve().parents[1]
    env = Environment(
        loader=FileSystemLoader(str(repo / "src" / "xentry" / "web" / "templates")),
        undefined=StrictUndefined,
        autoescape=True,
    )
    job = {
        "id": "j" * 32,
        "target_id": "php2shell",
        "cve_id": "CVE-2026-109618",
        "cleanup_state": "pending",
    }
    return env.get_template("vms.html").render(
        held=[{"job": job, "held": held}] if held is not None else [],
        environments=environments or [],
        candidates=candidates or [],
        csrf="t",
        asset_v=lambda: "1",
    )


HELD_BASE: dict[str, object] = {
    "target_vm": "xentry-j-target",
    "attacker_vm": "xentry-j-attacker",
    "network_id": "xentry-j",
    "target_ip": "10.42.1.10",
    "attacker_ip": "10.42.1.20",
    "keys_dir": "/var/lib/xentry/jobs/j/keys",
    "held_at": "2026-11-12T10:00:00+00:00",
    "hold_s": -1.0,
}


def test_a_held_vm_shows_the_verdict_as_pending() -> None:
    """G8 puts teardown before validation, so a held job has no verdict yet."""
    html = _render_vms(
        {
            **HELD_BASE,
            "runner_nonce_observed": True,
            "null_actor_observed_nonce": False,
            "nonce_sha256": "a" * 64,
            "probe_sha256": "a" * 64,
        }
    )
    assert 'data-status="pending">pending' in html
    assert "produced after release" in html
    # The runner's half is settled, and both digests are shown so the match is
    # checkable without exposing the nonce.
    assert "nonce observed" in html
    assert "control clean" in html
    assert "Probe digest" in html
    assert "a" * 32 in html


ENV_JOB: dict[str, object] = {
    "id": "e" * 32,
    "target_id": "php2shell",
    "cve_id": "CVE-2026-109618",
    "cleanup_state": "pending",
}

ENV_BASE: dict[str, object] = {
    "target_vm": "xentry-e-target",
    "attacker_vm": "xentry-e-attacker",
    "network_id": "xentry-e",
    "target_ip": "10.42.3.10",
    "attacker_ip": "10.42.3.20",
    "keys_dir": "/var/lib/xentry/jobs/e/keys",
    "poc_dir": "/home/xentry-guest/poc",
    "built_at": "2026-11-12T11:00:00+00:00",
}


def test_the_page_offers_a_rebuild_for_each_candidate() -> None:
    html = _render_vms(
        candidates=[
            {
                "job_id": "a" * 32,
                "cve_id": "CVE-2026-109618",
                "target_id": "php2shell",
                "poc_url": "https://example.test/poc",
                "cve_url": "https://example.test/cve",
            }
        ]
    )
    assert 'id="rebuild-form"' in html
    assert 'value="' + "a" * 32 + '"' in html
    assert "CVE-2026-109618 - php2shell" in html


def test_an_empty_page_states_both_counts_and_offers_no_rebuild() -> None:
    html = _render_vms()
    assert 'id="rebuild-form"' not in html
    # Counts, not prose: the page says how many of each kind are up.
    assert html.count('data-count="held">0</span>') == 1
    assert 'class="collapse-all"' not in html


def test_a_local_poc_shows_the_actor_login_on_the_target() -> None:
    """dirtyfrag has no attacker VM: xentry-guest on the target is the login
    that reproduces the escalation, and there is no "ubuntu" user at all -
    cloud-init's users list replaces the distro default."""
    html = _render_vms({**HELD_BASE, "attacker_vm": "", "attacker_ip": ""})
    assert "xentry-guest@10.42.1.10" in html
    assert "the user the PoC runs as" in html
    assert "/keys/actor" in html
    assert "root@10.42.1.10" in html
    # Every ssh block is copyable, and there is no attacker line to offer.
    assert html.count('class="copy"') == 2
    assert "ubuntu@" not in html


def test_a_remote_poc_also_shows_the_attacker_login() -> None:
    html = _render_vms(dict(HELD_BASE))
    assert "xentry-guest@10.42.1.20" in html
    assert html.count('class="copy"') == 3


def test_a_rebuilt_environment_shows_how_to_run_the_poc_by_hand() -> None:
    html = _render_vms(environments=[{"job": ENV_JOB, "env": dict(ENV_BASE)}])
    assert "sudo ssh -i /var/lib/xentry/jobs/e/keys/actor" in html
    assert "xentry-guest@10.42.3.20" in html
    assert "/home/xentry-guest/poc" in html
    assert "10.42.3.10" in html
    assert 'class="destroy-env"' in html


def test_a_rebuilt_environment_claims_no_verdict() -> None:
    """A rebuild plants no nonce and runs no control phase, so it proves nothing."""
    html = _render_vms(environments=[{"job": ENV_JOB, "env": dict(ENV_BASE)}])
    assert "none; a rebuild measures nothing" in html
    assert "nonce observed" not in html
    assert "reproduced" not in html


def test_a_rebuild_still_building_offers_no_login() -> None:
    html = _render_vms(environments=[{"job": ENV_JOB, "env": {}}])
    assert ">building" in html
    assert "sudo ssh" not in html
    # Destroying one mid-build goes through cancellation, so it is named that.
    assert "Cancel build" in html
    assert ">Destroy" not in html


def test_a_held_record_written_before_this_change_still_renders() -> None:
    html = _render_vms(dict(HELD_BASE))
    assert "pending" in html
    # No observation may be claimed for a record that never recorded one.
    assert "nonce observed" not in html
    assert "control clean" not in html
    assert "Probe digest" not in html


def test_an_affected_range_with_no_citation_at_all_is_refused() -> None:
    """Giving none passed silently while giving one bad one was fatal.

    The range picks the package version to install, so it may not be the
    model's unsourced claim - and every advisory states its own versions.
    """
    from xentry.extract import ExtractorError, verify_facts

    artifact = _artifact(REAL)
    facts = _facts(artifact, [REAL], [])
    with pytest.raises(ExtractorError, match="no citation was given"):
        verify_facts(facts, [artifact])  # type: ignore[arg-type,list-item]


def test_the_help_indicator_has_exactly_one_tooltip() -> None:
    """One sentence, one tooltip.

    The "i" mark used to set BOTH a title attribute and data-help with the
    same text, and the two are drawn by different machinery: the CSS tooltip
    opens on hover immediately, the browser's native title about a second
    later. So the same description appeared twice, the second overlapping the
    first.

    title was redundant rather than an accessibility affordance: style.css
    opens the CSS tooltip on :hover AND :focus-visible, so pointer and
    keyboard are both covered, and aria-label - which is not rendered - is
    what a screen reader reads.
    """
    import pathlib

    web = pathlib.Path(__file__).resolve().parents[1] / "src/xentry/web/static"
    js = (web / "app.js").read_text()
    css = (web / "style.css").read_text()
    mark = js[js.index("function stepHelp(") : js.index("function annotateStepNames(")]
    assert "mark.dataset.help = text;" in mark
    assert 'mark.setAttribute("aria-label"' in mark
    # The line that produced the second tooltip.
    assert "mark.title" not in mark
    # And the reason title is not needed: the CSS tooltip covers both.
    assert ".stephelp:hover::after" in css
    assert ".stephelp:focus-visible::after" in css


def test_times_are_shown_on_a_24_hour_clock() -> None:
    """No am/pm, anywhere a time is rendered.

    toLocaleTimeString() with no options follows the browser's locale, and an
    en-US browser renders "10:09:46 AM": wider, harder to scan down a column,
    and jarring beside the UTC timestamps the records keep. hour12: false pins
    the clock without hardcoding a locale, so day/month order and separators
    still follow the reader.
    """
    import pathlib

    js = (
        pathlib.Path(__file__).resolve().parents[1] / "src/xentry/web/static/app.js"
    ).read_text()
    assert "hour12: false" in js
    # Every rendered time goes through CLOCK. A bare call would quietly bring
    # am/pm back for whoever's browser asks for it. Comments are stripped
    # first, because the comment EXPLAINING this names the bare call - which
    # is what the first version of this test tripped on.
    code = "\n".join(
        line for line in js.splitlines() if not line.lstrip().startswith("//")
    )
    assert "toLocaleTimeString()" not in code
    assert "toLocaleTimeString(undefined, CLOCK)" in js
    # The tooltip too - hovering should not hand back the format just removed.
    title = js[js.index("function localTitle(") : js.index("function wireTimestamps(")]
    assert "...CLOCK," in title
    assert 'timeZoneName: "short"' in title
