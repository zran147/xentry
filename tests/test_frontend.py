"""The browser code is executed, not just shipped.

app.js has no test runner of its own; these drive it under node against a
minimal DOM stand-in, so the render paths the job page depends on are checked
in the normal test run. They skip where node is unavailable rather than fail.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "src" / "xentry" / "web" / "static" / "app.js"
JS_DIR = Path(__file__).resolve().parent / "js"
HARNESS = JS_DIR / "render.js"
WIRING = JS_DIR / "wiring.js"
ENVIRONMENTS = JS_DIR / "environments.js"
COPY = JS_DIR / "copy.js"
SESSION = JS_DIR / "session.js"
NODE = shutil.which("node")

skip_without_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


@skip_without_node
def test_app_js_parses() -> None:
    done = subprocess.run(
        [str(NODE), "--check", str(APP_JS)], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr


@skip_without_node
def test_render_functions_behave() -> None:
    done = subprocess.run(
        [str(NODE), str(HARNESS), str(APP_JS)],
        capture_output=True,
        text=True,
        check=False,
        cwd=HARNESS.parent,
    )
    assert done.returncode == 0, done.stdout + done.stderr


@skip_without_node
def test_job_page_wiring_makes_the_provision_row_clickable() -> None:
    # Exercises wireJobPage, the entry point: the render functions can be
    # correct while nothing is wired to them.
    done = subprocess.run(
        [str(NODE), str(WIRING), str(APP_JS)],
        capture_output=True,
        text=True,
        check=False,
        cwd=JS_DIR,
    )
    assert done.returncode == 0, done.stdout + done.stderr


@skip_without_node
def test_running_vms_page_requests_and_destroys_environments() -> None:
    # A rebuild detonates nothing, but it does start VMs: the request must
    # carry the CSRF header and name the job it was offered for.
    done = subprocess.run(
        [str(NODE), str(ENVIRONMENTS), str(APP_JS)],
        capture_output=True,
        text=True,
        check=False,
        cwd=JS_DIR,
    )
    assert done.returncode == 0, done.stdout + done.stderr


@skip_without_node
def test_the_session_feed_appends_and_tells_the_two_verbs_apart() -> None:
    # Two things Python cannot see. The feed is rebuilt from an array on every
    # stream tick, because renderSteps replaces the whole table and a feed
    # held only in the DOM would be wiped mid-session; and ADR 0004 asks that
    # free_exec never be drawn like exec, which is a property of the rendered
    # line rather than of the endpoint.
    done = subprocess.run(
        [str(NODE), str(SESSION), str(APP_JS)],
        capture_output=True,
        text=True,
        check=False,
        cwd=JS_DIR,
    )
    assert done.returncode == 0, done.stdout + done.stderr


@skip_without_node
def test_the_ssh_copy_button_works_without_the_clipboard_api() -> None:
    # The app is served over plain http on the LAN, where
    # navigator.clipboard does not exist, so the execCommand path is the one
    # that runs - and a button that claims to have copied when it has not is
    # worse than no button.
    done = subprocess.run(
        [str(NODE), str(COPY), str(APP_JS)],
        capture_output=True,
        text=True,
        check=False,
        cwd=JS_DIR,
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_every_step_the_runner_records_has_a_description() -> None:
    """A step added without help text gets no circle, silently.

    The steps table is the page people read when a job fails, so a row with
    no explanation is exactly the row they most need explained. This compares
    the names the runner actually records against STEP_HELP in app.js.
    """
    import re

    runner = (ROOT / "src" / "xentry" / "runner.py").read_text(encoding="utf-8")
    # self._step(conn, job_id, attempt_id, <seq>, "<name>", ...)
    recorded = set(re.findall(r'attempt_id,\s*[^,]+,\s*"([a-z_]+)"', runner))
    recorded |= set(re.findall(r'(?m)^\s*"(readiness|provision|reboot)",\s*$', runner))
    assert len(recorded) > 15, f"the step names stopped parsing: {sorted(recorded)}"

    app_js = APP_JS.read_text(encoding="utf-8")
    block = app_js.split("const STEP_HELP = {", 1)[1].split("\n};", 1)[0]
    described = set(re.findall(r"(?m)^\s{2}([a-z_]+):", block))

    missing = sorted(recorded - described)
    assert not missing, f"steps with no description: {missing}"


def test_nothing_from_the_app_is_cacheable_and_static_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET / is what SETS the token cookie.

    Nothing sent a Cache-Control header, so a browser could serve that page
    from its own cache, never receive the Set-Cookie, and fail every POST with
    token_missing - a page that looks fine and is dead until a hard reload.
    An /api GET served from cache freezes a job list the same way. /static is
    the opposite: its URL carries ?v=<content digest>, so it may be cached
    hard and for a year.
    """
    from fastapi.testclient import TestClient

    from tests.test_web import FakeRunner
    from xentry.web.app import build_app

    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
        # The cookie this page sets is the reason it must not be cached.
        assert "xentry_token" in page.cookies or "set-cookie" in page.headers

        for path in ("/api/jobs", "/api/system", "/vms"):
            answer = client.get(path)
            assert answer.headers["cache-control"] == "no-store", path

        asset = client.get("/static/app.js")
        assert asset.status_code == 200
        assert "immutable" in asset.headers["cache-control"], asset.headers
        assert "max-age=31536000" in asset.headers["cache-control"]
