"""An operator-approved download, offered only when nothing else can install.

The three CVEs that drove this - Confluence twice and WSO2 - ship a PoC that
is one exploit.py and assume the product already exists. Their affected
versions are downloadable from the vendor, and no archive carries them.
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
from xentry import generic
from xentry.db import connect, init_db
from xentry.fetch import Fetched, artifact_text
from xentry.jobstore import get_job, list_steps
from xentry.models import Facts
from xentry.runner import JobRunner

POC_REPO = "https://github.com/someone/CVE-2022-26134"
ADVISORY = (
    "cveMetadata.cveId: CVE-2022-26134\n"
    "cveMetadata.datePublished: 2022-06-02T00:00:00.000Z\n"
)
TARBALL_URL = "https://product-downloads.example/atlassian-confluence-7.13.0.tar.gz"


def _tarball() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        info = tarfile.TarInfo("confluence/bin/start.sh")
        body = b"#!/bin/sh\necho up\n"
        info.size = len(body)
        handle.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


TARBALL = _tarball()


def _fetched(url: str, body: bytes, content_type: str = "text/plain") -> Fetched:
    headers = {"content-type": content_type}
    return Fetched(
        url=url, final_url=url, status=200, headers=headers, body=body,
        text=artifact_text(headers, body), sha256=hashlib.sha256(body).hexdigest(),
    )


def _fetch(url: str) -> Fetched:
    if url == TARBALL_URL:
        return _fetched(url, TARBALL, "application/gzip")
    if "codeload" in url:
        return _fetched(url, TARBALL, "application/gzip")
    if url.endswith("/package.json"):
        from xentry.fetch import FetchError

        raise FetchError("HTTP status 404")
    return _fetched(url, ADVISORY.encode())


def _facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "cve_id": "CVE-2022-26134",
        "product": "Confluence Server",
        "affected_range": "< 7.13.7",
        "version_evidence": [],
        "protocol": "https",
        "ports": [],
        "auth_required": False,
        "build_strategy": "the product is installed from the vendor's tarball",
        "poc_context": "remote",
        # The shape that drove this: no package, no lab.
        "setup_packages": [],
        "setup_units": [],
        "poc_entrypoint": "exploit.py",
        "citations": [],
    }
    base.update(overrides)
    return Facts(**base)


# ------------------------------------------------- the last-resort ordering ---


def test_a_download_is_only_the_answer_when_nothing_else_is() -> None:
    """The guard the whole feature rests on. Every other reason to refuse must
    be absent before an approval is offered, or it becomes a way around the
    archives rather than a way past their limits."""
    assert generic.needs_a_download(_facts()) is True
    # A local PoC has no attacker to attest from: a download cannot fix that.
    assert generic.needs_a_download(_facts(poc_context="local")) is False
    # No port and no protocol default: nothing to reach even once installed.
    assert generic.needs_a_download(_facts(protocol=None, ports=[])) is False
    # A package the archives may well carry: ask them first.
    assert generic.needs_a_download(_facts(setup_packages=["confluence"])) is False


@pytest.mark.parametrize(
    ("filename", "verb"),
    [
        ("atlassian-confluence-7.13.0.tar.gz", "tarball"),
        ("wso2is-5.11.0.zip", "zip"),
        ("apache2_2.4.49-4_amd64.deb", "deb"),
        ("node-v22.11.0-linux-x64.tar.xz", "tarball"),
    ],
)
def test_the_install_follows_from_the_file(filename: str, verb: str) -> None:
    """Not an operator choice. A .deb has one install and a tarball has one,
    so offering a choice would only create a way to be wrong."""
    assert generic.install_verb(filename) == verb


@pytest.mark.parametrize("filename", ["setup.exe", "installer.bin", "install.sh", "x"])
def test_a_file_that_has_to_be_run_is_refused(filename: str) -> None:
    """A vendor installer is arbitrary code, which is the one thing a
    provisioning step here never executes - whatever it is packed in."""
    with pytest.raises(generic.NoObservable, match="no install for"):
        generic.install_verb(filename)


# --------------------------------------------------------- the form and job ---


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, facts: Facts) -> Any:
    from fastapi.testclient import TestClient

    from tests.test_web import FakeRunner
    from xentry import release as release_module
    from xentry.web.app import build_app

    monkeypatch.setattr("xentry.web.app.fetch", _fetch)
    monkeypatch.setattr("xentry.web.app.extract", lambda _artifacts: facts)
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


def test_the_form_reports_every_channel_before_offering_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app = _app(tmp_path, monkeypatch, _facts())
    with client:
        client.get("/")
        result = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert result.status_code == 200, result.json()
        body = result.json()
        assert body["state"] == "needs_artifact"
        assert [item["channel"] for item in body["channels"]] == [
            "a checked-in target",
            "an application-package lab",
            "an apt archive",
        ]
        assert "says how to install the affected software" in body["detail"]
        assert ".zip" in body["accepts"]
        # A check exists, so the approval has something to bind to.
        assert len(body["check_id"]) == 32


def test_approving_a_file_records_its_digest_and_its_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app = _app(tmp_path, monkeypatch, _facts())
    with client:
        client.get("/")
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        ).json()
        approved = client.post(
            "/api/artifacts/approve",
            json={"check_id": checked["check_id"], "urls": [TARBALL_URL]},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert approved.status_code == 200, approved.json()
        body = approved.json()
        assert body["files"][0]["filename"] == "atlassian-confluence-7.13.0.tar.gz"
        assert body["files"][0]["install"] == "tarball"
        assert body["files"][0]["bytes"] == len(TARBALL)
        # The approval is of bytes: this digest is what the job will install.
        assert body["files"][0]["sha256"] == hashlib.sha256(TARBALL).hexdigest()


def test_a_file_this_harness_cannot_install_is_refused_at_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, app = _app(tmp_path, monkeypatch, _facts())
    with client:
        client.get("/")
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        ).json()
        refused = client.post(
            "/api/artifacts/approve",
            json={"check_id": checked["check_id"], "urls": ["https://x.example/setup.exe"]},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert refused.status_code == 422
        assert "no install for" in refused.json()["detail"]


def test_an_unknown_check_cannot_be_approved_against(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The approval is per job, through the check that one job consumes."""
    client, app = _app(tmp_path, monkeypatch, _facts())
    with client:
        client.get("/")
        refused = client.post(
            "/api/artifacts/approve",
            json={"check_id": "0" * 32, "urls": [TARBALL_URL]},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert refused.status_code == 404


def test_a_job_installs_the_approved_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: check, approve, run, and the setup step is told the path
    and the install verb for the file the broker copied in."""
    facts = _facts(launch="start.sh")
    client, app = _app(tmp_path, monkeypatch, facts)
    data_dir = tmp_path / "data"
    with client:
        client.get("/")
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        ).json()
        client.post(
            "/api/artifacts/approve",
            json={"check_id": checked["check_id"], "urls": [TARBALL_URL]},
            headers={"X-Xentry-CSRF": app.state.token},
        )

    from xentry import release as release_module

    monkeypatch.setattr(
        "xentry.runner.resolved_artifacts",
        lambda: {item.artifact_id for item in release_module.RELEASES},
    )
    db_path = data_dir / "xentry.db"
    conn = init_db(db_path)
    from xentry.jobstore import create_job

    job_id, attempt_id, _dir = create_job(
        conn, data_dir=data_dir, poc_url=POC_REPO, cve_url="https://example.com/cve",
        check_id=checked["check_id"],
    )
    conn.close()
    broker = GenericBroker()
    JobRunner(
        db_path=db_path,
        data_dir=data_dir,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: facts,
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)

    conn = connect(db_path)
    try:
        job = get_job(conn, job_id)
        assert job is not None
        names = [row["name"] for row in list_steps(conn, job_id)]
        assert "stage_approved" in names
        assert names.index("stage_approved") < names.index("provision")
    finally:
        conn.close()
    setup = broker.exec_params["setup-generic"]
    # Names, not paths, and one token list: the step derives each install from
    # its own suffix, so two parallel lists cannot fall out of step.
    assert setup["artifacts"] == "atlassian-confluence-7.13.0.tar.gz", setup
    # Unpacking is not installing. Without this the tarball landed in
    # /opt/xentry-artifact and nothing ever started it, so the job spent its
    # 300s port wait and then failed as "nothing is listening".
    assert setup["launch"] == "start.sh"
    copied = [
        params.get("guest_path")
        for verb, params in broker.calls
        if verb == "copy_in"
    ]
    assert "atlassian-confluence-7.13.0.tar.gz" in copied, copied


# ------------------------------------------------------------- the form itself ---


def test_the_reason_is_rendered_above_the_remedy() -> None:
    """How this was first reported: "an empty json plan".

    The approval block sat between the form and the plan box, and its digest
    box carried the plan's own styling while empty - so the first thing on the
    page where the plan used to be was an empty plan-shaped box, with the
    channel table below it.
    """
    import re

    root = Path(__file__).resolve().parents[1]
    page = (root / "src/xentry/web/templates/index.html").read_text()
    order = [
        match.group(1)
        for match in re.finditer(r'<(?:pre|section) id="(plan|approval|approval-detail)"', page)
    ]
    assert order == ["plan", "approval", "approval-detail"], order
    # And nothing plan-shaped is on the page with no content and no hidden.
    for match in re.finditer(r'<pre id="([a-z-]+)" class="plan"([^>]*)>', page):
        assert "hidden" in match.group(2), f"{match.group(1)} is a visible empty plan box"


def test_the_digest_box_is_revealed_only_when_it_has_a_digest() -> None:
    app_js = (
        Path(__file__).resolve().parents[1] / "src/xentry/web/static/app.js"
    ).read_text()
    approval = app_js.split("function showApproval(", 1)[1].split("\nfunction ", 1)[0]
    # Cleared and hidden when the region opens, revealed after a successful fetch.
    assert "detail.hidden = true;" in approval
    assert "detail.hidden = false;" in approval
    assert approval.index("detail.hidden = true;") < approval.index("detail.hidden = false;")


def test_an_unbuilt_archive_is_named_rather_than_silently_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CVE-2021-41773 answered "no archive carries this", and the archive that
    does - Debian, which kept apache2 2.4.49 - had simply never been built
    here. The resolver only ever had Ubuntu to ask, and said nothing about it.
    """
    from fastapi.testclient import TestClient

    from tests.test_web import FakeRunner
    from xentry.web.app import build_app

    monkeypatch.setattr("xentry.web.app.fetch", _fetch)
    monkeypatch.setattr("xentry.web.app.extract", lambda _artifacts: _facts())
    # Only noble is built, which is the state that produced the report.
    monkeypatch.setattr("xentry.web.app.resolved_artifacts", lambda: {"ubuntu-generic-image"})
    app = build_app(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "xentry.db",
        broker_socket=tmp_path / "broker.sock",
        runner=FakeRunner(),  # type: ignore[arg-type]
    )
    client = TestClient(app)
    with client:
        client.get("/")
        body = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        ).json()
    skipped = [item for item in body["channels"] if "not consulted" in item["channel"]]
    assert skipped, body["channels"]
    verdict = skipped[0]["verdict"]
    assert "debian sid" in verdict
    assert "build-images.sh" in verdict
    assert "debian-11-generic" in verdict


# ------------------------------------------------- starting what was unpacked ---


@pytest.mark.parametrize(
    "name",
    ["bin/start.sh", "../start.sh", "..", ".", "/usr/bin/java", "start.sh;rm -rf /", ""],
)
def test_a_launcher_is_a_name_and_never_a_path(name: str) -> None:
    """The step resolves the name under the unpacked tree with find, so a name
    carrying a separator is refused rather than used as a path. "" is the
    normal case - most targets install a package - and yields no argument."""
    if name == "":
        assert generic.tokens([name], "launch") == ""
        return
    with pytest.raises(generic.NoObservable, match="refused launch"):
        generic.tokens([name], "launch")


def test_the_step_manifest_declares_the_launch_param() -> None:
    """Four tables have to agree: the script's positional args, the manifest's
    param list, the runner's dict, and the script's own hash. The broker
    refuses a param the manifest does not declare, so a launcher wired in the
    runner alone would have failed every approved-download job at dispatch."""
    import hashlib

    import yaml

    root = Path(__file__).resolve().parents[1]
    spec = yaml.safe_load((root / "targets/steps.yaml").read_text())["steps"]["setup-generic"]
    script = root / "targets" / spec["script"]
    # Positional, so the index IS the contract. `artifacts` replaced
    # artifact_path AND install - two params became one, because each file's
    # install is derived from its own suffix now - so everything after it moved
    # down a place. A script still reading ${11-} for launch after that change
    # would have silently read `place` instead.
    assert spec["params"].index("artifacts") == 8, spec["params"]
    assert spec["params"].index("launch") == 9, spec["params"]
    assert spec["params"].index("place") == 10, spec["params"]
    assert "artifact_path" not in spec["params"]
    assert "install" not in spec["params"]
    assert hashlib.sha256(script.read_bytes()).hexdigest() == spec["sha256"]
    text = script.read_text()
    assert 'artifacts="${9-}"' in text
    assert 'launch="${10-}"' in text
    assert 'place="${11-}"' in text


def _with_artifacts(tmp_path: Path, names: list[str], launch: str, place: str) -> Any:
    """The real script with the artifact directory pointed at a tmp path.

    The artifact arguments are only checked once the files exist, and the real
    directory is under /var/lib/xentry which needs root. The substitution is
    one string; the code under test is otherwise verbatim.
    """
    import subprocess

    root = Path(__file__).resolve().parents[1]
    store = tmp_path / "artifacts"
    store.mkdir(parents=True, exist_ok=True)
    for name in names:
        # Only the ones that are legal filenames: a case like "a/b.deb" exists
        # to check the script refuses the NAME, and creating it here would
        # fail in the test rather than in the code under test.
        if "/" not in name:
            (store / name).write_bytes(b"x")
    script = tmp_path / "setup-generic.sh"
    script.write_text(
        (root / "targets/common/setup-generic.sh")
        .read_text()
        .replace("/var/lib/xentry/artifacts", str(store))
    )
    return subprocess.run(
        ["bash", str(script), "http://10.0.0.1:3142", "sid", "", "", "deb822", "",
         "debian", "0", " ".join(names), launch, place],
        capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize(
    ("names", "launch", "place", "expected"),
    [
        # A name is a name: no separator, and nothing that climbs out.
        (["a/b.deb"], "", "", "refused artifact name"),
        # A suffix this harness has no install for.
        (["installer.bin"], "", "", "no install for"),
        # `place` names one kind, so it cannot describe two files - the second
        # would be written to the same path and silently win.
        (["one.conf", "two.war"], "", "apache-site", "place names one"),
        # A placed file needs a kind, and a kind needs a placed file.
        (["x.conf"], "", "", "refused place for x.conf"),
        (["x.conf"], "", "lighttpd-site", "refused place for x.conf"),
        (["x.tar.gz"], "", "apache-site", "no approved file is one that gets placed"),
        # And a launcher is still refused on its own terms.
        (["x.tar.gz"], "bin/start.sh", "", "refused launch"),
        (["x.tar.gz"], "..", "", "refused launch"),
    ],
)
def test_the_setup_script_refuses_an_artifact_set_it_cannot_install(
    tmp_path: Path, names: list[str], launch: str, place: str, expected: str
) -> None:
    """Checked in the script as well as in the app: the script is what runs as
    root in the guest, and the app is not its only caller."""
    done = _with_artifacts(tmp_path, names, launch, place)
    assert done.returncode == 2, done.stdout + done.stderr
    assert expected in done.stderr, done.stderr


def test_an_approved_file_the_broker_did_not_copy_in_is_named(tmp_path: Path) -> None:
    """The broker copies them in before this runs; if one is absent the step
    says which rather than failing later on a path that is not there."""
    _with_artifacts(tmp_path, [], "", "")
    import subprocess

    done = subprocess.run(
        ["bash", str(tmp_path / "setup-generic.sh"), "http://10.0.0.1:3142", "sid",
         "", "", "deb822", "", "debian", "0", "gone.deb", "", ""],
        capture_output=True, text=True, check=False,
    )
    assert done.returncode == 2
    assert "missing approved artifact" in done.stderr, done.stderr


def _launch_block() -> str:
    """The part of setup-generic.sh that starts an unpacked product.

    Extracted rather than run whole: the surrounding script configures apt and
    installs packages as root in a guest. If the block is restructured this
    raises instead of silently testing nothing.
    """
    root = Path(__file__).resolve().parents[1]
    text = (root / "targets/common/setup-generic.sh").read_text()
    start = text.index("# The unpacked product, started.")
    end = text.index("\n# The port the job was planned around", start)
    block = text[start:end]
    assert "mapfile -t entries" in block and "setsid nohup" in block, block
    return block


def _run_block(tmp_path: Path, launch: str) -> Any:
    import subprocess

    prefix = tmp_path / "prefix"
    var = tmp_path / "var"
    var.mkdir(parents=True, exist_ok=True)
    block = _launch_block().replace("/var/lib/xentry", str(var))
    script = tmp_path / "block.sh"
    script.write_text(
        f'set -euo pipefail\nPREFIX="{prefix}"\nlaunch="{launch}"\nunits=""\n{block}'
    )
    return subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False
    )


def _product(tmp_path: Path, name: str, *, bundled_jre: bool = False) -> Path:
    tree = tmp_path / "prefix" / "confluence-7.13.0"
    (tree / "bin").mkdir(parents=True)
    entry = tree / "bin" / name
    # 30s, so a block that waits for it fails the timing assertion rather than
    # passing slowly.
    entry.write_text(f"#!/bin/sh\ntouch {tmp_path}/ran\nexec sleep 30\n")
    entry.chmod(0o755)
    if bundled_jre:
        (tree / "jre" / "bin").mkdir(parents=True)
        java = tree / "jre" / "bin" / "java"
        java.write_text("#!/bin/sh\n")
        java.chmod(0o755)
    return entry


def test_the_launcher_is_started_from_its_own_directory(tmp_path: Path) -> None:
    """A launcher that runs in the foreground - WSO2's does - must not hold the
    provision step open until its timeout, and one that daemonises itself must
    still be running after this returns.

    The fake launcher here never exits on its own, and the timing assertion is
    the whole point of the test. Detaching the grandchild with setsid was not
    enough: something in that chain kept the step's inherited stdout, the
    broker reads that pipe to EOF, and the first version of this block held the
    provision step open for exactly as long as the launcher ran - 30s here,
    1800s and a timeout for a real product. Redirecting the subshell's own
    stdout and stderr is what fixed it, and this is what notices if it comes
    back."""
    import time

    _product(tmp_path, "start-confluence.sh", bundled_jre=True)
    started = time.monotonic()
    done = _run_block(tmp_path, "start-confluence.sh")
    elapsed = time.monotonic() - started
    assert done.returncode == 0, done.stdout + done.stderr
    assert elapsed < 10, f"the step waited {elapsed:.1f}s for a detached launcher"
    assert "launching" in done.stdout
    # The bundled runtime, not whatever the host happens to have.
    assert "/jre)" in done.stdout or "jre" in done.stdout, done.stdout
    for _ in range(50):
        if (tmp_path / "ran").exists():
            break
        import time

        time.sleep(0.1)
    assert (tmp_path / "ran").exists(), done.stdout + done.stderr


def test_a_launcher_that_is_not_there_names_the_ones_that_are(tmp_path: Path) -> None:
    _product(tmp_path, "wso2server.sh")
    done = _run_block(tmp_path, "start-confluence.sh")
    assert done.returncode == 1
    assert "no file named start-confluence.sh" in done.stderr
    assert "wso2server.sh" in done.stderr, done.stderr


def test_an_ambiguous_launcher_is_refused_rather_than_guessed(tmp_path: Path) -> None:
    """Two products in one archive, or a bundled sample, would otherwise have
    been resolved by whichever find returned first."""
    for product in ("a", "b"):
        tree = tmp_path / "prefix" / product / "bin"
        tree.mkdir(parents=True)
        (tree / "startup.sh").write_text("#!/bin/sh\n")
        (tree / "startup.sh").chmod(0o755)
    done = _run_block(tmp_path, "startup.sh")
    assert done.returncode == 1
    assert "ambiguous" in done.stderr
    assert done.stderr.count("startup.sh") >= 3, done.stderr


# ------------------------------------------- a repository with no exploit in it ---


def test_a_poc_with_nothing_to_run_is_not_offered_a_download() -> None:
    """blasty's CVE-2021-41773 repository is the case this is for.

    It ships a Dockerfile, a docker-compose.yml, four vendored
    apache2_2.4.49-4 .debs and a config the author labels "not a stock or
    recommended config ;-)" - and no exploit: the attack is a curl line in the
    README. needs_a_download consulted _reason, which never looks at the
    entrypoint, so the operator was offered an approval for a job that could
    not have run whatever they approved.
    """
    assert generic.needs_a_download(_facts()) is True
    assert generic.needs_a_download(_facts(poc_entrypoint=None)) is False
    assert generic.needs_a_download(_facts(poc_entrypoint="  ")) is False


def test_the_refusal_names_the_missing_exploit_not_the_missing_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both are true of blasty's repository; only one of them is the blocker.

    derive() ran first and raised on the package list, so the answer was
    "names no Ubuntu package to install" - which sent the reader looking for a
    package when nothing was ever going to be executed.
    """
    client, app = _app(tmp_path, monkeypatch, _facts(poc_entrypoint=None))
    with client:
        client.get("/")
        result = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        )
    assert result.status_code == 422, result.json()
    detail = result.json()["detail"]
    assert "does not name a file that runs the exploit" in detail, detail
    assert "Ubuntu package" not in detail, detail


# ------------------------------------- a package that is not vulnerable yet ---


def test_a_placement_is_refused_unless_a_file_is_approved_for_it() -> None:
    """CVE-2021-41773 resolves perfectly and still reproduces nothing.

    Debian sid carries apache2 2.4.49-4 at serial 20211004, so the package
    resolves, installs and listens - and is not vulnerable, because the stock
    config ships `<Directory /> Require all denied` and the traversal needs
    `Require all granted`. Without this the job would have passed readiness,
    run the PoC and reported "did not reproduce", and with no fixed-version
    control run on this path nothing would have said it was the configuration
    rather than the CVE.
    """
    settled = _facts(setup_packages=["apache2"], setup_units=["apache2"], ports=[80])
    assert generic.admits(settled) is True
    needs = _facts(
        setup_packages=["apache2"], setup_units=["apache2"], ports=[80],
        place="apache-site",
    )
    assert generic.admits(needs) is False
    assert "not vulnerable as packaged" in str(generic._reason(needs))
    # And it is exactly the gap an approval closes, so the form offers one.
    assert generic.needs_a_download(needs) is True
    assert generic.admits(needs, artifact=True) is True


@pytest.mark.parametrize(
    ("name", "verb"),
    [("000-default.conf", "file"), ("log4shell-1.0-SNAPSHOT.war", "file")],
)
def test_a_placed_file_is_installed_by_being_put_somewhere(name: str, verb: str) -> None:
    assert generic.install_verb(name) == verb


def test_only_a_placement_this_harness_knows_is_accepted() -> None:
    assert generic.placement(_facts()) == ""
    assert generic.placement(_facts(place="apache-site")) == "apache-site"
    assert generic.placement(_facts(place="tomcat-webapp")) == "tomcat-webapp"
    assert generic.placement(_facts(place="nginx-site")) == "nginx-site"
    # lighttpd is a real server and deliberately NOT a kind this harness knows:
    # a placement it cannot make must be refused rather than approximated.
    for bad in ("lighttpd-site", "../etc/passwd", "apache-site;rm -rf /"):
        with pytest.raises(generic.NoObservable, match="refused place"):
            generic.placement(_facts(place=bad))




def test_re_approving_replaces_the_whole_set(tmp_path: Path) -> None:
    """An approval is of a SET of bytes.

    Approving three files and then re-approving one left the other two behind
    - stored as artifact1 and artifact2, which nothing overwrote - and the job
    installed three files, two of them from an approval the operator thought
    they had replaced.
    """
    from xentry import sourcestore

    root = tmp_path / "store"
    sourcestore.save(root, "chk", {"cve": _fetched("https://x/cve", b"a"),
                                   "poc": _fetched("https://x/poc", b"b")})
    for index, name in enumerate(("one.deb", "two.deb", "three.conf")):
        sourcestore.add(root, "chk", f"artifact{index}",
                        _fetched(f"https://x/{name}", name.encode()))
    held = sorted(k for k in sourcestore.load(root, "chk") if k.startswith("artifact"))
    assert held == ["artifact0", "artifact1", "artifact2"]

    assert sourcestore.drop(root, "chk", "artifact") == 3
    sourcestore.add(root, "chk", "artifact0",
                    _fetched("https://x/only.deb", b"only"))
    back = sourcestore.load(root, "chk")
    assert sorted(k for k in back if k.startswith("artifact")) == ["artifact0"]
    assert back["artifact0"].body == b"only"
    # And the check's own sources are untouched: the bundle digest must not move.
    assert sorted(k for k in back if not k.startswith("artifact")) == ["cve", "poc"]


def test_the_install_order_follows_the_number_not_the_string() -> None:
    """Past nine files "artifact10" sorts before "artifact2" as a string, and a
    .deb would install after the config that configures it. Unreachable at
    MAX_APPROVED today; a trap if that ever rises."""
    names = [f"artifact{i}" for i in range(12)]
    by_string = sorted(names)
    by_number = sorted(names, key=lambda k: int(k.removeprefix("artifact")))
    assert by_string != by_number
    assert by_number[:3] == ["artifact0", "artifact1", "artifact2"]
    assert generic.MAX_APPROVED < 10, (
        "raise this and the runner's numeric sort is what keeps the order right"
    )


def test_the_endpoint_replaces_the_set_not_just_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The test above covers sourcestore.drop; this covers the endpoint calling
    it. Removing that one line failed nothing, which is the gap that let the
    bug exist in the first place.
    """
    from xentry import sourcestore

    client, app = _app(tmp_path, monkeypatch, _facts())
    data_dir = tmp_path / "data"
    with client:
        client.get("/")
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        ).json()
        first = client.post(
            "/api/artifacts/approve",
            json={
                "check_id": checked["check_id"],
                "urls": [
                    "https://x.example/one.deb",
                    "https://x.example/two.deb",
                    "https://x.example/three.conf",
                ],
            },
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert first.status_code == 200, first.json()
        assert len(first.json()["files"]) == 3
        second = client.post(
            "/api/artifacts/approve",
            json={"check_id": checked["check_id"], "urls": ["https://x.example/only.deb"]},
            headers={"X-Xentry-CSRF": app.state.token},
        )
        assert second.status_code == 200, second.json()

    held = sorted(
        name
        for name in sourcestore.load(data_dir, checked["check_id"])
        if name.startswith("artifact")
    )
    assert held == ["artifact0"], held


def test_two_placed_files_are_refused_at_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`place` names one kind, so it describes one file. Two would be written
    to the same path and the second would silently win."""
    client, app = _app(tmp_path, monkeypatch, _facts())
    with client:
        client.get("/")
        checked = client.post(
            "/api/links/check",
            json={"cve_url": "https://example.com/cve", "poc_url": POC_REPO},
            headers={"X-Xentry-CSRF": app.state.token},
        ).json()
        refused = client.post(
            "/api/artifacts/approve",
            json={
                "check_id": checked["check_id"],
                "urls": ["https://x.example/a.conf", "https://x.example/b.war"],
            },
            headers={"X-Xentry-CSRF": app.state.token},
        )
    assert refused.status_code == 422, refused.json()
    assert "only one placed file" in refused.json()["detail"]


def test_an_approval_does_not_replace_a_file_from_the_pocs_repository(tmp_path: Path) -> None:
    """Two provenances, and only one of them is the operator's to replace.

    Re-approving drops every "artifact" - that is what makes an approval a set
    rather than an accumulation. A file auto-fetched from the PoC's own
    repository is not part of that set and must survive, or approving a
    second download would silently remove the config the job needs.
    """
    from xentry import sourcestore

    root = tmp_path / "store"
    sourcestore.save(root, "chk", {"cve": _fetched("https://x/cve", b"a"),
                                   "poc": _fetched("https://x/poc", b"b")})
    sourcestore.add(root, "chk", "repo0",
                    _fetched("https://x/000-default.conf", b"<VirtualHost"))
    sourcestore.add(root, "chk", "artifact0", _fetched("https://x/one.deb", b"one"))
    sourcestore.add(root, "chk", "artifact1", _fetched("https://x/two.deb", b"two"))

    assert sourcestore.drop(root, "chk", "artifact") == 2
    back = sourcestore.load(root, "chk")
    assert sorted(k for k in back if k.startswith(("artifact", "repo"))) == ["repo0"]
    assert back["repo0"].body == b"<VirtualHost"


@pytest.mark.parametrize(
    ("place", "packages", "admitted"),
    [
        ("tomcat-webapp", ["tomcat9"], True),
        ("tomcat-webapp", ["tomcat10"], True),
        ("tomcat-webapp", [], False),
        ("tomcat-webapp", ["openjdk-11-jdk"], False),
        ("apache-site", ["apache2"], True),
        ("apache-site", ["nginx"], False),
    ],
)
def test_a_placement_needs_the_package_that_makes_its_directory(
    place: str, packages: list[str], admitted: bool
) -> None:
    """A job died in the guest with "no tomcat webapps directory: is tomcat in
    the package list?" - a question the form could have answered. A placement
    writes into a directory only its service creates, so the pairing is
    checkable at admission and is checked here, on the path where no download
    is on the table.

    WSO2's CVE-2022-29464 lands here: the model answered place "tomcat-webapp"
    with no package, and WSO2 ships its own Tomcat inside a .zip that no distro
    packages - so a placement is the wrong shape for it entirely, and the
    refusal says so rather than only asking for a package that does not exist.
    """
    item = _facts(
        place=place, place_file="x.war", setup_packages=packages,
        setup_units=packages, ports=[8080],
    )
    reason = generic._reason(item, artifact=True)
    assert (reason is None) is admitted, reason
    if not admitted:
        assert "to have a directory to go in" in str(reason), reason
        # And the refusal names the other way out, because a product that
        # ships its own servlet container should not be a placement at all.
        assert "approve the product archive" in str(reason), reason
