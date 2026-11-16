"""Extractor citation and parsing tests."""

from __future__ import annotations

import hashlib

import pytest

from xentry.extract import ArtifactText, ExtractorError, _parse_json, verify_facts
from xentry.models import EvidenceRef, Facts


def _facts(quote: str) -> Facts:
    text = "CVE-2026-109618\nAffected Versions: PHP 8.4.0 ~ 8.4.26\n"
    sha = hashlib.sha256(text.encode()).hexdigest()
    ref = EvidenceRef(artifact_id="a", sha256=sha, quote=quote, line_start=1, line_end=1)
    return Facts(
        cve_id="CVE-2026-109618",
        product="PHP",
        affected_range="8.4.0 ~ 8.4.26",
        version_evidence=[ref],
        protocol="http",
        ports=[],
        auth_required=False,
        build_strategy="mod_php",
        poc_context="remote",
        citations=[ref],
    )


def test_citation_must_appear_in_artifact() -> None:
    text = "CVE-2026-109618\nAffected Versions: PHP 8.4.0 ~ 8.4.26\n"
    artifact = ArtifactText("a", hashlib.sha256(text.encode()).hexdigest(), text)
    verify_facts(_facts("Affected Versions: PHP 8.4.0 ~ 8.4.26"), [artifact])
    with pytest.raises(ExtractorError) as exc:
        verify_facts(_facts("Affected Versions: PHP 8.4.27"), [artifact])
    assert exc.value.code == "evidence_insufficient"


def test_fenced_json_is_parsed() -> None:
    assert _parse_json('```json\n{"cve_id":"CVE-2026-109618"}\n```')["cve_id"] == "CVE-2026-109618"
    assert _parse_json('prefix {"cve_id":"CVE-2026-109618"} suffix')["cve_id"] == "CVE-2026-109618"
    with pytest.raises(ExtractorError):
        _parse_json("not json at all")


def test_the_prompt_and_the_model_declare_the_same_fields() -> None:
    """Two tables that drift silently.

    A field added to Facts but never described in the prompt is one the model
    is never asked for, so it is always the default and nothing says why. A
    field described but not on the model is dropped on parse. Neither shows up
    as a failure anywhere - the job just quietly behaves as though the field
    did not exist. Seven fields were added to both in one day, which is how
    this got written.

    Both the header list and the per-field bullets are checked, because the
    model reads the bullets for meaning and the header for completeness.
    """
    import re

    from xentry.extract import _prompt
    from xentry.models import Facts

    prompt = _prompt([])
    header = prompt.split("Schema keys:")[1].split(".\n")[0]
    declared = {part for part in re.split(r"[,\s]+", header) if part.isidentifier()}
    bullets = set(re.findall(r"^- ([a-z_]+(?: and [a-z_]+)?):", prompt, re.MULTILINE))
    described: set[str] = set()
    for item in bullets:
        described.update(part.strip() for part in item.split(" and "))

    # Filled in by verify_facts, never by the model.
    model = set(Facts.model_fields) - {"dropped_citations"}
    assert model - declared == set(), f"on Facts but not asked for: {sorted(model - declared)}"
    assert declared - model == set(), f"asked for but not on Facts: {sorted(declared - model)}"
    assert model - described == set(), f"asked for with no description: {sorted(model - described)}"


def test_an_evidence_failure_says_which_citations_failed() -> None:
    """The most common refusal was also the least informative.

    The check endpoint answered `detail=exc.code`, so an operator saw the bare
    word "evidence_insufficient" and the sentence naming the citations that did
    not verify was discarded. verify_facts builds that sentence; this asserts
    it is worth building.
    """
    import pytest

    from xentry.extract import ArtifactText, ExtractorError, verify_facts
    from xentry.models import EvidenceRef, Facts

    artifact = ArtifactText("poc", "b" * 64, "Local file disclosure happens here\n")
    facts = Facts(
        cve_id="CVE-1", product="X", affected_range="1.0",
        # One verified version citation, as every real reply has: the subject
        # here is the dropped NARRATIVE citation, and an unsourced range is
        # refused on its own now.
        version_evidence=[EvidenceRef(artifact_id="poc", quote="Local file disclosure")],
        protocol="http", ports=[80], auth_required=False, build_strategy="",
        poc_context="remote", poc_entrypoint="exploit.py",
        citations=[
            # A genuine fragment: no alphanumeric run at all, which is what the
            # rule is for. "674 Dockerfile" used to fail here on length alone
            # and no longer does - it names a file and a size and a reader can
            # find it.
            EvidenceRef(artifact_id="poc", quote="}`  {}  ["),
        ],
    )
    with pytest.raises(ExtractorError) as caught:
        verify_facts(facts, [artifact])
    assert caught.value.code == "evidence_insufficient"
    # The sentence the endpoint used to drop.
    assert "not something a reader could check" in str(caught.value), str(caught.value)
    assert "0 words" in str(caught.value), str(caught.value)


def test_a_citation_need_not_carry_a_digest_at_all() -> None:
    """The dominant failure in this harness, and it bought nothing.

    Every citation had to echo the artifact's 64-character sha256, and
    version_evidence and artifact_candidates are verified FATALLY - so one
    wrong character in one citation was evidence_insufficient for the whole
    CVE. The harness supplied the artifact and knows its digest; a model
    copying it proves only that it can copy hex. It is filled in now, and the
    record carries the real digest either way.
    """
    from xentry.extract import ArtifactText, verify_facts
    from xentry.models import EvidenceRef, Facts

    quote = "Apache HTTP Server 2.4.49 path traversal allows reading files"
    artifact = ArtifactText("poc", "b" * 64, quote + "\n")

    def facts(sha: str) -> Facts:
        return Facts(
            cve_id="CVE-2021-41773", product="Apache", affected_range="2.4.49",
            version_evidence=[EvidenceRef(artifact_id="poc", sha256=sha, quote=quote)],
            protocol="http", ports=[80], auth_required=False, build_strategy="",
            poc_context="remote", poc_entrypoint="exploit.py",
            citations=[EvidenceRef(artifact_id="poc", quote=quote)],
        )

    for label, sha in (("omitted", ""), ("one char wrong", "b" * 63 + "c"),
                       ("right", "b" * 64)):
        item = facts(sha)
        verify_facts(item, [artifact])
        assert item.version_evidence[0].sha256 == "b" * 64, label
        assert item.citations[0].sha256 == "b" * 64, label


@pytest.mark.parametrize(
    ("quote", "accepted"),
    [
        # Every one of these was refused on length alone, each on a different
        # CVE, and each is precise and verifiable evidence.
        ("FROM httpd:2.4.50", True),
        ('- "1234:8080"', True),
        ("674 Dockerfile", True),
        ("./cve-2021-4034", True),
        ("- 3000:3000", True),
        ("1100 README.md", True),
        ("import redis", True),
        # Ten characters, and it names the port samba's PoC connects to. This
        # is why the floor is 8 and not 12.
        ("port = 445", True),
        # What the floor was really for.
        ("}`", False),
        ("[", False),
        ("{\"a\":", False),
        # One alphanumeric run is a token, not a quote a reader can locate.
        ("1234", False),
        ("            ", False),
    ],
)
def test_a_citation_is_judged_by_structure_not_length(quote: str, accepted: bool) -> None:
    """The length floor was a blunt proxy and it rejected good evidence.

    `FROM httpd:2.4.50` is the best possible proof of an affected version and
    it is seventeen characters. Putting the PoC's source files in the artifact
    gave the model better things to cite than the gate would accept, and
    version_evidence is verified fatally - so the harness's own improvement
    became its commonest refusal.
    """
    import pytest as _pytest

    from xentry.extract import ArtifactText, ExtractorError, verify_facts
    from xentry.models import EvidenceRef, Facts

    text = f"line one\n{quote}\nlast line of the artifact here\n"
    artifact = ArtifactText("poc", "d" * 64, text)
    facts = Facts(
        cve_id="CVE-1", product="x", affected_range="1.0",
        version_evidence=[EvidenceRef(artifact_id="poc", quote=quote)],
        protocol="http", ports=[80], auth_required=False, build_strategy="",
        poc_context="remote", poc_entrypoint="exploit.py",
        citations=[EvidenceRef(artifact_id="poc", quote=quote)],
    )
    if accepted:
        verify_facts(facts, [artifact])
        assert facts.citations and facts.citations[0].quote == quote
    else:
        with _pytest.raises(ExtractorError):
            verify_facts(facts, [artifact])


def test_a_reply_that_is_right_but_shaped_wrong_is_repaired() -> None:
    """Both failures the operator hit on the Apache and Grafana CVEs.

    `poc_command: "curl ..."` instead of an evidence-ref object, and a missing
    `poc_context`, each killed the whole extraction - and were reported as
    `provider_unavailable`, which sends the reader to look at the network when
    the provider answered perfectly well. Neither repair invents anything: the
    quote still has to be present in the artifact or the ref is dropped, and
    the context is read off the protocol the model itself gave.
    """
    from xentry.extract import ArtifactText, coerce_facts
    from xentry.models import Facts

    curl = 'curl -s --path-as-is "http://h:8080/icons/.%2e/etc/passwd"'
    cve = ArtifactText("cve", "a" * 64, "Apache 2.4.49 path traversal\n")
    poc = ArtifactText("poc", "b" * 64, f"Run it:\n$ {curl}\n")
    payload = {
        "cve_id": "CVE-2021-41773",
        "product": "Apache",
        "affected_range": "2.4.49",
        # A bare string, and from the CVE artifact rather than the PoC.
        "version_evidence": ["Apache 2.4.49 path traversal"],
        "protocol": "http",
        "ports": [80],
        "auth_required": False,
        "build_strategy": "",
        # poc_context omitted entirely, exactly as the Grafana reply omitted it.
        "poc_command": curl,
        "poc_command_target": "h:8080",
        "poc_command_read": "/etc/passwd",
        "citations": ["Apache 2.4.49 path traversal"],
    }
    facts = Facts.model_validate(coerce_facts(payload, [cve, poc]))
    assert facts.poc_context == "remote"
    assert facts.poc_command is not None and facts.poc_command.quote == curl
    # The artifact each quote came from is a lookup, not a guess: the one whose
    # text contains it.
    assert facts.poc_command.artifact_id == "poc"
    assert facts.version_evidence[0].artifact_id == "cve"


def test_a_bare_refusal_code_is_not_passed_off_as_a_message() -> None:
    """`{"error": "evidence_insufficient"}` arrived as "evidence_insufficient:
    extractor reported insufficient evidence" - the harness's own words, saying
    nothing, and a reply that DID explain itself had its explanation turned
    into a reason code."""
    import pytest as _pytest

    from xentry.extract import ExtractorError, _parse_json

    with _pytest.raises(ExtractorError) as bare:
        _parse_json('{"error": "evidence_insufficient"}')
    assert bare.value.code == "evidence_insufficient"
    assert "gave no reason" in str(bare.value)
    assert "this check's log" in str(bare.value)

    with _pytest.raises(ExtractorError) as spoken:
        _parse_json('{"error": "the README names no version at all"}')
    assert spoken.value.code == "evidence_insufficient"
    assert "the README names no version at all" in str(spoken.value)


def test_an_application_protocol_is_a_tcp_service() -> None:
    """"smtp" killed the whole reply for exim CVE-2019-10149.

    `protocol` is a Literal of what the harness can DO - open an HTTP port, an
    HTTPS port, a TCP port, or nothing - and a model naming the application
    protocol is not wrong about the CVE. http and https stay distinct because
    they are the only two with a standard port the harness supplies.
    """
    from xentry.extract import ArtifactText, coerce_facts

    artifacts = [ArtifactText("poc", "c" * 64, "exim 4.87 to 4.91\n")]
    for named, wanted in (
        ("smtp", "tcp"),
        ("ssh", "tcp"),
        ("ajp", "tcp"),
        ("LDAP", "tcp"),
        ("http", "http"),
        ("https", "https"),
        ("tcp", "tcp"),
        ("local", "local"),
    ):
        got = coerce_facts({"protocol": named}, artifacts)
        assert got["protocol"] == wanted, named


def test_an_over_long_artifact_keeps_its_listing_and_its_sources() -> None:
    """Head-only truncation threw away the authoritative part.

    The harness appends the repository listing and the PoC's own source files
    to the END of the PoC artifact. For CVE-2022-29464 the listing begins at
    character 24,186 of a 25,365-character artifact, so with a 12,000
    character head the model was told "the listing is AUTHORITATIVE about
    which files exist" and then handed no listing. It answered
    poc_entrypoint: null for a repository whose single file is exploit.py.
    """
    from xentry.extract import MAX_ARTIFACT_CHARS, ArtifactText, _prompt

    readme = "a long writeup paragraph.\n" * 1200
    tail = (
        "\n\nrepository files (size path), every subfolder included:\n"
        "1070 exploit.py\n\n--- exploit.py ---\nimport requests\nPORT = 2222\n"
    )
    text = readme + tail
    assert len(text) > MAX_ARTIFACT_CHARS
    prompt = _prompt([ArtifactText("poc", "d" * 64, text)])
    assert "1070 exploit.py" in prompt
    assert "--- exploit.py ---" in prompt
    assert "PORT = 2222" in prompt
    # The README's opening survives too - that is where a usage line is.
    assert "a long writeup paragraph." in prompt
    assert "middle of this artifact omitted" in prompt


def test_nvd_fix_boundaries_are_read_from_the_record() -> None:
    """Dirty Pipe resolved to a patched kernel because of what was missing.

    The CNA record states "Linux Kernel 5.17 rc6" as an AFFECTED version and
    the model copied it faithfully, with fixed_versions empty. NVD's record
    carries the three stable releases that actually fixed it - and those lines
    sit in the middle of a 17,822-character record, past the prompt's
    truncation, so asking the model for them asks for what it may never have
    seen. They are read from the whole artifact instead, and only when the
    model named none.
    """
    from xentry.extract import ArtifactText, coerce_facts

    nvd = ArtifactText(
        "nvd",
        "e" * 64,
        "vulnerabilities[0].cve.id: CVE-2022-0847\n"
        "...cpeMatch[0].versionStartIncluding: 5.8\n"
        "...cpeMatch[0].versionEndExcluding: 5.10.102\n"
        "...cpeMatch[1].versionEndExcluding: 5.15.25\n"
        "...cpeMatch[2].versionEndExcluding: 5.16.11\n"
        # Another vendor's product in the same record, and the last AFFECTED
        # version rather than a fix - which must not be read as one.
        "...configurations[15].nodes[0].cpeMatch[0].versionEndIncluding: 12.4.2-02044\n",
    )
    got = coerce_facts({"affected_range": "Linux Kernel 5.17 rc6"}, [nvd])
    assert got["fixed_versions"] == ["5.10.102", "5.15.25", "5.16.11"]
    assert "12.4.2-02044" not in got["fixed_versions"]

    # The model's own answer wins when it gave one.
    kept = coerce_facts({"fixed_versions": ["5.16.11"]}, [nvd])
    assert kept["fixed_versions"] == ["5.16.11"]
    # And a record with no such lines leaves the field alone.
    bare = ArtifactText("cve", "f" * 64, "no cpe data here\n")
    assert coerce_facts({"affected_range": "all"}, [bare]).get("fixed_versions") in (
        None,
        [],
    )


def test_the_listing_names_the_entrypoint_when_the_model_does_not() -> None:
    """CVE-2021-44228 was refused for having "no file that runs the exploit".

    kozmer/log4j-shell-poc holds exactly one - `4208 poc.py` in its listing -
    and the reply came back with poc_entrypoint null. This is a lookup in
    evidence the harness fetched, not a guess: the listing is part of the PoC
    artifact. Exactly one match, or nothing, because two candidates would mean
    choosing and choosing is what the harness does not do.
    """
    from xentry.extract import ArtifactText, coerce_facts

    listing = (
        "Run poc.py as described below.\n\n"
        "repository files (size path), every subfolder included:\n"
        "177 Dockerfile\n"
        "3051 README.md\n"
        "4208 poc.py\n"
        "1836540 target/log4shell-1.0-SNAPSHOT.war\n"
    )
    poc = ArtifactText("poc", "a" * 64, listing)
    assert coerce_facts({}, [poc])["poc_entrypoint"] == "poc.py"

    # The model's own answer always wins.
    assert coerce_facts({"poc_entrypoint": "run.py"}, [poc])["poc_entrypoint"] == "run.py"
    # And a command-only PoC is not given an entrypoint it does not want.
    commanded = coerce_facts({"poc_command": {"artifact_id": "poc", "quote": "curl x"}}, [poc])
    assert commanded.get("poc_entrypoint") is None

    # Two candidates: nothing, because that would be a choice.
    both = ArtifactText(
        "poc", "b" * 64,
        "repository files (size path), every subfolder included:\n"
        "100 poc.py\n200 exploit.py\n",
    )
    assert coerce_facts({}, [both]).get("poc_entrypoint") is None
    # A name in a subfolder is not the root script this rule is about.
    nested = ArtifactText(
        "poc", "c" * 64,
        "repository files (size path), every subfolder included:\n300 tools/poc.py\n",
    )
    assert coerce_facts({}, [nested]).get("poc_entrypoint") is None
