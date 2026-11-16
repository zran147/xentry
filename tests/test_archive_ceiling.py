"""The prefix alone admitted the fix. The ceiling is what excludes it."""

from __future__ import annotations

import hashlib
import lzma

from xentry import archive, release
from xentry.fetch import Fetched


def _index(*stanzas: bytes) -> bytes:
    filler = b"".join(
        f"Package: filler{n}\nVersion: {n}.{n}-{n}\nArchitecture: amd64\n\n".encode()
        for n in range(600)
    )
    return lzma.compress(b"".join(stanzas) + filler)


def _server(index: bytes) -> object:
    def fetch_fn(url: str, **_options: object) -> Fetched:
        return Fetched(
            url=url,
            final_url=url,
            status=200,
            headers={},
            body=index,
            text="",
            sha256=hashlib.sha256(index).hexdigest(),
        )

    return fetch_fn


def test_a_fallback_prefix_must_not_admit_the_build_that_fixed_it() -> None:
    """The measured hole: prefix "2.4" is satisfied by apache2 2.4.52.

    CVE-2021-44790 affects 2.4.51 and earlier and was fixed in 2.4.52. When the
    exact prefix finds nothing, version_prefixes falls back to "2.4", and
    jammy's archive carries 2.4.52-1ubuntu4 - the fix. On the prefix alone the
    dated check answered "carries it", so the job would have provisioned a
    patched build and reported that the CVE did not reproduce, which reads
    exactly like a result. resolve() filters its own choice by the ceiling;
    this is the same filter on the archive's answer.
    """
    served = _server(
        _index(b"Package: apache2\nVersion: 2.4.52-1ubuntu4\nArchitecture: amd64\n\n")
    )
    ceiling = release.upper_bound("2.4.51", ["2.4.52"], "2.4")
    assert ceiling == ("2.4.52", False)

    # Without the ceiling this is the false accept.
    assert archive.refusal("apache2", "2.4", "20211219T0Z", "jammy", "ubuntu", served) == ""
    # With it, the refusal names the build and the bound.
    gap = archive.refusal(
        "apache2", "2.4", "20211219T0Z", "jammy", "ubuntu", served, ceiling
    )
    assert "2.4.52-1ubuntu4" in gap
    assert "2.4.52" in gap


def test_the_affected_build_still_passes_under_the_same_ceiling() -> None:
    """The ceiling must not refuse the build the advisory is about.

    A guard that refuses everything would pass the test above and make the
    harness useless, so the affected build is asserted against the identical
    ceiling.
    """
    served = _server(
        _index(b"Package: apache2\nVersion: 2.4.51-2\nArchitecture: amd64\n\n")
    )
    ceiling = release.upper_bound("2.4.51", ["2.4.52"], "2.4")
    assert (
        archive.refusal("apache2", "2.4", "20211219T0Z", "sid", "debian", served, ceiling)
        == ""
    )


def test_no_ceiling_is_still_an_existence_check() -> None:
    """The per-package gate passes no ceiling: it only asks whether a name exists.

    setup_packages entries other than the subject have no version to assert -
    "tomcat" either exists in the dated archive or it does not - so a missing
    ceiling must not start refusing them.
    """
    served = _server(
        _index(b"Package: tomcat9\nVersion: 9.0.43-1\nArchitecture: amd64\n\n")
    )
    assert archive.refusal("tomcat9", "", "20211219T0Z", "sid", "debian", served) == ""
    assert "does not carry tomcat" in archive.refusal(
        "tomcat", "", "20211219T0Z", "sid", "debian", served
    )


def test_the_prefix_is_a_search_key_not_a_claim_about_the_build() -> None:
    """nginx 1.30.1-2 is affected by "1.30.0 before 1.30.2" and was refused.

    version_prefixes yields 1.30.2, 1.30 and 1.30.0 for that range, and the
    affected build starts with neither outer one - the prefix is only what the
    resolver matched on. Requiring it here reported an affected build as not
    affected, and which answer you got depended on which prefix matched first.
    The ceiling is the authority, and it says yes for every prefix.
    """
    served = _server(
        _index(b"Package: nginx\nVersion: 1.30.1-2\nArchitecture: amd64\n\n")
    )
    for prefix in release.version_prefixes("1.30.0 before 1.30.2"):
        ceiling = release.upper_bound("1.30.0 before 1.30.2", ["1.30.1-3"], prefix)
        assert (
            archive.refusal("nginx", prefix, "20260521T0Z", "sid", "debian", served, ceiling)
            == ""
        ), prefix


def test_an_epoch_in_the_bound_does_not_reject_everything() -> None:
    """A bound of 5:7.0.15-2 parsed as version five.

    fixed_versions can carry a Debian version, epoch and all. The version's
    epoch was already stripped; the bound's was not, so every comparison
    against such a bound failed and the whole package was refused.
    """
    served = _server(
        _index(b"Package: redis-server\nVersion: 5:7.0.15-1+b1\nArchitecture: amd64\n\n")
    )
    assert (
        archive.refusal(
            "redis-server", "7.0", "20241006T0Z", "sid", "debian", served,
            ("5:7.0.15-2", False),
        )
        == ""
    )


def test_a_multi_segment_range_asks_every_branch() -> None:
    """redis 7.0.15 sits in the advisory's SECOND branch and was refused.

    ">= 2.6, < 6.2.16; >= 7.0.0, < 7.2.6; >= 7.3.0, < 7.4.1" collapses to one
    bound through upper_bound, so 7.0.15 was compared against 6.2.16. Four
    refusals in one sweep were this shape. The floors matter as much as the
    ceilings: 6.5 is above the first branch and below the second, so no branch
    covers it and it must still be refused.
    """
    affected_range = ">= 2.6, < 6.2.16; >= 7.0.0, < 7.2.6; >= 7.3.0, < 7.4.1"
    ranges = release.segments(affected_range)
    assert len(ranges) == 3, ranges
    for version, affected in (
        (b"5:7.0.15-1+b1", True),
        (b"5:6.2.15-1", True),
        (b"5:6.5.0-1", False),   # the gap between two affected branches
        (b"5:7.2.6-1", False),   # the version that fixed that branch
        (b"5:8.0.6-1", False),
    ):
        served = _server(
            _index(b"Package: redis-server\nVersion: " + version + b"\nArchitecture: amd64\n\n")
        )
        gap = archive.refusal(
            "redis-server", "", "20241006T0Z", "sid", "debian", served, None, ranges
        )
        assert (gap == "") is affected, (version, gap)


def test_a_single_segment_range_keeps_the_old_path() -> None:
    """segments() is empty for one branch, so nothing else changes behaviour.

    The multi-branch test answers only the question upper_bound cannot; every
    existing caller must keep taking the ceiling path it was verified on.
    """
    assert release.segments("1.30.0 before 1.30.2") == ()
    assert release.segments("2.4.51") == ()
    assert release.segments("") == ()


def test_the_extractors_phrasing_of_a_range_is_not_stable() -> None:
    """The same advisory came back with two different separators.

    redis CVE-2024-31449 was extracted as ">= 2.6, < 6.2.16; >= 7.0.0, ..." on
    one check and ">= 2.6, < 6.2.16 and >= 7.0.0, ..." on the next. The first
    version of segments() split on ";" alone, so the second phrasing produced
    NO segments and fell silently back to the single-bound path - which is the
    exact bug the segments were added to fix, reappearing because the input
    was worded differently. A separator the extractor uses and this does not
    is indistinguishable from having no multi-branch support at all.
    """
    both = (
        ">= 2.6, < 6.2.16; >= 7.0.0, < 7.2.6; >= 7.3.0, < 7.4.1",
        ">= 2.6, < 6.2.16 and >= 7.0.0, < 7.2.6 and >= 7.3.0, < 7.4.1",
    )
    for phrasing in both:
        ranges = release.segments(phrasing)
        assert len(ranges) == 3, (phrasing, ranges)
        covered = any(
            release.at_least("7.0.15", low) and release.within("7.0.15", high, inc)
            for low, high, inc in ranges
        )
        assert covered, phrasing
        # And the gap between branches stays out under either phrasing.
        assert not any(
            release.at_least("6.5.0", low) and release.within("6.5.0", high, inc)
            for low, high, inc in ranges
        ), phrasing
    # "and" as ordinary prose must not invent a branch.
    assert release.segments("2.4.49 and earlier") == ()
    assert release.segments("from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85")


def test_a_privesc_poc_that_demands_root_is_refused() -> None:
    """CVE-2026-96512 reached the exploit step, thirteen steps in, to say so.

    Its poc.sh builds its own vulnerable sudoers rule and then tests it:
        [ "$(id -u)" -eq 0 ] || die "run as root - this rewrites /etc/sudoers"
    The exploit inside it is genuinely unprivileged - TZ=XXX24 against an
    expired NOTAFTER rule - but the file as shipped cannot run as the actor,
    and running it as root would prove nothing: root reading a root-only nonce
    is not an escalation.
    """
    from xentry import generic

    for text in (
        '[ "$(id -u)" -eq 0 ] || die "run as root - this rewrites /etc/sudoers"',
        'if [ $EUID -ne 0 ]; then echo "Please run as root"; exit 1; fi',
        "import os\nif os.geteuid() != 0:\n    sys.exit('must be run as root')",
    ):
        assert generic.wants_root(text), text


def test_a_good_privesc_poc_is_not_refused_for_mentioning_root() -> None:
    """Both halves of the signal are needed, and this is why.

    A root-identity check is equally present in a CORRECT privesc PoC - it is
    how one asserts it started unprivileged, and readiness-local.sh does
    exactly that - while the word "root" appears in every line of this subject
    matter. Either signal alone refuses the PoCs the harness most wants.
    """
    from xentry import generic

    for text in (
        '[ "$(id -u)" -ne 0 ] || { echo "already root"; exit 1; }\n./exploit',
        'test "$(id -u)" -ne 0 || { echo "the actor is already root" >&2; exit 1; }',
        "# this gives you a root shell\nprint('spawning root shell')",
        "# escalate to root via the kernel bug\nrun_exploit()",
    ):
        assert not generic.wants_root(text), text


def test_two_files_at_the_root_one_a_readme_names_the_other() -> None:
    """The operator's rule, for a repository that holds nothing else.

    Two files at the root and one of them a README means the other one IS the
    PoC - there is nothing to choose between, which is the only condition under
    which this harness picks a file at all. The canonical-name repair above it
    only matches five known names, and a repository whose script is called
    something else was refused for "naming no file that runs the exploit".

    Counting is of ROOT files, as specified: a repository with a helper
    subfolder and one script at its root still qualifies.
    """
    from xentry.extract import ArtifactText, coerce_facts

    def listing(*names: str) -> ArtifactText:
        body = "\n".join(f"{100 + i} {n}" for i, n in enumerate(names))
        return ArtifactText(
            artifact_id="poc",
            # A body section follows, holding a line that reads exactly like a
            # listing entry - the scoping is what keeps it out.
            text=(
                "README text\n\nrepository files (size path), every subfolder "
                f"included:\n{body}\n\n\n--- x ---\n9999 decoy.py\n"
            ),
            sha256="x",
        )

    def entry(*names: str) -> str | None:
        got = coerce_facts({"ports": [], "protocol": "http"}, [listing(*names)])
        return got.get("poc_entrypoint")

    assert entry("README.md", "grafana_exploit.sh") == "grafana_exploit.sh"
    assert entry("readme.txt", "exp.py") == "exp.py"
    # A helper subfolder does not change the root count.
    assert entry("README.md", "run.sh", "lib/x.py") == "run.sh"
    # Anything that would require a choice is left alone.
    assert entry("README.md", "a.py", "b.py") is None
    assert entry("README.md") is None
    assert entry("a.py", "b.py") is None
    # And the decoy line in the file body is never read as a file name.
    assert entry("README.md", "only.sh") == "only.sh"


def test_a_package_list_makes_a_dockerfile_redundant() -> None:
    """blasty's CVE-2021-41773 was refused for a Dockerfile it never needed.

    The facts came back with setup_packages ['apache2'], place apache-site AND
    dockerfile "" - the repository happens to ship one. derive() picks
    setup-docker whenever a dockerfile is named, so the docker path won over the
    apt path, and the Dockerfile-fetch check then refused the job because
    blasty's Dockerfile runs `apt update`.

    The prompt already asks for the right answer: "if setup_packages can name a
    package that installs it, prefer that". The apt path is strictly better
    here - it is dated, and a Dockerfile is not.
    """
    from xentry.extract import coerce_facts

    got = coerce_facts(
        {"setup_packages": ["apache2"], "dockerfile": "", "place": "apache-site",
         "ports": [80], "protocol": "http"},
        [],
    )
    assert got["dockerfile"] is None
    # A target with no package to install keeps its Dockerfile: there it IS the
    # only description of the vulnerable environment.
    kept = coerce_facts(
        {"setup_packages": [], "dockerfile": "lab", "ports": [8080], "protocol": "http"},
        [],
    )
    assert kept["dockerfile"] == "lab"


def test_a_port_means_something_listens_so_it_is_not_local() -> None:
    """Grafana's CVE-2021-43798 asked for a root relay that cannot exist.

    It is a path-traversal file read over HTTP on port 3000, and the facts came
    back poc_context "local" with ports [3000] and no privesc_shape - so the
    harness demanded a root-handover shape. Nothing listens for a local
    privesc, so a port contradicts the context, and the facts say so themselves.

    Only when no shape is named: a shape is a positive statement about how root
    is handed over, and that judgement stays the model's.
    """
    from xentry.extract import coerce_facts

    fixed = coerce_facts(
        {"setup_packages": ["grafana"], "ports": [3000], "protocol": "http",
         "poc_context": "local"},
        [],
    )
    assert fixed["poc_context"] == "remote"
    for shape in ("stdin-shell", "argv-command"):
        kept = coerce_facts(
            {"setup_packages": ["sudo"], "ports": [1234], "protocol": "local",
             "poc_context": "local", "privesc_shape": shape},
            [],
        )
        assert kept["poc_context"] == "local", shape


def test_a_container_may_apt_install_from_the_dated_archive() -> None:
    """apt is served now; everything else a build might fetch is not.

    The job's apt proxy runs a second listener on port 80 and setup-docker
    passes --add-host for deb.debian.org, security.debian.org and the Ubuntu
    names, so a container's own apt reaches the DATED archive - the image's
    sources.list cannot be rewritten, because `docker build` takes no volume
    flag, so the proxy has to be that host instead.

    A released suite does not even need the expiry override the guest's apt
    gets: measured, bookworm at 20250415 carries no Valid-Until while sid at
    the same serial expired on 21 Apr 2025. That measurement is also the
    correction to entry 52f, which concluded "a Debian base cannot
    apt-install" from sid alone.
    """
    from xentry import generic

    allowed = (
        "FROM debian:bookworm\nRUN apt-get update && apt-get install -y git\n",
        "FROM debian:12\nRUN apt update\n",
        "FROM tomcat:8.0.36-jre8\nCOPY x.war /usr/local/tomcat/webapps/\n",
    )
    for text in allowed:
        assert not generic.docker_refusal(text), text
    # Nothing serves these: apk and yum want archives this proxy does not
    # carry, the registry proxy is not wired into containers, and curl, wget
    # and git clone want the open internet.
    for text in (
        "FROM alpine:3.19\nRUN apk add --no-cache curl\n",
        "FROM centos:7\nRUN yum install -y gcc\n",
        "FROM python:3.11\nRUN pip install requests\n",
        "FROM ubuntu:22.04\nRUN git clone https://github.com/x/y /s\n",
        "FROM ubuntu:22.04\nRUN wget -O /t https://e/x\n",
    ):
        assert generic.docker_refusal(text), text


def test_the_apt_proxy_routes_its_companion_archive() -> None:
    """A bookworm container asks one host:port for /debian AND /debian-security.

    The proxy was single-archive by construction and refused the second prefix,
    which is what entry 52f measured as a 403. The gate does not loosen: a
    request still has to match one of THIS archive's own prefixes, and the
    cache stays keyed per matched name so two archives' identical pool paths
    cannot collide.
    """
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    from broker.aptproxy import ARCHIVES

    routes = {
        name: prefix
        for name, prefix, _base in ARCHIVES["debian"].routes("20250415T0Z")
    }
    assert routes == {"debian": "debian", "debian-security": "debian-security"}
    # Ubuntu needs no companion: archive.ubuntu.com and security.ubuntu.com
    # both serve under /ubuntu, measured in entry 52g.
    assert [n for n, _p, _b in ARCHIVES["ubuntu"].routes("20250415T0Z")] == ["ubuntu"]


def test_a_missed_nonce_reports_what_the_poc_printed() -> None:
    """The transcript survives the failure that needs it most.

    CVE-2021-41773 reached 18 of 19 steps: real_actor exited 0 against an
    apache2 2.4.49-4 whose own changelog carries no fix for it, and the job
    then failed with "the PoC transcript did not contain the nonce" and nothing
    else - because the transcript became evidence on the success path and was
    discarded on this one. exploit_failed, six lines above, had always reported
    its transcript.

    Asserted against the source because the surrounding function needs a
    broker, two VMs and a network; what matters is that neither branch can go
    back to discarding it.
    """
    import pathlib

    text = (
        pathlib.Path(__file__).resolve().parents[1] / "src/xentry/runner.py"
    ).read_text()
    assert "the PoC transcript did not contain the nonce" not in text
    assert "but the nonce is not in " in text
    assert '"(nothing at all)"' in text
    # The local/privesc branch too, where the serial log is the decisive
    # channel. The transcript is shown there as DIAGNOSIS and says so: the
    # verdict stays nonce_not_observed, because a guest attesting about its own
    # escalation is exactly what that channel exists to not rely on.
    assert "not evidence, the guest " in text
    assert text.count("redact(attacker_transcript, self._job.secrets)") == 2


def test_the_fallback_release_must_have_existed_at_the_serial() -> None:
    """A release that did not exist yet has no index to serve.

    The fallback was RELEASES[0] - simply the newest build - so a CVE whose
    advisory names no version got noble at whatever serial its publication
    date gave. CVE-2022-0543's serial is 20220217 and noble released in April
    2024, so the job provisioned, asked the proxy for dists/noble/Release and
    died on a 404 that reads like a broken mirror rather than a wrong choice.

    No table of dates is needed: an Ubuntu version IS its release date, and
    sid is rolling.
    """
    from xentry import release

    # BY SUITE, not by position: RELEASES is ordered by how well each archive
    # can be dated - Debian first - and this test is about release DATES, which
    # is a separate thing. Unpacking positionally made it break the moment the
    # order became a policy.
    by_suite = {item.suite: item for item in release.RELEASES}
    noble, jammy, focal = by_suite["noble"], by_suite["jammy"], by_suite["focal"]
    sid, bionic = by_suite["sid"], by_suite["bionic"]
    early = "20220217T000000Z"
    assert release.existed(focal, early)
    assert release.existed(bionic, early)
    assert release.existed(sid, early)
    assert not release.existed(noble, early)
    # jammy released 2022-04, two months after this serial. The conservative
    # answer is the right one here: its index exists at that serial only
    # because it was in development, and a development suite is not what
    # "the archive as it was" means.
    assert not release.existed(jammy, early)

    # The newest that DID exist, per serial, which is what the fallback is.
    # sid leads the order and has always existed, so it is the fallback at
    # every serial now. That is the point of the reorder: Debian's archive is
    # the one with a complete pocket history, and sid is newer than the
    # bullseye base so apt only ever upgrades.
    for serial, suite in (
        ("20220217T000000Z", "sid"),
        ("20211004T000000Z", "sid"),
        ("20241118T000000Z", "sid"),
        ("20250629T000000Z", "sid"),
    ):
        pick = release.fallback_for(release.RELEASES, serial)
        assert pick is not None and pick.suite == suite, (serial, pick)

    # Below every build, there is nothing to fall back TO, and None is a
    # refusal rather than a release to guess at.
    ubuntu_only = tuple(item for item in release.RELEASES if item.archive == "ubuntu")
    assert release.fallback_for(ubuntu_only, "20150101T000000Z") is None


def test_the_assessment_cannot_overrule_the_runners_measurement() -> None:
    """Both directions, because it only clamped one.

    Two CVE-2021-41773 jobs with identical runner facts - nonce observed,
    control clean, the same probe evidence digest, the same model - came back
    `reproduced` and `inconclusive`. The second carried
    `nonce_observed_but_no_matching_evidence_hash`, a reason_code this codebase
    cannot emit: the model invented it after being asked to find "a hash
    matching nonce_sha256" in a narrative the runner redacts the nonce from.
    """
    from xentry.models import LlmVerdict
    from xentry.validator import RunnerFacts, clamp_verdict

    def facts(**over: object) -> RunnerFacts:
        base = {
            "nonce_observed": True,
            "nonce_id": "real-1",
            "nonce_sha256": "a" * 64,
            "null_actor_observed_nonce": False,
            "version_match": True,
            "precondition_ok": True,
            "vm_ids": ["t", "a"],
            "network_id": "xentry-1",
            "probe_evidence_sha256": "b" * 64,
        }
        base.update(over)
        return RunnerFacts(**base)  # type: ignore[arg-type]

    def said(verdict: str, code: str) -> LlmVerdict:
        return LlmVerdict(
            verdict=verdict, reason_code=code, evidence_refs=[], explanation="because"
        )

    # UP: a measured run cannot be talked down, whatever the model returns.
    for verdict, code in (
        ("inconclusive", "nonce_observed_but_no_matching_evidence_hash"),
        ("not_reproduced", "looked_wrong_to_me"),
        ("inconclusive", ""),
    ):
        got = clamp_verdict(said(verdict, code), facts())
        assert got.verdict == "reproduced", (verdict, got)
        assert got.reason_code == "nonce_observed_with_matching_evidence"
        # The dissent survives, because a model objecting to a clean run is
        # worth reading even when it cannot change the verdict.
        assert verdict in got.explanation and "because" in got.explanation

    # DOWN: unchanged. No measurement, no reproduction.
    got = clamp_verdict(said("reproduced", "x"), facts(nonce_observed=False))
    assert got.verdict == "not_reproduced" and got.reason_code == "nonce_not_observed"
    got = clamp_verdict(said("reproduced", "x"), facts(version_match=False))
    assert got.verdict == "inconclusive" and got.reason_code == "version_unidentified"

    # And the control run is decisive: if the wrapper ALONE produced the nonce,
    # the exploit proved nothing, so nothing is clamped up.
    got = clamp_verdict(said("inconclusive", "c"), facts(null_actor_observed_nonce=True))
    assert got.verdict == "inconclusive" and got.reason_code == "c"
    got = clamp_verdict(said("not_reproduced", "p"), facts(precondition_ok=False))
    assert got.verdict == "not_reproduced" and got.reason_code == "p"

    # A model that already agrees is passed through untouched.
    agreed = said("reproduced", "nonce_observed_with_matching_evidence")
    assert clamp_verdict(agreed, facts()) is agreed


def test_a_command_taking_flag_can_be_told_to_read_the_nonce() -> None:
    """{read_nonce} is a command, where the other three placeholders are values.

    CVE-2022-0543's exploit reached command execution on the target - its own
    output says "Running your command: id" and uid=108(redis) - and the job
    still failed nonce_not_observed, because the extractor copied "-x id" out
    of the README and the harness had no way to ask for the nonce instead.

    "cat <path>" is two words, so it cannot be a token: a space is exactly
    what would let an argv list become a second command. The run step expands
    the placeholder into ONE argv element, so the quoting lives in checked-in
    shell.
    """
    from xentry import generic

    assert generic.tokens(["-x", "{read_nonce}"], "argv") == "-x {read_nonce}"
    assert generic.tokens(
        ["-i", "{ip}", "-p", "{port}", "-x", "{read_nonce}"], "argv"
    ) == "-i {ip} -p {port} -x {read_nonce}"
    # The guarantee the placeholder exists to preserve: no token may carry a
    # space, a quote or a shell operator, so no list of them can become a
    # second command.
    for refused in (
        ["cat {nonce}"],
        ["{read_host}"],
        ["; id"],
        ["$(id)"],
        ["`id`"],
        ["a|b"],
        ["--flag 'x'"],
    ):
        try:
            generic.tokens(refused, "argv")
        except generic.NoObservable:
            continue
        raise AssertionError(f"accepted {refused!r}")

    # The step that expands it is pinned, and the expansion is in shell.
    import pathlib

    script = (
        pathlib.Path(__file__).resolve().parents[1]
        / "targets/common/run-poc-generic.sh"
    ).read_text()
    assert '"{read_nonce}") argv+=("cat $nonce_path") ;;' in script
    # And the extractor is told to prefer it over the README's example.
    extract = (
        pathlib.Path(__file__).resolve().parents[1] / "src/xentry/extract.py"
    ).read_text()
    assert "{read_nonce} as that argument" in extract


def test_a_local_relay_is_never_sent_the_remote_only_params() -> None:
    """poc_args and port belong to run-poc-generic and to nothing else.

    poc_args was set for EVERY derived job while only run-poc-generic declares
    it, so every local PoC reached its final step and died on

        unknown step params: ['poc_args']

    CVE-2025-32463 passed 14 of 15 steps that way - provisioned, readiness
    satisfied, exploit built, control run clean - and failed at real_actor on a
    parameter name. The whole privesc class was blocked by it.

    A local relay has no use for a documented argv anyway: the argument it
    passes is the harness's own command, not one the advisory wrote.
    """
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[1]
    steps = yaml.safe_load((root / "targets/steps.yaml").read_text())["steps"]

    # Only the remote step declares them.
    assert "poc_args" in steps["run-poc-generic"]["params"]
    assert "port" in steps["run-poc-generic"]["params"]
    local = [name for name in steps if name.startswith("run-poc-local-")]
    assert len(local) >= 5, local
    for name in local:
        declared = steps[name]["params"]
        assert "poc_args" not in declared, name
        assert "port" not in declared, name

    # And the runner sends them only under the gate. Both assignments must sit
    # inside the same `poc_context != "local"` block - the bug was poc_args
    # sitting one line ABOVE it.
    runner = (root / "src/xentry/runner.py").read_text()
    gate = runner.index('if target.poc_context != "local":')
    # Wide enough to clear the comment that explains the gate - the first
    # version of this window was 900 chars and stopped short of the assignment
    # it was checking for.
    nearby = runner[gate : gate + 1600]
    assert 'params["poc_args"]' in nearby
    assert 'params["port"] = str(port)' in nearby
    before_gate = runner[:gate]
    assert 'params["poc_args"]' not in before_gate


def test_a_ref_field_that_is_not_a_list_is_repaired() -> None:
    """null means "none", and a lone object means "one" - neither is a refusal.

    The repair loop over the ref-list fields only fixed the ITEMS inside a
    list, so a reply that sent null - or a single object instead of a list of
    one - reached validation and died:

        evidence_insufficient: the reply does not fit the facts schema
        artifact_candidates  Input should be a valid list

    That reads as "the model said nothing useful" when the model said "no
    candidates", and it cost CVE-2025-32463 a check - the retry admitted on
    the same inputs, so it was shape, not substance.

    Nothing here invents a fact, which is the line coerce_facts does not
    cross: an absent list becomes empty, and a lone object becomes a list
    holding it.
    """
    from xentry.extract import REF_LISTS, coerce_facts

    ref = {"artifact_id": "poc", "quote": "x", "line_start": 1, "line_end": 1}
    for key in REF_LISTS:
        assert coerce_facts({key: None}, [])[key] == []
        assert len(coerce_facts({key: ref}, [])[key]) == 1
        assert len(coerce_facts({key: "exploit.py"}, [])[key]) == 1
        assert coerce_facts({key: []}, [])[key] == []
        # A list of two stays a list of two.
        assert len(coerce_facts({key: [ref, ref]}, [])[key]) == 2
