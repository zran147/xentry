"""A target for a CVE in an application package, not a distro package.

The derived target installs an Ubuntu package at a version resolved from the
advisory. That covers distro-packaged services and excludes most of what gets
published: an npm package, a Composer library, a gem. Their PoC repositories
usually ship a Docker Compose lab that would build the environment, and this
module deliberately does not run it.

What it reads instead is the lab's ``package.json``. That one file carries the
dependency pins, the build and start commands, and the port - everything the
Dockerfile would have told us except the node version, which the image
provides. So the author's ``RUN`` lines never execute, the version installed is
the version this harness chose, and the commands come from a closed vocabulary
checked here rather than from a shell string.

The vocabulary is the limit, and it is meant to be. ``next build`` and
``next start -p <port>`` are what it admits today. A lab that starts some other
way is refused with no_environment, which is a one-line addition to
``START_COMMANDS`` once someone has decided that framework's start command is
safe to run - not a guess made at job time.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from xentry.models import (
    EvidenceChannel,
    Facts,
    NonceSpec,
    NullActor,
    PocPin,
    ProbeStep,
    Resources,
    Timeouts,
)
from xentry.targets import TargetInstance, _step_sha

ECOSYSTEM_ID = "npm"
MANIFEST_NAME = "package.json"
# The runtime, served by the job's registry mirror and checked in the guest
# against this digest. Ubuntu's own nodejs is 18.19 on noble and a current npm
# advisory needs 20 or later, so no apt package can serve - and an image per
# ecosystem would be 2.3 GB of disk each, forever, for one tarball.
NODE_VERSION = "v22.11.0"
NODE_SHA256 = "83bf07dd343002a26211cf1fcd46a9d9534219aad42ee02847816940bf610a72"
# A directory inside a repository: no leading slash, no traversal, no shell.
APP_DIR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
GITHUB_RAW = "https://raw.githubusercontent.com/"
BASE_IMAGE_ID = "ubuntu-24.04-generic"
NONCE_PATH = "/var/lib/xentry/nonce"
NONCE_MODE = 0o644
APP_DIR = "/srv/app"
# npm's own name rules, plus the scoped form. A version must be exact: a range
# would install whatever is newest, which for a CVE is usually the fix.
PACKAGE_RE = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
# npm's own range syntax, less anything that leaves the registry: no git url,
# no file path, no "latest", no "*".
RANGE_RE = re.compile(r"^[~^]?\d+(\.\d+){0,2}(-[0-9A-Za-z.-]+)?$|^\d+(\.\d+){0,2}\s*-\s*\d+(\.\d+){0,2}$|^[<>]=?\d+(\.\d+){0,2}$")
MAX_DEPENDENCIES = 40
# The closed vocabulary. Each entry maps a script the lab wrote to the argv the
# checked-in step will run, with the port substituted by the harness.
START_COMMANDS = {
    re.compile(r"^next start(?: -p (?P<port>\d{2,5}))?$"): "next-start",
}
BUILD_COMMANDS = {
    re.compile(r"^next build$"): "next-build",
}
DEFAULT_PORTS = {"next-start": 3000}
# The fixed build listens beside the vulnerable one on the same VM. An offset
# rather than a fixed number, so a lab that chose 3000 and a lab that chose
# 8080 each get a free neighbour; both ports are opened to the attacker.
CONTROL_PORT_OFFSET = 1
MAX_PORT = 65535

PROVES = (
    (
        "After the PoC ran, the attacker VM printed a value that exists only in "
        "a file on the target which nothing serves over the network, and the "
        "same wrapper without the exploit did not."
    ),
    (
        "The dependency tree the service loaded matches the lockfile this "
        "harness resolved on the host, whose every tarball was checked against "
        "the digest the registry published."
    ),
)
DOES_NOT_PROVE = (
    (
        "That the application code the PoC repository supplies is a faithful "
        "deployment of the affected software. The app is the PoC author's; only "
        "the package version, the runtime and the commands are this harness's."
    ),
    (
        "That the vulnerability is the reason the PoC succeeded, until the same "
        "stack at the fixed version has been run and failed."
    ),
)
# With a control run the second caveat above is answered, so it is replaced
# rather than left standing next to a claim that contradicts it.
CONTROL_PROVES = (
    "The same PoC, against the same stack on the same VM with only {subject} "
    "moved to {fixed} - the version the advisory says fixes this - did not "
    "produce the value. The readiness step records the version each build "
    "actually resolved to, and they differ only in {subject}."
)
CONTROL_DOES_NOT_PROVE = (
    "That {fixed} is the first fixed version, or that no other change between "
    "the two builds contributes: moving {subject} moves whatever its own "
    "dependency constraints resolve to, and the lockfiles record what moved."
)


def closure_id(subject: str, deps: tuple[tuple[str, str], ...]) -> str:
    """The artifact id for one resolved dependency set.

    Defined here and imported by scripts/pin-npm-closure.py, because two
    definitions of a digest-derived id drift silently: the operator pins one id
    and the job looks up another, and the only symptom is an artifact that is
    somehow never found. The whole set goes into the fingerprint - two labs can
    pin the same subject version and differ in a peer, and those are not the
    same environment.
    """
    specs = sorted(f"{name}@{version}" for name, version in deps)
    fingerprint = hashlib.sha256(" ".join(specs).encode()).hexdigest()[:8]
    version = next(
        (spec for spec in specs if spec.rsplit("@", 1)[0] == subject), subject
    ).replace("@", "-", 1)
    return f"npm-closure-{version.replace('/', '-')}-{fingerprint}"


class NoEnvironment(RuntimeError):
    """The lab cannot be rebuilt from what it declares, so the job must not run."""


@dataclass(frozen=True)
class Environment:
    """What one lab's package.json declares, after validation."""

    dependencies: tuple[tuple[str, str], ...]
    build: str
    start: str
    port: int


def _command(raw: str, table: dict[re.Pattern[str], str], kind: str) -> tuple[str, int | None]:
    if not raw.strip():
        raise NoEnvironment(f"package.json declares no {kind} script")
    for pattern, name in table.items():
        match = pattern.match(raw.strip())
        if match is not None:
            port = match.groupdict().get("port") if match.groupdict() else None
            return name, int(port) if port else None
    raise NoEnvironment(
        f"{kind} command {raw.strip()!r} is not one this harness runs; "
        f"it admits {sorted(table.values())}"
    )


# CAN THIS BE GENERALISED BEYOND npm? YES, AND ONLY FOUR PLACES ARE npm.
#
# The shape here is not about Node. It is: the vulnerable package is a
# DEPENDENCY of some host application, the lab reproduces through that
# application, and a control run reinstalls the closure at the fixed version
# to show the finding moves with it. That applies to pip, composer, cargo, go
# and maven without a change of idea.
#
# What is npm-specific is narrow:
#
#   read_app()        parses package.json - dependencies and scripts.start
#   declared_version()walks that manifest's dependency map
#   manifest_url()    builds a raw URL to package.json inside the PoC repo
#   _command()        maps a start command to the port it listens on
#
# What is already ecosystem-agnostic:
#
#   subject_for()     which package the control moves, read from the app
#   fixed_for()       the fixed version to move it to, from facts
#   control_port_for()the second port the control serves on
#   closure_id()      a digest of the resolved dependency set
#   derive()          everything after Environment is in hand
#
# The serving side is general already: RegistryProxy carries pypi, npm and
# nodejs ecosystems with their own filters and one cutoff rule.
#
# So generalising means an Environment READER per ecosystem - a small
# interface returning {dependencies, start command, port} - and leaving the
# selection logic alone. It is not done here because exactly one CVE has
# needed it (CVE-2026-126187, react reproduced through next), and a second
# reader written against no second example would encode this one's accidents:
# the subject-is-not-the-product rule was only discoverable BECAUSE a real
# advisory named react while the tree carried next. A pip case would tell us
# whether `extras` and environment markers belong in the interface, and
# guessing that now is how the closure id ends up meaning different things in
# different ecosystems.
def read_app(package_json: str) -> Environment:
    """Validate one lab's package.json into an Environment, or refuse.

    Everything here is the lab author's data and none of it reaches a shell: a
    dependency is a name and an exact version, and a script has to match a
    pattern whose result is a step id, not a command line.
    """
    try:
        declared = json.loads(package_json)
    except json.JSONDecodeError as exc:
        raise NoEnvironment(f"package.json does not parse: {exc}") from exc
    if not isinstance(declared, dict):
        raise NoEnvironment("package.json is not an object")

    raw_deps = declared.get("dependencies")
    if not isinstance(raw_deps, dict) or not raw_deps:
        raise NoEnvironment("package.json declares no dependencies to install")
    if len(raw_deps) > MAX_DEPENDENCIES:
        raise NoEnvironment(f"{len(raw_deps)} dependencies is more than this harness installs")
    dependencies = []
    for name, version in sorted(raw_deps.items()):
        if not isinstance(name, str) or not PACKAGE_RE.match(name):
            raise NoEnvironment(f"refused package name: {name!r}")
        if not isinstance(version, str) or not RANGE_RE.match(version):
            # A range is admitted now, and that is the change the registry
            # mirror buys. It used to be refused because a range installed
            # whatever was newest, which for a CVE is usually the fix; against
            # an index that holds only what existed before the advisory, a
            # range resolves to what the lab's author would have got. What is
            # still refused is anything that is not a version at all - a git
            # url, a tarball path, "latest" - because those reach past the
            # mirror to somewhere this job cannot pin.
            raise NoEnvironment(
                f"{name} is declared as {version!r}, which is not a version or range "
                "this harness can resolve against a dated index"
            )
        dependencies.append((name, version))

    scripts = declared.get("scripts")
    if not isinstance(scripts, dict):
        raise NoEnvironment("package.json declares no scripts")
    build, _ = _command(str(scripts.get("build") or ""), BUILD_COMMANDS, "build")
    start, port = _command(str(scripts.get("start") or ""), START_COMMANDS, "start")
    if port is None and start not in DEFAULT_PORTS:
        # Adding to START_COMMANDS without adding here would otherwise be a
        # KeyError at job time rather than a refusal.
        raise NoEnvironment(f"{start} names no port and this harness has no default for it")
    return Environment(
        dependencies=tuple(dependencies),
        build=build,
        start=start,
        port=port or DEFAULT_PORTS[start],
    )


def declared_version(environment: Environment, package: str) -> str:
    """What the lab declared for one package, for the record. Not an assertion.

    Two reasons this is not the version to check an install against. npm
    resolves, so a declared version need not survive: this lab declares react
    19.3.0 and the closure pins 19.3.1, because a constraint inside next wins.
    And the advisory's product need not be in the tree at all - CVE-2026-126187
    is about react-server-dom-webpack, which appears nowhere in the closure
    because next vendors its own copy.

    So the installed tree is compared against the pinned lockfile, in the guest,
    and the question of which version is the affected one is settled by the
    fixed-version control run rather than by a name match here.
    """
    wanted = package.strip().lower()
    for name, version in environment.dependencies:
        if name.lower() == wanted:
            return version
    return ""


def manifest_url(poc_url: str, app_dir: str) -> str:
    """Where the lab's package.json is, in the PoC repository.

    The repository is read at HEAD, the same ref ``stage_poc`` archives, so the
    manifest this resolves against and the source that gets installed are one
    commit. Nothing here is a provenance claim: both are hashed into the
    bundle and the versions that matter are the closure's, not the lab's.
    """
    if not poc_url.startswith("https://github.com/"):
        raise NoEnvironment(f"only github.com PoC repositories can be read: {poc_url}")
    if app_dir and not APP_DIR_RE.match(app_dir):
        raise NoEnvironment(f"refused app_dir: {app_dir!r}")
    slug = poc_url.removeprefix("https://github.com/").rstrip("/").removesuffix(".git")
    if slug.count("/") != 1:
        raise NoEnvironment(f"not a repository url: {poc_url}")
    prefix = f"{app_dir}/" if app_dir else ""
    return f"{GITHUB_RAW}{slug}/HEAD/{prefix}{MANIFEST_NAME}"


def select(facts: Facts, poc_url: str, manifest_text: str) -> tuple[TargetInstance, Environment]:
    """An ecosystem target for this lab, or a refusal.

    Nothing has to be pinned in advance. The lab's own package.json says which
    dependencies it wants and at what ranges; the job's registry mirror decides
    what those ranges mean by serving only what existed before the advisory was
    published. So a pasted CVE runs without an operator resolving anything,
    which a per-lab closure never allowed.
    """
    environment = read_app(manifest_text)
    subject = subject_for(facts, environment)
    fixed = fixed_for(environment, subject, facts.fixed_versions) if subject else ""
    return (
        derive(facts, poc_url, environment, subject=subject, fixed_version=fixed),
        environment,
    )


def _parts(version: str) -> tuple[int, ...]:
    """A version as numbers, ignoring any range operator and prerelease tag."""
    head = version.lstrip("^~<>= ").split("-", 1)[0]
    pieces = []
    for piece in head.split("."):
        if not piece.isdigit():
            break
        pieces.append(int(piece))
    return tuple(pieces)


def fixed_for(environment: Environment, subject: str, candidates: list[str]) -> str:
    """The fix for the branch this lab is on, or "" for no control run.

    An advisory for a maintained library names one fixed version per supported
    branch - CVE-2026-126187 names 19.0.9, 19.1.10, 19.2.9 and 19.3.1 - and
    only one of them is a version *forward* of where the lab sits. The live
    extractor, asked for "the fixed version", returned 19.0.9 against a lab
    declaring 19.3.0: a two-minor downgrade, which would have made the control
    build a different stack rather than the same one one version on, and would
    not have satisfied next's own peer range either.

    So the smallest candidate above what the lab declares wins, and if none is
    above it there is no control run rather than a misleading one.
    """
    declared = _parts(declared_version(environment, subject))
    best = ""
    for candidate in candidates:
        version = candidate.strip()
        if not VERSION_RE.match(version):
            continue
        parts = _parts(version)
        if declared and parts <= declared:
            continue
        if not best or parts < _parts(best):
            best = version
    return best


def subject_for(facts: Facts, environment: Environment) -> str:
    """The package whose version the control run moves, or "" for none.

    The advisory's product, but only when the lab actually declares it. For
    CVE-2026-126187 the product is react, the lab reproduces through next, and
    the affected package - react-server-dom-webpack - is vendored inside next
    and absent from the tree entirely. Where the product is not a declared
    dependency there is no subject, no control run, and a job that says so,
    rather than a guess that moves the wrong package and asserts something
    about a version with nothing to do with the finding.
    """
    product = facts.product.strip().lower()
    for name, _ in environment.dependencies:
        if name.lower() == product:
            return name
    return ""


def control_port_for(port: int) -> int:
    """Where the fixed build listens. Beside the vulnerable one, never on it."""
    control = port + CONTROL_PORT_OFFSET
    if control > MAX_PORT:
        control = port - CONTROL_PORT_OFFSET
    if control < 1 or control == port:
        raise NoEnvironment(f"no control port is available beside {port}")
    return control


def derive(
    facts: Facts,
    poc_url: str,
    environment: Environment,
    subject: str = "",
    fixed_version: str = "",
) -> TargetInstance:
    """A target that installs a pinned npm closure and runs the lab's app.

    ``subject`` is the package whose version the control run will move. It is
    not inferred from the advisory's product: for CVE-2026-126187 that product
    is react, the lab reproduces through next, and the affected package itself
    is vendored inside next and absent from the tree. Guessing would mean
    asserting a version that has nothing to do with the finding.
    """
    if subject and not PACKAGE_RE.match(subject):
        raise NoEnvironment(f"refused subject package: {subject!r}")
    control_port = 0
    proves: tuple[str, ...] = PROVES
    does_not_prove: tuple[str, ...] = DOES_NOT_PROVE
    if fixed_version:
        # A control run with nothing named to compare is not a control: the
        # reader would be told two builds differ without being told how.
        if not subject:
            raise NoEnvironment(
                "a fixed-version control run needs a subject package, and the "
                f"advisory's product is not one this lab declares: {facts.product!r}"
            )
        if not VERSION_RE.match(fixed_version):
            raise NoEnvironment(f"refused fixed version: {fixed_version!r}")
        declared = declared_version(environment, subject)
        if declared == fixed_version:
            raise NoEnvironment(
                f"{subject} is declared at {declared}, which is the fixed version: "
                "the two runs would be the same run"
            )
        control_port = control_port_for(environment.port)
        substitution = {"subject": subject, "fixed": fixed_version}
        proves = (*PROVES, CONTROL_PROVES.format(**substitution))
        does_not_prove = (
            DOES_NOT_PROVE[0],
            CONTROL_DOES_NOT_PROVE.format(**substitution),
        )
    return TargetInstance(
        target_id=ECOSYSTEM_ID,
        cve_ids=(facts.cve_id,),
        poc_context="remote",
        base_image_id=BASE_IMAGE_ID,
        kernel_artifact_id=None,
        resources=Resources(vcpu=4, memory_mb=8192, disk_gb=40),
        attacker_profile_id="attacker-remote",
        network_profile_id="isolated",
        actor_user="xentry-guest",
        setup_step_id="setup-npm",
        setup_script="common/setup-npm.sh",
        readiness_step_id="readiness-npm",
        build_step_id="build-poc-generic",
        invocation_step_id="run-poc-generic",
        null_step_id="null-generic",
        probe_step_id="probe-generic-transcript",
        setup_sha256=_step_sha("setup-npm"),
        # Readiness asserts this exact version is what node loaded, which is the
        # difference between "a service is listening" and "the affected build
        # is listening". The closure bundle is pinned by digest, so the bytes
        # are recorded too.
        # The version is measured in the guest after the mirror resolved it,
        # not asserted from here: a range is admitted now, so what the lab
        # declares need not be what the date admits.
        expected_version="",
        poc=PocPin(
            artifact_id="poc-generic",
            repository=poc_url.rstrip("/").removesuffix(".git"),
            commit="",
            files=[],
            sha256="",
            build_step_id="build-poc-generic",
            invocation_step_id="run-poc-generic",
        ),
        probes=(
            ProbeStep(
                step_id="probe-generic-transcript",
                kind="response_parse",
                decisive=True,
                params={"source": "attacker_transcript"},
                timeout_s=10,
            ),
        ),
        nonce=NonceSpec(path=NONCE_PATH, owner="root", mode=NONCE_MODE),
        null_actor=NullActor(location="attacker", step_id="null-generic"),
        evidence_channel=EvidenceChannel(kind="attacker_transcript", channel="stdout+stderr"),
        target_ports=(
            (environment.port, control_port) if control_port else (environment.port,)
        ),
        poc_archive_guest_path="/var/lib/xentry/artifacts/poc-generic.tar.gz",
        poc_dir="/home/xentry-guest/xentry-poc",
        what_proves=proves,
        what_does_not_prove=does_not_prove,
        timeouts=Timeouts(boot_s=120, provision_s=2400, readiness_s=900, poc_s=900, validate_s=120),
        subject_package=subject,
        fixed_version=fixed_version,
        control_port=control_port,
    )
