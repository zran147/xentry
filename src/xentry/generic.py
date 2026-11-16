"""A target derived from extracted facts, for a CVE nobody wired by hand.

The three checked-in TargetInstances each carry a bespoke observation: a file
the PHP worker serves, a response GitLab writes back, a root shell on a serial
console. That design work is what admitting a new CVE normally costs. This
module admits the one shape that needs none of it.

The observation is the attacker's own transcript. The broker places a nonce on
the target at a path nothing serves over the network; the null actor runs the
PoC wrapper without the exploit and must not print it; the real actor runs the
exploit and must. So the claim is "the PoC obtained read access on the target",
which is honest, checkable, and the same for every remote PoC - at the cost of
being attested by the attacker rather than observed on the target, which is why
a generic job's authority is guest_attested and never runner_observed.

Anything that needs a different observation is refused with no_observable
rather than guessed at.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

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
from xentry.release import RELEASES, Release, Resolution
from xentry.targets import TargetInstance, _step_sha

GENERIC_ID = "generic"
# Checked here as well as in the scripts. The step layer is the boundary that
# matters, but a bad token should be refused before the broker is asked to run
# anything with it, and the reason should reach the job page.
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(=[A-Za-z0-9+.:~-]+)?$")
UNIT_RE = re.compile(r"^[A-Za-z0-9@._-]+$")
# A bare filename: no slash, so it cannot be a path, and no "." or ".." alone.
LAUNCH_RE = re.compile(r"^(?!\.\.?$)[A-Za-z0-9._-]+$")
# Parentheses and the rest are in real PoC filenames - GitHub happily holds
# "Apache_APISIX_RCE(CVE-2022-24112).py", and refusing it refused the CVE. Safe
# because broker/runtime.py shlex.quotes every step parameter and every script
# reads the entrypoint as "./$entrypoint", so these are argv bytes and never
# shell syntax. Traversal is refused separately, before any trimming.
ENTRYPOINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/()+,@%=~-]*$")
MAX_TOKENS = 40
# The experimental pipeline writes its PoC to this name, so the entrypoint is
# the harness's own rather than one the advisory named.
AUTHORED_ENTRYPOINT = "exploit.py"
# Its own minimal image, not php2shell's. That one bakes Apache and the PHP
# build chain, which has nothing to do with an arbitrary CVE and could satisfy
# a dependency by accident - making a reproduction depend on packages that
# appear in no record. SUITE must name the release BASE_IMAGE_ID was built
# from, because setup-generic points apt at <suite>, -updates and -security.
#
# These two are a PAIR and a test asserts they agree, because setup-generic
# points apt at <suite>: a default naming one release with a suite from another
# would aim apt at an archive that image cannot install from. They are NOT tied
# to whichever release is ordered first - nothing reads them to choose a
# release, and the release a job runs on comes from resolve() or the fallback.
BASE_IMAGE_ID = "ubuntu-24.04-generic"
# The archive ships the fixed version, so installing from today's snapshot
# usually installs something that is not vulnerable. The serial is the lever:
# one from just before the advisory went out resolves to the build that was
# current while the flaw was still public-unknown.
#
# The date is parsed from the advisory itself, not taken from the extractor.
# It decides which packages a target is built from, so a model that read the
# wrong line would quietly change what the job reproduces.
SNAPSHOT_LEAD_DAYS = 1
# snapshot.ubuntu.com starts in 2023; before that there is nothing to serve.
# The earliest date ANY archive can serve, not Ubuntu's. This was
# snapshot.ubuntu.com's 2023 floor, which silently voided the whole point of
# the Debian archive: CVE-2021-41773 is published 2021-10-05, the serial it
# needs is 20211004, and this returned "" for it - so the job would have
# provisioned from the broker's default and installed a patched Apache. The
# per-archive floor is the broker's to enforce, and aptproxy.ARCHIVES already
# does, refusing a serial the chosen archive cannot serve.
SNAPSHOT_FLOOR = datetime(2021, 8, 1, tzinfo=UTC)
SUITE = "noble"
NONCE_PATH = "/var/lib/xentry/nonce"
# World-readable on purpose, and root-owned. The control runs on the attacker,
# so it reaches the target only over the network, where nothing serves this
# file; any code or arbitrary read on the target can see it. That makes the
# observation mean "the PoC got read access", with no guess about which user
# the vulnerable service runs as - a guess that would silently turn a real
# reproduction into a failed probe.
NONCE_MODE = 0o644
# A local job needs the opposite: a secret only root can read, so that reading
# it IS the privilege. /root is unreadable to xentry-guest whatever the file
# mode, and the mode says so a second time.
NONCE_PATH_LOCAL = "/root/xentry-nonce"
NONCE_MODE_LOCAL = 0o600
# How a local PoC accepts the command that carries the proof out, and the
# checked-in script for each. The harness must not guess: a relay handed to an
# exploit in a shape it does not accept is silently ignored, and the job then
# reports no observation for a CVE that reproduces perfectly.
# A kernel CVE cannot be reproduced on this path. Installing a linux-image
# .deb does not change the RUNNING kernel - only a reboot does, and this path
# has no reboot step (the checked-in dirtyfrag target is the one that does).
# Without this guard an approved kernel .deb installs, the VM keeps running
# the image's own kernel, readiness has no uname assertion to catch it, and
# the job reports a result about a kernel that was never booted.
KERNEL_NAMES = ("linux-image", "linux-modules", "linux-headers", "linux-generic")
PRIVESC_STEPS = {
    "stdin-shell": "run-poc-local-stdin",
    "argv-command": "run-poc-local-argv",
    # The PoC hands the caller no way to run anything: it embeds the command
    # root will execute, so the relay is substituted into its own text.
    "fixed-command": "run-poc-local-patch",
    # A real terminal, for a PoC that calls isatty() or runs an interactive
    # program: piping into it does nothing at all.
    "pty-shell": "run-poc-local-pty",
    # The exploit returns having left a setuid-root binary; running THAT runs
    # as root, and the step finds it by what appeared rather than being told.
    "setuid-drop": "run-poc-local-setuid",
    # A helper has to be running before the exploit works - CVE-2023-0386
    # needs a FUSE mount up first - so poc_command quotes that first line.
    "two-stage": "run-poc-local-stage",
}
# The shapes whose relay needs a command quoted from the artifact.
QUOTED_SHAPES = frozenset({"fixed-command", "two-stage"})
# The toolchain, for a local job only. Most privesc PoCs are C, the generic
# image carries ca-certificates, curl and a keyring, and there is no network
# in the guest - so without this every C exploit fails at the build step. It
# is a provisioning default like DEFAULT_PORTS, installed from the same dated
# serial as everything else and visible in the step's own parameters; it is
# not a claim about the vulnerability.
LOCAL_TOOLCHAIN = ("build-essential",)
MAX_PORTS = 8

# Module constants, not just arguments to derive(), because the audit page has
# to show them for a finished job and cannot re-derive the facts.
# Appended when the version could not be asserted because the advisory named
# none. The build is still the one the serial carries - one day before
# publication - but "the affected version was installed" is not something this
# job can claim, and readiness skipped its own check too.
DATED_CAVEAT = (
    "That the installed version is an affected one. The advisory named no "
    "version to match, so the build is whatever the archive carried one day "
    "before the advisory was published, and readiness asserted no version."
)
PROVES_LOCAL = (
    (
        "After the pinned PoC ran, the host's serial log for this VM carried a "
        "value that only root could read from /root/xentry-nonce. The guest "
        "actor is xentry-guest, with no sudo and no supplementary groups, and "
        "/dev/ttyS0 is root:dialout 0660 - readiness asserts it is not "
        "writable before the exploit runs - so neither reading the file nor "
        "writing the console was available to the actor beforehand."
    ),
    (
        "The null run did both with no exploit and was denied both, and its "
        "nonce never reached the serial log."
    ),
)
DOES_NOT_PROVE_LOCAL = (
    (
        "That the escalation is unforgeable. Once a kernel exploit succeeds, "
        "nothing inside that guest is trustworthy, including the console "
        "write; the authority stays guest_attested+llm_assessed. What the "
        "runner observed is that a value appeared on a host-side channel the "
        "unprivileged actor could not reach."
    ),
    (
        "Which user or capability the exploit obtained beyond reading that "
        "file and writing that device."
    ),
)
PROVES = (
    (
        "After the pinned PoC ran, the attacker VM printed a value that exists "
        "only in a file on the target which nothing serves over the network, and "
        "the same wrapper without the exploit did not."
    ),
)
DOES_NOT_PROVE = (
    (
        "Nothing about which user the PoC ran as on the target, nor that the "
        "installed version is the affected one: no version was checked against "
        "the advisory."
    ),
    (
        "The value is attested by the attacker, not observed on the target, so a "
        "PoC that fabricated it would look the same. The authority field says "
        "guest_attested for this reason."
    ),
    (
        "This target was derived from extracted facts rather than checked in, so "
        "no human reviewed its setup, its readiness check or its evidence design."
    ),
)


# How a downloaded file can be installed. The verb is a property of the file,
# not a choice the operator makes: a .deb has one install and a tarball has
# one, and asking a person to pick between them only creates a way to be
# wrong. A type with no entry here is refused at approval time rather than
# attempted - a vendor's interactive installer is arbitrary code, and running
# it is the thing this program does not do.
INSTALL_VERBS = {
    ".deb": "deb",
    ".tar.gz": "tarball",
    ".tgz": "tarball",
    ".tar.xz": "tarball",
    ".tar.bz2": "tarball",
    # A zip is a tarball in another container and unzip is as inert as tar.
    # It matters because it is what several products ship: wso2is-5.11.0.zip
    # unpacks to a directory with bin/wso2server.sh in it, the same shape as
    # Confluence's tar.gz. What is still refused is an installer that has to
    # be *run* - a .exe, a .bin, a .sh wrapper - whatever it is packed in.
    ".zip": "zip",
    # Placed, not unpacked. A config or a web archive is one file that belongs
    # at one path, and `place` says which path by naming its kind. Both are as
    # inert as a tarball: nothing here runs them, the service that reads them
    # does. This is what reaches a CVE whose stock package is not vulnerable
    # until it is configured, and one whose vulnerable application is shipped
    # already built - kozmer's target/log4shell-1.0-SNAPSHOT.war.
    ".conf": "file",
    ".war": "file",
}

# Where a placed file goes, by kind. The paths live in setup-generic.sh; this
# is the closed set the extractor may choose from, and the script refuses
# anything else.
# A PyPI distribution name, which is not an apt one: PEP 503 allows letters,
# digits, ., - and _ in any case, so `zope.interface` and `Flask` are valid
# where PACKAGE_RE refuses both. No slash, no space, no colon - this reaches a
# pip command line, and the proxy is a reverse proxy serving one fixed path
# shape, so a name that tried to be a URL would be refused there too.
PIP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# One token of a PoC's documented invocation: a flag, a placeholder, or a
# plain value. Three positionals are this harness's own convention and a PoC
# with named flags cannot be driven by it - kozmer/log4j-shell-poc answered
# "unrecognized arguments: 10.42.1.10 8080 /var/lib/xentry/nonce" against its
# own "usage: poc.py [--userip userip] [--webport webport] [--lport lport]".
# No space, quote or shell metacharacter, so a list of these cannot become a
# second command; the step validates every token again before using it.
# {read_nonce} is the fourth placeholder and the only one that is a COMMAND
# rather than a value. A PoC whose flag takes a path wants {nonce}; one whose
# flag takes a command to run - redis's "-x", and every -c/--cmd/--exec shape -
# needs "cat <path>", which is two words and so cannot be a token here: a
# space is exactly what would let a token list become a second command. The
# run step expands this one into a single argv element instead, so the quoting
# lives in checked-in shell and the model still supplies no spaces.
#
# CVE-2022-0543 is why. Its exploit reached command execution on the target -
# "Running your command: id" / uid=108(redis) - and the job still failed
# nonce_not_observed, because the extractor copied "-x id" out of the README
# and nothing could ask it to read the nonce instead.
ARGV_RE = re.compile(
    r"^(\{(ip|port|nonce|read_nonce)\}"
    r"|-{1,2}[A-Za-z0-9][A-Za-z0-9-]*|[A-Za-z0-9][A-Za-z0-9._/:=-]*)$"
)
# A RUN line that fetches from the network. The OCI mirror serves any Docker
# Hub repository now, because an image the build does not add to is accounted
# for by its own digest - but a build that INSTALLS undated software is the
# case ADR 34c was really about, and the guest has no route to a registry or an
# archive other than this job's dated proxies. docker build takes no volume
# flag and reads the container's own sources.list, so there is no way to point
# it at them.
#
# Measured: CVE-2025-32433's Dockerfile is FROM debian:bookworm and runs
# apt-get install, and died after seven steps and a container build on
# "Temporary failure resolving 'deb.debian.org'". That is knowable from the
# Dockerfile text at the check.
DOCKER_FETCH = re.compile(
    # [ \t]* and not \s*: \s matches a newline, so a match could START on the
    # blank line above the RUN and the quoted line came back EMPTY - the
    # operator saw "The line is:" with nothing after it.
    # apt and apt-get are NOT here any more: the job's apt proxy now runs a
    # second listener on port 80 and setup-docker passes --add-host for
    # deb.debian.org, security.debian.org and the Ubuntu names, so a
    # container's apt reaches the DATED archive. A released suite's Release
    # carries no Valid-Until - measured, bookworm at 20250415 has none while
    # sid at the same serial expired on 21 Apr 2025 - so it does not even need
    # the expiry override the guest's own apt gets.
    #
    # Everything else stays refused, because nothing serves it: apk, yum and
    # friends want archives this proxy does not carry, the registry proxy is
    # not wired into containers, and curl, wget and git clone want the open
    # internet.
    r"^[ \t]*RUN\b[^\n]*?\b("
    r"apk|yum|dnf|zypper|pacman"
    r"|pip|pip3|npm|yarn|gem|go\s+get|cargo|composer"
    r"|curl|wget|git\s+clone"
    r")\b",
    re.IGNORECASE | re.MULTILINE,
)


def docker_refusal(text: str) -> str:
    """"" when this Dockerfile can be built offline, else why it cannot."""
    hit = DOCKER_FETCH.search(text or "")
    if not hit:
        return ""
    line = (text or "")[hit.start():].splitlines()[0].strip()
    return (
        "this PoC's Dockerfile fetches from the network at build time and the "
        "guest has no route to one; `docker build` reads the container's own "
        f"sources.list, not this job's proxies. The line is: {line[:120]}"
    )


PLACEMENTS = frozenset({"apache-site", "nginx-site", "tomcat-webapp"})
# A placement writes into a directory that only exists once its service is
# installed, so each kind needs a package to have put it there. Checked at
# admission because the alternative is what happened: a job provisioned,
# placed nothing, and died in the guest with "no tomcat webapps directory: is
# tomcat in the package list?" - a question the form could have answered.
PLACEMENT_NEEDS = {
    "apache-site": "apache2",
    # CVE-2019-11043 is nginx in front of php-fpm, and the model picked
    # apache-site for it because that was the closest kind on offer. A
    # vocabulary that is too small does not produce a refusal, it produces
    # a wrong answer.
    "nginx-site": "nginx",
    "tomcat-webapp": "tomcat",
}


# A config and a package and a runtime is three; more than this is a product
# being assembled by hand, which is the thing the archives are for.
MAX_APPROVED = 6
# The name the file takes inside the guest. Its SUFFIX decides the install, so
# the name has to survive, and a name is all it may be: the step resolves it
# under one directory and never as a path.
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def artifact_name(filename: str) -> str:
    """The guest-side name for an approved file, or refuse to invent one."""
    name = filename.strip()
    if not ARTIFACT_NAME_RE.match(name) or ".." in name or len(name) > 128:
        raise NoObservable(f"refused artifact filename: {filename!r}")
    return name


def install_verb(filename: str) -> str:
    """The install this harness knows for that file, or refuse to guess."""
    name = filename.strip().lower()
    for suffix, verb in sorted(INSTALL_VERBS.items(), key=lambda item: -len(item[0])):
        if name.endswith(suffix):
            return verb
    raise NoObservable(
        f"this harness has no install for {filename!r}: it can unpack a tarball "
        "or a zip and install a .deb, and nothing else. An installer that has to "
        "be run is arbitrary code, which is the one thing a provisioning step "
        "here never does"
    )


class NoObservable(RuntimeError):
    """No evidence design fits these facts, so the job must not pretend to run."""


# An HTTP advisory almost never names a port: "unauthenticated RCE in <web app>"
# states the protocol and leaves the port to whatever the deployment chose. The
# standard port for the protocol is a provisioning default like setup_packages,
# not a claim about the vulnerability - the extractor still never invents one,
# and the transcript shows the harness supplied it. A PoC that needs a different
# port says so, and that port wins.
DEFAULT_PORTS = {"http": 80, "https": 443}


def ports_for(facts: Facts) -> tuple[int, ...]:
    if facts.ports:
        return tuple(dict.fromkeys(facts.ports))
    default = DEFAULT_PORTS.get(facts.protocol or "")
    return () if default is None else (default,)


def is_kernel(facts: Facts) -> bool:
    """Does provisioning this CVE replace the running kernel?"""
    return any(
        name.startswith(KERNEL_NAMES) for name in facts.setup_packages
    ) or "linux kernel" in facts.product.lower()


def is_local(facts: Facts) -> bool:
    """A local PoC with a shape the harness has a relay for."""
    return facts.poc_context == "local" and facts.privesc_shape in PRIVESC_STEPS


# A privesc PoC that demands root to run. Two signals together, because
# either alone is wrong: a root-identity check is equally present in a GOOD
# privesc PoC - readiness-local.sh itself asserts the actor is NOT root - and
# the word "root" is in every line of this subject matter. What distinguishes
# them is a check PLUS a sentence telling the caller to be root.
#
# Measured on CVE-2026-96512, whose poc.sh is
#   [ "$(id -u)" -eq 0 ] || die "run as root - this rewrites /etc/sudoers"
# because it builds its own vulnerable sudoers rule and then tests it. The
# exploit inside it IS an unprivileged one, but the file as shipped cannot run
# as the actor, and running it as root would prove nothing: root reading a
# root-only nonce is not an escalation.
ROOT_CHECK = re.compile(r"\b(id -u|EUID|geteuid)\b")
ROOT_DEMAND = re.compile(
    r"(run|runs|execute|must be|needs?|requires?|please run)\s+"
    r"(it |this |the script )?(as |with )?root\b",
    re.IGNORECASE,
)


def wants_root(poc_text: str) -> bool:
    """Does this PoC refuse to run as anyone but root?"""
    return bool(ROOT_CHECK.search(poc_text) and ROOT_DEMAND.search(poc_text))


def _reason(facts: Facts, *, artifact: bool = False) -> str | None:
    local = facts.poc_context == "local"
    if local and not is_local(facts):
        # The channel is not the problem - every VM has a serial console wired
        # to a host file the guest cannot write. What the harness cannot supply
        # is the shape: how this particular exploit accepts the command that
        # reads the root-only nonce and writes it to that console.
        return (
            "a local PoC has to say how it hands over root, and this one "
            f"{'names ' + repr(facts.privesc_shape) if facts.privesc_shape else 'names none'}"
            ": the harness has a checked-in relay for a "
            "root shell that reads commands on stdin (stdin-shell) and for an "
            "exploit that takes the command as an argument (argv-command). One "
            "that needs an interactive terminal, or only drops a setuid binary, "
            "needs a relay designed and checked in for it"
        )
    if is_kernel(facts) and not local:
        # The reboot and the uname assertion are on the local path: the setup
        # step installs the kernel, updates the initramfs and grub and records
        # which kernel it added, the runner reboots, and readiness refuses to
        # continue unless the running kernel IS that one. A remote kernel CVE
        # has none of that and no observation design either.
        return (
            "this is a kernel CVE, and replacing the running kernel needs the "
            "reboot and the uname assertion that only the local privesc path "
            "has - a remote one would report a result about a kernel that was "
            "never booted"
        )
    if facts.privesc_shape in QUOTED_SHAPES and facts.poc_command is None:
        return (
            f"a {facts.privesc_shape} PoC needs a command quoted from the "
            "artifact: for fixed-command the one it embeds for root to run, for "
            "two-stage the line that starts the helper the exploit needs"
        )
    if facts.privesc_shape == "fixed-command" and not (
        facts.poc_command
        and (facts.poc_command_exec or "")
        and (facts.poc_command_exec or "") in facts.poc_command.quote
    ):
        return (
            "a fixed-command PoC embeds the command root runs, so it needs the "
            "span inside that quote which names the command - the harness "
            "replaces that span and nothing else"
        )
    if not local and not ports_for(facts):
        return (
            "no port was extracted and protocol "
            f"{facts.protocol!r} has no standard one, so the attacker cannot be "
            "allowed to reach the target and no service can be waited on"
        )
    if any(port < 1 or port > 65535 for port in ports_for(facts)):
        return f"extracted ports are not usable: {facts.ports}"
    if len(ports_for(facts)) > MAX_PORTS:
        return f"{len(facts.ports)} ports is too many to open for one target"
    if not local and facts.protocol not in {"http", "https", "tcp"}:
        return f"protocol {facts.protocol!r} is not a network protocol the harness opens"
    # Kept on the artifact path too, which is where it was earned: a job died
    # in the guest with "no tomcat webapps directory: is tomcat in the package
    # list?" after an approved .war was placed into a tree nothing had created.
    # What the message adds is the other way out, because WSO2's CVE-2022-29464
    # lands here with place "tomcat-webapp" and no package - and WSO2 ships its
    # own Tomcat inside a .zip, so a placement is the wrong shape for it
    # entirely.
    if facts.place in PLACEMENT_NEEDS and not any(
        PLACEMENT_NEEDS[facts.place] in name for name in facts.setup_packages
    ):
        need = PLACEMENT_NEEDS[facts.place]
        return (
            f"the {facts.place} placement needs {need} installed to have a directory "
            f"to go in, and setup_packages names {facts.setup_packages or 'nothing'} - "
            f"name the package, or approve the product archive that brings its own "
            f"{need} (a .zip or .tar.gz), which is how a product with an embedded "
            "servlet container is installed"
        )
    if facts.place and not artifact:
        # The package resolves and would install and listen - and would not be
        # vulnerable. Debian's apache2 ships `<Directory /> Require all denied`
        # and CVE-2021-41773 needs `Require all granted`, which is exactly the
        # 000-default.conf blasty ships and labels "not a stock or recommended
        # config ;-)". Without this the job provisions, passes readiness, runs
        # the PoC and reports "did not reproduce" - and with no fixed-version
        # control run on this path (entry 24c) nothing would say it was the
        # configuration rather than the CVE.
        return (
            f"the affected software is not vulnerable as packaged: it needs a "
            f"file placed as {facts.place}, so approve the one the PoC ships"
        )
    # A Dockerfile IS a statement of how the affected software is installed -
    # the author's rather than ours - so it answers this branch. Without this
    # clause a docker target was refused for naming no package, which is the
    # one thing it is never going to name.
    if not facts.setup_packages and not artifact and facts.dockerfile is None:
        # This target's whole provisioning is `apt-get install`. With nothing to
        # install, the base image carries ca-certificates, curl and a keyring,
        # so no service can ever come up and readiness is guaranteed to time
        # out - five minutes and a VM after the answer was already knowable.
        #
        # Which of two things went wrong matters to whoever reads this, and
        # app_dir distinguishes them. CVE-2026-126187 ships a lab the ecosystem
        # target can rebuild, so pointing there is useful. CVE-2026-56290 ships
        # one Python script, two screenshots and a README that assumes you
        # already have a Joomla install - pointing at an ecosystem target there
        # sends the reader looking for something that does not exist.
        ports = "/".join(str(port) for port in ports_for(facts)) or "a port"
        if facts.app_dir is not None:
            return (
                "the PoC's instructions name no apt package to install, so "
                f"nothing would ever listen on port {ports}. It does ship "
                f"{facts.app_dir or 'the repository root'} as the directory that "
                "builds the application, but this harness could not rebuild the "
                "environment from it - the manifest there is missing, or declares "
                "a runtime or a start command outside the vocabulary"
            )
        return (
            "nothing in this PoC says how to install the affected software: it "
            "names no apt package and no directory that builds the "
            f"application, so nothing would ever listen on port {ports}. A PoC "
            "that assumes a target already exists needs that target checked in, "
            "which is a per-CVE piece of work and not something this path can "
            "derive"
        )
    return None


def admits(facts: Facts, *, artifact: bool = False) -> bool:
    return _reason(facts, artifact=artifact) is None


def needs_a_download(facts: Facts) -> bool:
    """Whether an approved download is the only thing this CVE is missing.

    True when every other reason to refuse is absent: the PoC is remote, its
    port is known, the protocol is one the harness opens - and the only gap is
    that nothing here says how to install the affected software. That is the
    whole guard on offering an approval: the apt archives and the ecosystem
    path are tried first, and this is what is left when they have failed for
    that one reason rather than for any other.
    """
    if not (facts.poc_entrypoint or "").strip() and not has_command(facts):
        # Nothing to run on the attacker, so no file could make this job
        # possible. The guard listed above was incomplete: _reason never looks
        # at the entrypoint, so a repository that ships only a target recipe
        # was offered an approval it could never use, and the job would have
        # failed at the entrypoint after the operator approved bytes.
        #
        # `and not has_command` was missing, and that was a regression of
        # exactly the kind this guard was written to prevent. The guard predates
        # the command-only PoC, and once that existed a repository whose exploit
        # IS a command - blasty's CVE-2021-41773 - had no poc_entrypoint, so the
        # approval it needed for its config was refused as a flat 422 instead of
        # offered as a card. "Is there anything to run" is what this means, and
        # entrypoint() is the function that answers it.
        return False
    return _reason(facts) is not None and admits(facts, artifact=True)


def release_for(resolution: Resolution | None, fallback: Release | None = None) -> Release:
    if resolution is not None:
        return resolution.release
    return fallback or RELEASES[0]


def derive(
    facts: Facts,
    poc_url: str,
    resolution: Resolution | None = None,
    fallback: Release | None = None,
    artifact: str = "",
) -> TargetInstance:
    """Build a target from facts, or refuse to.

    The PoC pin is left empty here and filled by the stage_poc step from the
    bytes it actually fetched: nobody knows the digest of an arbitrary
    repository in advance, so there is nothing to pin to at admission time.
    That is a weaker pin than the checked-in targets have - it says "these are
    the bytes that ran", not "these are the bytes the vendor published" - and
    it is recorded as evidence so a reader can see which ones they were.
    """
    # An approved download replaces the apt *lookup*, not the apt step: a .deb
    # needs its dependency closure from the archive, so the step that installs
    # a file is the step that already configures apt. All `artifact` changes
    # here is the admission check - the package was never going to be the thing
    # installed, so its absence is no longer a reason to refuse.
    reason = _reason(facts, artifact=bool(artifact))
    if reason is not None:
        raise NoObservable(reason)
    local = is_local(facts)
    ports = () if local else ports_for(facts)
    # A local job attacks the machine it runs on: no attacker VM, no port, and
    # the evidence leaves through the host's serial console rather than an
    # attacker's transcript. Everything else - the apt install from the dated
    # archive, the version assertion, the null run, the PoC staging - is the
    # same path the remote jobs take.
    run_step = PRIVESC_STEPS[facts.privesc_shape or ""] if local else "run-poc-generic"
    return TargetInstance(
        target_id=GENERIC_ID,
        cve_ids=(facts.cve_id,),
        poc_context="local" if local else "remote",
        base_image_id=release_for(resolution, fallback).image_id,
        kernel_artifact_id=None,
        resources=Resources(vcpu=2, memory_mb=4096, disk_gb=25),
        attacker_profile_id=None if local else "attacker-remote",
        network_profile_id="isolated",
        actor_user="xentry-guest",
        # The author's Dockerfile, when that is the only description of the
        # vulnerable environment they wrote. A different step, not a flag on
        # this one: it installs nothing from the dated archive and its
        # provenance is theirs, so the two must not be confusable in a record.
        setup_step_id=(
            "setup-docker" if (facts.dockerfile is not None) else "setup-generic"
        ),
        setup_script="common/setup-generic.sh",
        readiness_step_id="readiness-local" if local else "readiness-generic",
        build_step_id="build-poc-generic",
        invocation_step_id=run_step,
        null_step_id="null-local" if local else "null-generic",
        probe_step_id="probe-generic-serial" if local else "probe-generic-transcript",
        setup_sha256=_step_sha("setup-generic"),
        # Set when a release was resolved for an affected version: readiness
        # then asserts the installed package matches it, which is the
        # difference between "something is listening" and "the affected build
        # is listening". Empty when the PoC needed no packages installed.
        expected_version="" if resolution is None else resolution.prefix,
        poc=PocPin(
            artifact_id="poc-generic",
            repository=poc_url.rstrip("/").removesuffix(".git"),
            commit="",
            files=[],
            sha256="",
            build_step_id="build-poc-generic",
            invocation_step_id=run_step,
        ),
        probes=(
            ProbeStep(
                step_id="probe-generic-serial",
                kind="host_serial",
                decisive=True,
                params={"channel": "org.xentry.evidence.0"},
                timeout_s=60,
            )
            if local
            else ProbeStep(
                step_id="probe-generic-transcript",
                kind="response_parse",
                decisive=True,
                params={"source": "attacker_transcript"},
                timeout_s=10,
            ),
        ),
        nonce=NonceSpec(
            path=NONCE_PATH_LOCAL if local else NONCE_PATH,
            owner="root",
            mode=NONCE_MODE_LOCAL if local else NONCE_MODE,
        ),
        null_actor=NullActor(
            location="target" if local else "attacker",
            step_id="null-local" if local else "null-generic",
        ),
        evidence_channel=EvidenceChannel(
            kind="host_serial" if local else "attacker_transcript",
            channel="org.xentry.evidence.0" if local else "stdout+stderr",
        ),
        target_ports=ports,
        poc_archive_guest_path="/var/lib/xentry/artifacts/poc-generic.tar.gz",
        poc_dir="/home/xentry-guest/xentry-poc",
        what_proves=PROVES_LOCAL if local else PROVES,
        what_does_not_prove=(DOES_NOT_PROVE_LOCAL if local else DOES_NOT_PROVE)
        + ((DATED_CAVEAT,) if resolution is not None and not resolution.prefix else ()),
        timeouts=Timeouts(boot_s=120, provision_s=1800, readiness_s=600, poc_s=900, validate_s=120),
    )


def tokens(values: list[str], kind: str) -> str:
    """One space-separated argument for a step, or raise on anything odd."""
    pattern = {
        "package": PACKAGE_RE, "unit": UNIT_RE, "launch": LAUNCH_RE, "pip": PIP_RE,
        "argv": ARGV_RE,
    }[kind]
    cleaned = [value.strip() for value in values if value.strip()]
    if len(cleaned) > MAX_TOKENS:
        raise NoObservable(f"{len(cleaned)} {kind}s is more than this harness will install")
    for value in cleaned:
        if not pattern.match(value):
            raise NoObservable(f"refused {kind}: {value!r}")
    return " ".join(cleaned)


def placement(facts: Facts) -> str:
    """The placement kind, checked against the closed set, or "" for none."""
    kind = (facts.place or "").strip()
    if kind and kind not in PLACEMENTS:
        raise NoObservable(
            f"refused place: {kind!r}; this harness knows {sorted(PLACEMENTS)}"
        )
    return kind


# A command-only PoC is written to this name. It is not a path from the
# repository: the repository has nothing to run.
COMMAND_ENTRYPOINT = "exploit.sh"
# One line, and short. A command that spans lines is a script, and a script is
# the other case; the cap is there because this is a quote and a quote that
# long is not a command.
MAX_COMMAND = 2000


def has_command(facts: Facts) -> bool:
    return facts.poc_command is not None and not (facts.poc_entrypoint or "").strip()


def command_script(facts: Facts) -> str:
    """A shell PoC built from a command the extractor QUOTED, not authored.

    "The app never supplies a command" is what the whole step vocabulary rests
    on, and this does not break it: the command arrives as an EvidenceRef, so
    _verify_refs has already checked it appears verbatim in the PoC artifact.
    A command that is not in the README is refused, which means the model can
    point at one and cannot write one.

    The two substitutions are spans of that same quote - the host:port the
    README wrote and the file it read - replaced by the arguments
    run-poc-generic.sh already passes: $1 $2 $3. Bare, not quoted, because
    both sit inside an argument the command has already quoted.
    """
    ref = facts.poc_command
    if ref is None:
        raise NoObservable("no command was quoted for this PoC")
    # A README writes its commands behind a prompt marker, and the quote is
    # copied VERBATIM so the citation can be verified against the artifact -
    # which means the marker comes with it. blasty's CVE-2021-41773 quote is
    #   $ curl -s --path-as-is "http://localhost:8080/icons/.%2e/..."
    # and that reached the guest as a script whose line 6 began with "$", so
    # bash reported `$: command not found` after seventeen steps had passed.
    # Stripped HERE and not in the facts, because the facts must keep matching
    # the bytes the citation points at.
    command = re.sub(r"^[$#]\s+", "", ref.quote.strip())
    if not command or "\n" in command or len(command) > MAX_COMMAND:
        raise NoObservable(f"refused command: {command[:60]!r}")
    host = (facts.poc_command_target or "").strip()
    read = (facts.poc_command_read or "").strip()
    run = (facts.poc_command_exec or "").strip()
    # Exactly one, and WHICH one is the claim being made. A disclosure proves a
    # traversal; it does not prove execution. An advisory that describes only
    # code execution is not answered by reading a file, so the extractor says
    # which span it found and the record carries that word into the evidence.
    if bool(read) == bool(run):
        raise NoObservable(
            "a quoted command needs exactly one of poc_command_read - the file the "
            "target discloses - or poc_command_exec, the command it runs"
        )
    proof = "disclosure" if read else "execution"
    span = read or run
    for label, token in (("target", host), (proof, span)):
        # Missing and wrong are different failures, and reporting them as one
        # produced "the target span '' is not in the quoted command" - which
        # reads as a harness fault. The usual cause of a missing target span is
        # a README that shows a raw HTTP request rather than a command.
        if not token:
            raise NoObservable(
                f"the quoted command names no {label}: {command[:60]!r} has no "
                "host:port to point at the target, which is what a raw HTTP "
                "request line looks like rather than a runnable command"
            )
        if token not in command:
            raise NoObservable(
                f"the {label} span {token!r} is not in the quoted command, so the "
                "substitution cannot be checked"
            )
    # Where the span sits decides how the nonce can be written. An odd number
    # of single quotes before it means it is inside a single-quoted string,
    # where $3 does not expand - the PoC would send the literal text "$3" to
    # the target and read nothing. Closing and reopening the quote around a
    # double-quoted expansion is the shell's own idiom for it.
    before = command[: command.index(span)]
    if before.count("'") % 2 == 1:
        nonce = "'\"$3\"'"
    elif before.count('"') % 2 == 1:
        nonce = "$3"
    else:
        nonce = '"$3"'
    body = command.replace(host, "$1:$2").replace(
        span, nonce if read else f"cat {nonce}"
    )
    if "$1" not in body or "$3" not in body:
        raise NoObservable("the substitution did not change the command")
    return (
        "#!/bin/sh\n"
        "# Quoted verbatim from the PoC's own text, with the target's address\n"
        "# and the nonce path substituted. Nothing here was authored.\n"
        f"# Proof of {proof}: the span {span!r} carried the nonce.\n"
        "set -eu\n"
        f"{body}\n"
    )


def entrypoint(facts: Facts) -> str:
    """The one file that runs the exploit.

    Guessing badly here would run the wrong file in the attacker VM, so the
    only accepted forms are a relative path the extractor read in the PoC's own
    text. There is no autodetection: a repository with two plausible scripts
    would make the choice silently, and that choice decides what "the PoC" even
    means for the verdict.
    """
    raw = (facts.poc_entrypoint or "").strip()
    if not raw and has_command(facts):
        # A command-only PoC: there is no file in the repository, and the one
        # that runs is built from the quoted command. Checked here rather than
        # trusted, so a command that cannot be substituted is refused at
        # admission instead of at the run step.
        command_script(facts)
        return COMMAND_ENTRYPOINT
    if not raw:
        raise NoObservable(
            "the PoC text does not name a file that runs the exploit, and this "
            "harness will not pick one for you"
        )
    # Checked before any trimming: lstrip("./") would turn "/etc/passwd" into
    # "etc/passwd" and "../x.py" into "x.py", quietly admitting both.
    if raw.startswith("/") or ".." in raw:
        raise NoObservable(f"refused entrypoint: {raw!r}")
    candidate = raw.removeprefix("./")
    if not ENTRYPOINT_RE.match(candidate):
        raise NoObservable(f"refused entrypoint: {raw!r}")
    return candidate


PUBLISHED_RE = re.compile(
    r"^\S*(?:datePublished|published): (\d{4}-\d{2}-\d{2}T[0-9:.]+Z?)\s*$",
    re.MULTILINE,
)


def advisory_published(cve_text: str) -> str:
    """The advisory's publication timestamp, from a rendered advisory record.

    This is read from the reader-facing rendering rather than from JSON,
    because that is what the caller holds, and getting it wrong is expensive
    and quiet: with no date there is no per-CVE snapshot serial, the broker's
    default applies, and for a recent CVE that usually means provisioning the
    *patched* build - so the exploit fails and the job looks like a
    non-reproduction rather than a misconfiguration.

    Both record shapes are covered, which the old json.loads was not: NVD 2.0
    writes `vulnerabilities[0].cve.published` and CVE 5.x writes
    `cveMetadata.datePublished`, and cve.org links only ever reach the second.
    A page with no such field - a GitHub advisory, say - still yields "".
    """
    match = PUBLISHED_RE.search(cve_text)
    if match is not None:
        return match.group(1)
    # The raw records too, both shapes. The rendering is what the caller holds
    # today, but losing this date is expensive and silent on the apt path, so
    # it is not left depending on one representation.
    try:
        record = json.loads(cve_text)
    except ValueError:
        return ""
    for path in (
        ("vulnerabilities", 0, "cve", "published"),
        ("cveMetadata", "datePublished"),
    ):
        node: Any = record
        try:
            for key in path:
                node = node[key]
        except (KeyError, IndexError, TypeError):
            continue
        if isinstance(node, str):
            return node
    return ""


def cutoff_for(published: str, *, now: datetime | None = None) -> str:
    """The registry cutoff to resolve against, or "" to run no registry proxy.

    The same rule the apt serial uses, in the format a registry index carries:
    one day before publication, floored at the start of that day. That is what
    makes the two provisioning channels say the same thing - a job installs the
    build that was current while the flaw was still unpublished, whether it
    comes from the archive or from a package registry.

    "" is not a fallback to "today". It means no cutoff could be derived, and
    the broker then starts no registry proxy at all, because resolving against
    a live registry would pin whatever semver answers today - for a recent CVE,
    usually the fix.
    """
    serial = snapshot_for(published, now=now)
    if not serial:
        return ""
    return f"{serial[0:4]}-{serial[4:6]}-{serial[6:8]}T00:00:00Z"


def snapshot_for(published: str, *, now: datetime | None = None) -> str:
    """The snapshot serial to provision from, or "" to use the default.

    One day before publication, floored at the start of that day: the last
    archive state that predates the advisory. An unparseable, too-early or
    future date yields "" rather than a guess, because a silently wrong serial
    installs a build nobody chose.
    """
    text = published.strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    moment = datetime.now(UTC) if now is None else now
    target = (parsed - timedelta(days=SNAPSHOT_LEAD_DAYS)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    if target < SNAPSHOT_FLOOR or target > moment:
        return ""
    return target.strftime("%Y%m%dT%H%M%SZ")
