"""CVE/PoC fact extraction.

The extractor sees only labeled excerpts and returns typed Facts with citations.
No tools, no fetch, no execute. The runner verifies every quote against the
artifact text before the facts can influence the plan.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

import litellm

from xentry import transcript
from xentry.models import EvidenceRef, Facts

FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
# A citation has to be something a reader can find and check, which is what a
# bare "}`" is not. Twenty characters was a blunt proxy for that and it threw
# away good evidence: `FROM httpd:2.4.50` is seventeen characters and is the
# best possible proof of an affected version, `- "1234:8080"` is thirteen and
# names the port. Three separate CVEs failed on exactly those lines, and the
# failure is fatal because version_evidence is verified fatally - so the
# harness's own improvement, putting the PoC's source files in the artifact,
# gave the model better things to cite than the gate would accept.
#
# The length floor drops and a structural rule carries the intent: a quote
# needs at least two alphanumeric runs. "}`" has none, "[" has none, "1234"
# has one; every real line has two or more. The floor then only has to exclude
# a quote too slight to be an anchor, and 12 was still too high: samba's PoC
# line `port = 445` is ten characters and names the port, and it was fatal.
# What actually verifies a citation is _quote_present - the quote has to be IN
# the artifact - and that holds at any length.
MIN_QUOTE = 8
MIN_QUOTE_WORDS = 2
MAX_ARTIFACT_CHARS = 12_000


class ExtractorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        # Filled in by the caller that owns the transcript id. A refusal is the
        # one case where anyone wants to read the model's own reply, and the id
        # it is filed under was known only inside the caller.
        self.check_id = ""


@dataclass(frozen=True)
class ArtifactText:
    artifact_id: str
    sha256: str
    text: str


def _numbered(text: str) -> str:
    return "\n".join(f"{index}: {line}" for index, line in enumerate(text.splitlines(), 1))


def _prompt(artifacts: list[ArtifactText]) -> str:
    blocks = []
    for artifact in artifacts:
        # Head AND tail. The harness appends the repository listing and the
        # PoC's own source files to the END of that artifact, and head-only
        # truncation silently threw away both - for CVE-2022-29464 the listing
        # begins at character 24,186 of a 25,365-character artifact, so the
        # model was told "the listing is AUTHORITATIVE about which files
        # exist" and then given no listing. It answered poc_entrypoint: null
        # for a repository whose single file is exploit.py.
        body = artifact.text
        if len(body) > MAX_ARTIFACT_CHARS:
            half = MAX_ARTIFACT_CHARS // 2
            body = f"{body[:half]}\n[... middle of this artifact omitted ...]\n{body[-half:]}"
        blocks.append(
            f"ARTIFACT {artifact.artifact_id} sha256={artifact.sha256}\n"
            f"{_numbered(body)}\n"
        )
    return (
        "You are the xentry extractor. Return exactly one JSON object and no markdown.\n"
        "Use only the supplied artifacts. Do not invent hashes, versions, ports, or quotes.\n"
        "Schema keys: cve_id, product, affected_range, version_evidence, protocol, ports, "
        "auth_required, build_strategy, poc_context, marker_candidate, setup_packages, "
        "setup_units, attacker_packages, attacker_pip, app_dir, fixed_versions, "
        "poc_entrypoint, poc_argv, "
        "privesc_shape, "
        "poc_command, poc_command_target, poc_command_read, poc_command_exec, "
        "launch, place, place_file, dockerfile, "
        "artifact_candidates, citations.\n"
        "- cve_id: CVE-YYYY-NNNN or later digits.\n"
        "- product: the affected software product (for kernel advisories use "
        "\"Linux kernel\"), not the vulnerability nickname.\n"
        "- affected_range: the exact affected-version or version-range text; for "
        "kernel advisories include the kernel version (for example 6.17.0-23), "
        "not the vulnerability name.\n"
        "- version_evidence: quote the WHOLE LINE a version appears on, key "
        "included - \"containers.cna.affected[0].versions[3].version: = 8.3.0\" "
        "rather than \"= 8.3.0\". A bare version is five characters that occur "
        "all over a record, so it anchors nothing and is refused; the line is "
        "unique and a reader can find it.\n"
        "- version_evidence: array of objects exactly like "
        '{"artifact_id":"...","sha256":"...","quote":"...","line_start":1,"line_end":1}.\n'
        "- protocol: http, https, tcp, local, or null.\n"
        "- ports: array of integers the TARGET listens on - the ports the PoC "
        "connects *to*. A port the PoC itself binds is not one of these: its own "
        "HTTP or LDAP listener, a reverse-shell port, a callback port. If the "
        "instructions say the application is reached at a port, that is the one. "
        "CVE-2021-44228's PoC says \"you can access it on localhost:8080\" and also "
        "binds 1389, 8000 and 9001; only 8080 belongs here. A container recipe's "
        "\"8080:80\" is a mapping, not the port the service itself listens on: "
        "report 80. If nothing in the text names a port at all, give the "
        "protocol's standard one - http 80, https 443, ssh 22, smtp 25, smb 445, "
        "ldap 389, mysql 3306, couchdb 5984 - rather than an empty array: a "
        "remote PoC with no port leaves nothing to point it at. An empty array "
        "is right only for a local PoC.\n"
        "- auth_required: boolean.\n"
        "- build_strategy: short description.\n"
        "- poc_context: remote or local.\n"
        "- marker_candidate: optional short path or token.\n"
        "- setup_packages: distro package names that would install the affected "
        "software itself, as plain names such as \"apache2\"; [] if none would. The "
        "PoC artifact ends with a listing of every file in the repository, "
        "subfolders included, and that listing is evidence: a vendored "
        "\"apache2_2.4.49-4_amd64.deb\" names the package apache2, and a Dockerfile "
        "that apt-installs a list names those. Name a package only when installing "
        "it would make the affected software run and listen on the port - a "
        "library, a plugin or a language module starts nothing, so log4j inside an "
        "application is []. Name the obvious package even when NOTHING in the text "
        "mentions apt: for widely packaged software the product name is usually "
        "the package name, so Cacti is \"cacti\", CouchDB is \"couchdb\", Apache "
        "HTTP Server is \"apache2\". A LOCAL privesc has a package too - the one "
        "shipping the vulnerable binary: sudo is \"sudo\", pkexec is "
        "\"policykit-1\", the loader is \"libc6\". For a LINUX KERNEL flaw name "
        "the kernel package - \"linux-image-amd64\" on Debian, "
        "\"linux-image-generic\" on Ubuntu - because the harness installs it from "
        "the dated archive, reboots into it and asserts uname: that is the only "
        "way a kernel CVE can be reproduced here, and naming nothing refuses it. "
        "A wrong guess is checked and refused, "
        "not installed - the harness asks the archive whether that package exists "
        "AND publishes a version the advisory names, and both must hold. Never a "
        "command, never a version.\n"
        "- setup_units: systemd unit names to enable, such as \"apache2\"; [] if none.\n"
        "- attacker_packages: Ubuntu package names the PoC needs on the machine it "
        "RUNS FROM, not on the target - a JDK for a JNDI exploit, build-essential "
        "for a PoC that compiles. CVE-2021-44228's PoC runs an LDAP server with "
        "java, so it needs a JDK. [] when the PoC is plain Python, whose "
        "dependencies are already in the attacker image. Never a command.\n"
        "- attacker_pip: PyPI distribution names the PoC IMPORTS and the attacker "
        "image does not already carry. It carries requests, paramiko, "
        "cryptography, pycryptodome, colorama, beautifulsoup4 and lxml; name "
        "anything else the entrypoint imports, such as termcolor or rich. Use "
        "the PyPI name, not the import name, when they differ. [] when every "
        "import is standard library or already listed. Never a version, never "
        "a command.\n"
        "- poc_argv: how to invoke poc_entrypoint, as a LIST of argument tokens, "
        "when it does not take three positionals. This harness runs "
        "`<entrypoint> <target-ip> <port> <nonce-path>`; if the PoC's own "
        "usage, argparse calls or README say otherwise, give its arguments and "
        "use {ip}, {port} and {nonce} where those values go - for example "
        "[\"--userip\", \"{ip}\", \"--webport\", \"{port}\"]. [] when the three "
        "positionals are right. Each token is a flag, a placeholder or a plain "
        "value; never a quote, a space or a shell operator.\n"
        "  If a flag takes a COMMAND TO RUN rather than a value - -x, -c, "
        "--cmd, --exec and the like - use {read_nonce} as that argument, NOT "
        "the example command from the README. {read_nonce} becomes a command "
        "that reads the nonce file, which is the only thing this harness can "
        "check: a PoC that runs the README's `id` proves code execution to a "
        "human reading the output and nothing at all to the runner. "
        "CVE-2022-0543's exploit did exactly that - it reached command "
        "execution as uid=108(redis) and the job still failed, because it was "
        "told to run `id`.\n"
        "- app_dir: if the repository ships a directory that builds the vulnerable "
        "application - a Dockerfile, a compose file, a package.json - the path to it "
        "relative to the repository root, such as \"lab\"; \"\" for the root itself; "
        "null if there is no such directory. Report where it is, not how to build "
        "it: the build commands are never run.\n"
        "- fixed_versions: every version the advisory names as fixing the flaw, "
        "as bare versions such as [\"19.0.9\",\"19.1.10\",\"19.3.1\"]; an advisory "
        "that fixes several branches names one per branch, so list them all and "
        "do not choose between them. Take one from the PoC's own text or the "
        "vendor note too when the advisory itself gives none: this field is "
        "what stops the harness installing a BUILD that already carries the "
        "fix, so \"OpenSMTPD 6.6\" with the fix at 6.6.2p1 needs that 6.6.2p1. "
        "For a KERNEL flaw that is the per-branch stable release carrying the "
        "fix - 5.16.11, 5.15.25, 5.10.102 for CVE-2022-0847 - and NOT the "
        "\"5.17 rc6\" the record states as affected: without those three the "
        "harness installs 5.16.18, which has the fix. "
        "[] only if no source names one.\n"
        "The PoC artifact has three parts: its README, then a listing of every "
        "file in the repository as `size path`, then the small text files "
        "themselves, each under a `--- path ---` heading. Use all three.\n"
        "The listing is AUTHORITATIVE about which files exist, and the prose is "
        "not: CVE-2022-29464's README writes \"Using exploiy.py\" in a heading and "
        "\"python3 exploit.py\" in the command below it, and only one of those is a "
        "file. Where prose and listing disagree, the listing wins.\n"
        "The source files are where a PORT usually is. CVE-2025-32433's README is "
        "a blog link and an image while its exploit says `PORT = 2222`; "
        "CVE-2021-41773's port is `\"8080:80\"` in a compose file. Read them before "
        "concluding a port is unknown.\n"
        "NEVER cite the file listing. Its lines are an inventory, not prose - "
        "\"674 Dockerfile\" is not evidence of anything and is too short to be a "
        "citation. Cite the README, the advisory, or a line of source.\n"
        "- poc_entrypoint: for a COMPILED PoC this is the file that RUNS, which is "
        "not the source: blasty/CVE-2021-3156 ships hax.c and a Makefile saying "
        "`gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c`, so the entrypoint is "
        "sudo-hax-me-a-sandwich. Read the name after -o, or the Makefile target; "
        "the harness runs `make` and then runs this path, and a .c file here "
        "cannot be executed.\n"
        "- poc_entrypoint: the one file in the PoC repository that runs the exploit, "
        "as a path relative to the repository root such as \"exploit.py\" or "
        "\"scripts/run.py\"; the file listing shows subfolders, so a script that "
        "lives in one is named with its path. Take it from the LISTING, not from "
        "the prose: if the listing holds exactly one script that could run an "
        "exploit - exploit.py, poc.py, CVE-xxxx.py, a single .sh - that is the "
        "one, whatever the README calls it or misspells it. null ONLY when the "
        "listing holds no such file at all: a repository of a Dockerfile, a "
        "compose file and vendored packages is a vulnerable-target recipe, and "
        "then poc_command is how its exploit is expressed.\n"
        "- privesc_shape: for a LOCAL PoC only - one that escalates privilege on "
        "the machine it runs on rather than attacking one over the network - how "
        "the exploit lets its caller run a command as root. \"stdin-shell\" when it "
        "gives a root shell that reads commands on standard input, which is the "
        "common case: a PoC that execs /bin/sh after escalating accepts piped "
        "commands. \"argv-command\" when the exploit takes the command to run as an "
        "argument, such as `./exploit \"id\"`. "
        "\"pty-shell\" when it needs a real TERMINAL - it calls isatty(), "
        "or runs an interactive program, so a pipe makes it do nothing at all. "
        "\"setuid-drop\" when the exploit RETURNS and what it leaves behind is a "
        "setuid-root file; the harness finds that file by what appeared rather "
        "than being told, so nothing more is needed. "
        "\"fixed-command\" when it hands the caller no way to run anything "
        "because it EMBEDS the command root will execute - exim CVE-2019-10149's "
        "PoC sends a crafted address containing it - and then poc_command must "
        "quote that embedded command from the artifact and poc_command_exec must "
        "name the span inside it that is the command, because the harness "
        "replaces that span and nothing else. \"two-stage\" when a HELPER has to "
        "be running before the exploit works - CVE-2023-0386's README says "
        "`./fuse ./ovlcap/lower ./gc` and then `./exp`, so neither half alone "
        "is the PoC - and then poc_command quotes that first line, which must "
        "name a file in the repository with ./ and may carry plain arguments "
        "and nothing else. null when NONE of the six fits, or when the PoC is "
        "remote. "
        "Decide it from the source and the README, not from the CVE: this "
        "picks which checked-in relay script runs, and a wrong shape means the "
        "exploit never receives the command and the job reports no observation.\n"
        "- launch: if the affected software is distributed as an archive rather "
        "than a package - a product tarball or zip that unpacks to a directory - "
        "the bare FILENAME of the script inside it that starts the server, such "
        "as \"start-confluence.sh\", \"startup.sh\" or \"wso2server.sh\". A name "
        "only: no path, no arguments, no command. null when the software installs "
        "as a package, or when the text does not name one.\n"
        "- poc_command: when the repository holds no script but the text DOES show "
        "the exploit as a command - a curl line, a one-liner - that command as an "
        "evidence-ref object, with the command itself as the \"quote\". It is "
        "checked verbatim against the artifact, so copy it exactly and do not "
        "tidy it. A raw HTTP request line - \"GET /path?x=y HTTP/1.1\" - is NOT "
        "a command: nothing can run it and it carries no host to point at the "
        "target, so poc_command is null when the text shows a request and no "
        "command that sends it. null also when there is a script, or no command "
        "either.\n"
        "- poc_command_target: the exact substring of that command that is the "
        "host and port it talks to, such as \"localhost:8080\"; null if there is "
        "no poc_command.\n"
        "- poc_command_read and poc_command_exec: exactly ONE of these, and which "
        "one is the claim the run will prove. poc_command_read is the exact "
        "substring naming the file the target discloses, such as \"/etc/passwd\". "
        "poc_command_exec is the exact substring naming the command the target "
        "runs, such as \"id\". Choose by what the ADVISORY describes, not by which "
        "command looks better: if the advisory describes a path traversal or an "
        "arbitrary file read, a disclosure proves it and read is the right one - "
        "CVE-2021-41773 is a traversal, so reading a file satisfies it even though "
        "RCE is reachable under some configurations. If the advisory describes only "
        "code execution, reading a file does NOT prove it and exec is required. "
        "Both null when there is no poc_command.\n"
        "- place: null for a product that ships its own servlet container. WSO2, "
        "Confluence and Jira are .zip or .tar.gz products with Tomcat INSIDE "
        "them, so nothing is placed into a distro tomcat and no distro packages "
        "them: those get launch plus an approved product archive, not a "
        "placement. A placement is for a file dropped into a package's own "
        "tree.\n"
        "- place: a placement is refused unless setup_packages also names the "
        "package that PROVIDES the directory it goes in - apache2 for an "
        "apache-site, nginx for an nginx-site, a tomcat package for a "
        "tomcat-webapp - because without it there is no directory to place into "
        "and nothing would listen. Name both or neither.\n"
        "- place: when the affected software is NOT vulnerable as packaged until a "
        "file is in place, the kind of placement: \"apache-site\" for an Apache "
        "site config, \"nginx-site\" for an nginx one, \"tomcat-webapp\" for a .war "
        "that is the affected application. Do NOT force-fit: if the software "
        "needs a config none of these kinds describes, answer null and say so in "
        "build_strategy rather than naming the closest one - a wrong kind writes "
        "a file to a path the service never reads. CVE-2021-41773 is apache-site, because Debian's apache2 "
        "ships Require-all-denied and the traversal needs Require-all-granted, "
        "and the PoC's 000-default.conf is that file. null when the package alone "
        "is vulnerable, which is the usual case.\n"
        "- dockerfile: the directory in the PoC repository holding a Dockerfile "
        "that builds the VULNERABLE TARGET, relative to the root, \"\" for the root "
        "itself - the file listing shows them. Set it only when the Dockerfile is "
        "the only description of how the affected software is set up: if "
        "setup_packages can name a package that installs it, prefer that, because "
        "an image's base tag is not a version and this harness cannot date it. "
        "null when there is no such Dockerfile or a package would do. Only Debian "
        "and Ubuntu base images can be built; a Dockerfile FROM anything else is "
        "null too.\n"
        "- place_file: when place is set, the path in the PoC repository of the "
        "file that IS that placement, relative to its root, such as "
        "\"000-default.conf\" or \"target/log4shell-1.0-SNAPSHOT.war\" - the file "
        "listing shows them. null when place is null.\n"
        "- artifact_candidates: array of the same evidence-ref objects for PoC/setup artifacts.\n"
        "- citations: array of the same evidence-ref objects; at least one.\n"
        "Every quote must be copied verbatim from the artifact text and must name "
        "its artifact_id. sha256 may be omitted - it is filled in from the artifact "
        "you named, so there is nothing to copy and nothing to get wrong. Line "
        "numbers when possible. A quote must be a whole "
        f"phrase or line of at least {MIN_QUOTE} characters and {MIN_QUOTE_WORDS} "
        "words; never a fragment such as a bare brace, bracket or punctuation. A "
        "sentence from the advisory's own description is always long enough and "
        "always there, so prefer one when nothing shorter is better evidence. "
        "If the evidence is "
        "insufficient, return {\"error\": \"evidence_insufficient\"}.\n\n"
        + "\n".join(blocks)
    )


def _parse_json(content: str) -> dict[str, Any]:
    raw = content.strip()
    fenced = FENCE_RE.search(raw)
    if fenced:
        raw = fenced.group(1).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise ExtractorError("validator_error", "extractor returned no JSON object")
        try:
            parsed = json.loads(raw[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ExtractorError("validator_error", "extractor returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ExtractorError("validator_error", "extractor result is not an object")
    if parsed.get("error"):
        # The model's own text, in the MESSAGE position. It used to go in the
        # CODE position with a fixed sentence as the message, so a reply of
        # {"error": "evidence_insufficient"} arrived as "evidence_insufficient:
        # extractor reported insufficient evidence" - which says nothing and
        # reads like the harness's own words - and a reply that DID explain
        # itself had its explanation turned into a reason code.
        detail = str(parsed["error"]).strip() or "(empty)"
        known = detail in {"evidence_insufficient", "no_observable", "provider_unavailable"}
        raise ExtractorError(
            detail if known else "evidence_insufficient",
            f"the extractor refused with the bare code {detail!r} and gave no "
            "reason; its full reply is in this check's log"
            if known
            else f"the extractor refused: {detail}",
        )
    return parsed


REF_LISTS = ("version_evidence", "artifact_candidates", "citations")
# What a PoC calls its one runnable script, at the root of the repository.
ENTRY_NAMES = ("poc.py", "exploit.py", "exploit.sh", "poc.sh", "exploit.rb")
# NVD's own fix boundary. versionEndExcluding IS the fixed version, by
# definition, and versionEndIncluding is the last affected one - so only the
# first is harvested.
CPE_END_RE = re.compile(r"versionEndExcluding: (\d[\w.+:~-]*)")


def _nvd_fixed(artifacts: list[ArtifactText]) -> list[str]:
    """The fix versions the record states, read from the whole artifact.

    CVE-2022-0847's NVD record carries 5.10.102, 5.15.25 and 5.16.11 - the
    three stable releases that fixed Dirty Pipe - while the CNA record states
    "Linux Kernel 5.17 rc6" as an AFFECTED version, which is what the model
    copied and what made the job resolve to a patched kernel. Those lines sit
    in the middle of a 17,822-character record, past the prompt's truncation,
    so asking the model for them is asking for what it may never have seen.
    Taken here instead, and only when the model named none.
    """
    found: list[str] = []
    for item in artifacts:
        for match in CPE_END_RE.finditer(item.text):
            if match.group(1) not in found:
                found.append(match.group(1))
    return found


def _as_ref(value: Any, artifacts: list[ArtifactText]) -> Any:
    """A bare string where an evidence ref belongs: repaired, not fatal.

    The model answers `poc_command: "curl ..."` instead of
    `{"artifact_id": ..., "quote": "curl ..."}` often enough to matter, and
    pydantic refused the WHOLE reply for it - reported as
    provider_unavailable, which sent the reader to look at the network. The
    repair changes nothing about what is checked: the quote still has to be
    present in the artifact it names or the ref is dropped. Which artifact is
    a lookup rather than a guess - the one whose text contains the quote.
    """
    if not isinstance(value, str) or not value.strip():
        return value
    quote = value.strip()
    where = next(
        (item.artifact_id for item in artifacts if quote in item.text),
        artifacts[0].artifact_id if artifacts else "poc",
    )
    return {"artifact_id": where, "quote": quote}


def coerce_facts(payload: dict[str, Any], artifacts: list[ArtifactText]) -> dict[str, Any]:
    """Mechanical repairs to a reply that is right but shaped wrong.

    Only what follows from the reply itself. Nothing here invents a fact: a
    missing poc_context is read off the protocol the model DID give, and a
    string is wrapped in the object the schema wants. Anything else still
    fails validation, and now says so as evidence_insufficient rather than as
    an unavailable provider.
    """
    if isinstance(payload.get("poc_command"), str):
        payload["poc_command"] = _as_ref(payload["poc_command"], artifacts)
    # A NON-list where a list belongs, as well as a wrong-shaped item inside
    # one. This repaired only the items, so a reply that sent null - or a
    # single object instead of a list of one - went straight to validation and
    # died as evidence_insufficient:
    #   artifact_candidates  Input should be a valid list
    # which cost CVE-2025-32463 a check and reads as "the model said nothing
    # useful" when the model said "no candidates".
    #
    # null means an empty list, and a lone object means a list of one. Neither
    # invents a fact, which is the line this function does not cross.
    for key in REF_LISTS:
        items = payload.get(key)
        if not isinstance(items, list):
            items = [] if items is None else [items]
        payload[key] = [_as_ref(item, artifacts) for item in items]
    # An application protocol where a transport belongs. "smtp" killed the
    # whole reply for exim CVE-2019-10149 - reported as provider_unavailable -
    # when every one of these means the same thing to this harness: open a TCP
    # port and let the attacker reach it. http and https stay distinct because
    # they are the only two with a standard port the harness supplies.
    protocol = payload.get("protocol")
    if isinstance(protocol, str) and protocol.lower() not in {
        "http", "https", "tcp", "local", "",
    }:
        payload["protocol"] = "tcp"
    # The listing names the exploit and the model sometimes does not. This is
    # a lookup in evidence the harness fetched, not a guess: the repository
    # listing is in the PoC artifact, and these five names are what a PoC
    # calls its one runnable script. kozmer/log4j-shell-poc holds exactly one
    # of them - `4208 poc.py` - and came back with poc_entrypoint null, which
    # refused CVE-2021-44228 for having "no file that runs the exploit".
    # Exactly one match, or nothing: two candidates mean choosing, and
    # choosing is what the harness does not do.
    if not payload.get("poc_entrypoint") and not payload.get("poc_command"):
        listed = {
            name
            for item in artifacts
            if item.artifact_id == "poc"
            for name in ENTRY_NAMES
            if re.search(rf"^\d+ {re.escape(name)}$", item.text, re.MULTILINE)
        }
        if len(listed) == 1:
            payload["poc_entrypoint"] = listed.pop()
    # And a repository that holds nothing else: two files at the root, one of
    # them a README, means the other one IS the PoC - there is nothing to
    # choose between. Scoped to the listing section, because a line inside a
    # file's body can read exactly like "1402156 apache2_2.4.49-4_amd64.deb".
    if not payload.get("poc_entrypoint") and not payload.get("poc_command"):
        for item in artifacts:
            if item.artifact_id != "poc":
                continue
            section = item.text.split("repository files", 1)[-1].split("\n\n", 1)[0]
            root = re.findall(r"^\d+ ([^/\n]+)$", section, re.MULTILINE)
            rest = [n for n in root if not n.lower().startswith("readme")]
            if len(root) == 2 and len(rest) == 1:
                payload["poc_entrypoint"] = rest[0]
    # A package list makes a Dockerfile redundant, which is what the prompt
    # already asks for: "Set it only when the Dockerfile is the only
    # description of how the affected software is set up: if setup_packages can
    # name a package that installs it, prefer that". blasty's CVE-2021-41773
    # came back with setup_packages ['apache2'], place apache-site AND
    # dockerfile "" - and derive() picks setup-docker whenever a dockerfile is
    # named, so the docker path won and the job was refused for a Dockerfile it
    # never needed. The apt path is strictly better here: it is dated, and the
    # Dockerfile is not.
    if payload.get("setup_packages") and payload.get("dockerfile") is not None:
        payload["dockerfile"] = None
    # A port means something listens, and nothing listens for a local privesc.
    # Grafana's CVE-2021-43798 is a path traversal read over HTTP on port 3000
    # and came back poc_context "local" with ports [3000] and no privesc_shape,
    # so the harness asked for a root-handover relay that cannot exist for it.
    # Only when no shape is named: a shape is a positive statement about how
    # root is handed over, and that one is the model's to make.
    if (
        payload.get("ports")
        and not payload.get("privesc_shape")
        and payload.get("poc_context") == "local"
    ):
        payload["poc_context"] = "remote"
    if not payload.get("fixed_versions"):
        harvested = _nvd_fixed(artifacts)
        if harvested:
            payload["fixed_versions"] = harvested
    if not payload.get("poc_context"):
        payload["poc_context"] = (
            "local"
            if payload.get("protocol") == "local" or payload.get("privesc_shape")
            else "remote"
        )
    return payload


def _json_strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _json_strings(value)]
    if isinstance(node, list):
        return [s for value in node for s in _json_strings(value)]
    return []


def _quote_present(quote: str, text: str) -> bool:
    """Is the quote really in the artifact?

    A raw substring match is the right test for an artifact the model read
    verbatim. It is the wrong test for JSON: NVD stores a multi-line
    description with escaped newlines, the model quotes the prose it decoded,
    and the two never match byte for byte. So a JSON artifact is compared
    against its decoded string values, which is the content the model actually
    read, and the check stays exact against those.
    """
    # Both forms, raw first. Every artifact is rendered to the model through
    # _numbered(), and the same prompt says "copied verbatim from the artifact
    # text" AND "Line numbers when possible" - so a model that does as it is
    # told produces "51: containerd is an open-source container runtime", which
    # is not a substring of anything. CVE-2024-40635 was refused on five
    # citations that were all the prompt's own rendering, with a CORRECT
    # extraction behind them. Trying the raw form first means a quote that
    # genuinely begins with digits and a colon still matches as itself.
    for form in (quote, _unnumbered(quote)):
        if form in text:
            return True
    try:
        document = json.loads(text)
    except ValueError:
        return False
    values = list(_json_strings(document))
    return any(
        form in value for form in (quote, _unnumbered(quote)) for value in values
    )


def _unnumbered(quote: str) -> str:
    """The quote with the prompt's own line numbers taken back off."""
    return "\n".join(re.sub(r"^ *\d+: ?", "", line) for line in quote.splitlines())


def _verify_refs(refs: list[EvidenceRef], texts: dict[str, ArtifactText]) -> None:
    for ref in refs:
        artifact = texts.get(ref.artifact_id)
        if artifact is None:
            raise ExtractorError("evidence_insufficient", f"unknown artifact: {ref.artifact_id}")
        if artifact.sha256 != ref.sha256:
            # Corrected, not refused. The harness supplied the artifact and
            # knows its digest; a model echoing 64 hex characters proves only
            # that it can copy them. And the cost of requiring it was the
            # dominant failure in this harness: version_evidence and
            # artifact_candidates are verified FATALLY, so one wrong character
            # in one citation was evidence_insufficient for the whole CVE -
            # which is what "a lot of evidence_insufficient" turned out to be.
            # The record keeps the real digest either way, so nothing about
            # what the evidence IS depends on the model getting this right.
            ref.sha256 = artifact.sha256
        quote = ref.quote.strip()
        words = len(re.findall(r"[A-Za-z0-9]+", quote))
        if not quote or len(quote) < MIN_QUOTE or words < MIN_QUOTE_WORDS:
            raise ExtractorError(
                "evidence_insufficient",
                f"citation quote is not something a reader could check "
                f"({len(quote)} chars, {words} words; minimum {MIN_QUOTE} and "
                f"{MIN_QUOTE_WORDS}): {quote[:40]!r}",
            )
        if not _quote_present(ref.quote, artifact.text):
            raise ExtractorError(
                "evidence_insufficient",
                f"citation quote not found in artifact {ref.artifact_id}: "
                f"{ref.quote.strip()[:60]!r}",
            )


def _filter_refs(
    refs: list[EvidenceRef], texts: dict[str, ArtifactText]
) -> tuple[list[EvidenceRef], list[str]]:
    """Split citations into the ones that verify and the reasons the rest did not."""
    kept: list[EvidenceRef] = []
    dropped: list[str] = []
    for ref in refs:
        try:
            _verify_refs([ref], texts)
        except ExtractorError as exc:
            dropped.append(str(exc))
            continue
        kept.append(ref)
    return kept, dropped


def verify_facts(facts: Facts, artifacts: list[ArtifactText]) -> None:
    texts = {artifact.artifact_id: artifact for artifact in artifacts}
    # version_evidence backs the affected range and artifact_candidates picks
    # what gets built, so nothing unverified may be USED - but refusing the
    # whole CVE because one quote among several did not verify was the single
    # biggest source of evidence_insufficient in this harness. The lists are
    # filtered like the narrative citations: what verifies is kept, what does
    # not is dropped with its reason. The affected range still may not go
    # unbacked, so a version list that started non-empty and ends empty is
    # refused - and a dropped artifact_candidate costs that candidate, which
    # leaves the operator approving a download instead of facing a dead end.
    facts.version_evidence, lost_version = _filter_refs(facts.version_evidence, texts)
    facts.artifact_candidates, lost_artifact = _filter_refs(facts.artifact_candidates, texts)
    # Not just "all of them dropped": NONE GIVEN passed silently, while one bad
    # quote among two used to be fatal. The affected range is what picks the
    # package version to install, so an unsourced range is the one thing here
    # that must not stand - and every advisory states its own versions, so a
    # citation is always available.
    if facts.affected_range.strip() and not facts.version_evidence:
        raise ExtractorError(
            "evidence_insufficient",
            f"nothing backs the affected range {facts.affected_range[:60]!r}: "
            + ("; ".join(lost_version)[:400] if lost_version else "no citation was given"),
        )
    # The narrative citations are not. One punctuation fragment among a dozen
    # good quotes used to throw away a whole VM build, so a citation that does
    # not verify is dropped and the reason kept - nothing unverified is ever
    # presented as evidence, and the count is recorded as job evidence.
    facts.citations, facts.dropped_citations = _filter_refs(facts.citations, texts)
    facts.dropped_citations = lost_version + lost_artifact + facts.dropped_citations
    # The command a command-only PoC runs is verified as evidence, because
    # that is what makes it a quote rather than something the model wrote.
    # DROPPED rather than fatal, for the same reason citations are: an optional
    # field that does not verify should cost that field, not the whole
    # extraction. Verifying it strictly turned a command the model had tidied -
    # a collapsed space, a smartened quote - into evidence_insufficient for the
    # whole CVE.
    #
    # AFTER the citations, not before: that line ASSIGNS dropped_citations, so
    # a reason appended above it was silently thrown away and the audit trail
    # for the drop went with it.
    if facts.poc_command is not None:
        kept, reasons = _filter_refs([facts.poc_command], texts)
        if not kept:
            facts.poc_command = None
            facts.dropped_citations.extend(reasons)
    if not facts.citations:
        raise ExtractorError(
            "evidence_insufficient",
            "no citation could be verified: " + "; ".join(facts.dropped_citations)[:500],
        )


def direct_extract(artifacts: list[ArtifactText]) -> Facts:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise ExtractorError("provider_unavailable", "DEEPSEEK_API_KEY is missing")
    model = os.environ.get("XENTRY_EXTRACTOR_MODEL") or os.environ.get(
        "XENTRY_VALIDATOR_MODEL", "deepseek/deepseek-chat"
    )
    prompt = _prompt(artifacts)
    try:
        response = litellm.completion(
            model=model,
            api_key=api_key,
            api_base=os.environ.get("DEEPSEEK_API_BASE"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            timeout=120,
        )
    except Exception as exc:
        transcript.record("extract", prompt, f"provider_unavailable: {exc}")
        raise ExtractorError("provider_unavailable", str(exc)) from exc
    content = (response.choices[0].message.content or "").strip()
    # Captured before parsing, so a malformed reply stays inspectable.
    transcript.record("extract", prompt, content)
    parsed = coerce_facts(_parse_json(content), artifacts)
    try:
        facts = Facts.model_validate(parsed)
    except Exception as exc:
        raise ExtractorError("evidence_insufficient", f"facts schema failed: {exc}") from exc
    verify_facts(facts, artifacts)
    return facts


def extract(artifacts: list[ArtifactText], runtime: str | None = None) -> Facts:
    selected = runtime or os.environ.get("XENTRY_AGENT_RUNTIME", "litellm")
    if selected == "adk":
        # ADK is the production extractor. The direct call is the documented
        # fallback when the ADK path is unavailable (Gate F).
        try:
            from xentry.extract_adk import adk_extract

            return adk_extract(artifacts)
        except ExtractorError:
            raise
        except Exception as exc:
            raise ExtractorError("provider_unavailable", f"ADK extractor failed: {exc}") from exc
    return direct_extract(artifacts)
