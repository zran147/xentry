"""FastAPI app for the xentry V1 web flow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from starlette.responses import Response

from xentry import archive, ecosystem, generic, release, sourcestore, transcript
from xentry.broker import BrokerClient, BrokerError
from xentry.bundle import build_bundle
from xentry.db import connect, init_db
from xentry.extract import ArtifactText, ExtractorError, extract
from xentry.fetch import (
    FetchError,
    bundle_sha256,
    fetch,
    fetch_cve_enrichment,
    fetch_cve_evidence,
    fetch_poc_evidence,
    poc_file_url,
)
from xentry.jobstore import (
    count_live_jobs,
    get_check,
    get_job,
    list_artifacts,
    list_environments,
    list_experiments,
    list_held_jobs,
    list_jobs,
    list_steps,
    list_validations,
    now,
    request_cancel,
    request_release,
)
from xentry.runner import JobRunner, RunnerFailure
from xentry.security import constant_time_equal, new_token
from xentry.targets import (
    CATALOG,
    STEPS,
    by_cve,
    by_id,
    by_poc_url,
    resolved_artifacts,
)

ROOT = Path(__file__).resolve().parents[3]
TEMPLATES = ROOT / "src" / "xentry" / "web" / "templates"
STATIC = ROOT / "src" / "xentry" / "web" / "static"


class LinkCheckRequest(BaseModel):
    cve_url: str
    poc_url: str


class ArtifactApprovalRequest(BaseModel):
    check_id: str
    # One URL per line in the form. A CVE often needs more than one file - a
    # config AND the package, a .war AND the runtime - and approving them one
    # at a time meant each click was a separate decision about a set that only
    # makes sense together.
    urls: list[str]


class ExperimentRequest(BaseModel):
    cve_url: str


class EnvironmentRequest(BaseModel):
    job_id: str


class JobCreateRequest(BaseModel):
    cve_url: str
    poc_url: str
    check_id: str


DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "testserver"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _allowed_hosts(extra: str | None = None) -> frozenset[str]:
    configured = extra if extra is not None else os.environ.get("XENTRY_ALLOWED_HOSTS", "")
    hosts = {host.strip().lower() for host in configured.split(",") if host.strip()}
    return DEFAULT_ALLOWED_HOSTS | hosts


def _request_host(request: Request) -> str:
    return (request.url.hostname or "").lower()


def _origin_matches_authority(origin: str, request: Request) -> bool:
    if not origin or origin == "null":
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        origin_port = parsed.port
        request_port = request.url.port
    except ValueError:
        return False
    if origin_port is None:
        origin_port = 443 if parsed.scheme == "https" else 80
    if request_port is None:
        request_port = 443 if request.url.scheme == "https" else 80
    return parsed.hostname.lower() == _request_host(request) and origin_port == request_port


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message}},
        status_code=status,
    )


def _token_path(data_dir: Path) -> Path:
    path = data_dir / "instance" / "token"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(new_token(), encoding="utf-8")
        path.chmod(0o600)
    return path


def _raw_poc_url(target: Any) -> str:
    repo = target.poc.repository.removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{repo}/{target.poc.commit}/README.md"


def _safe_link(url: str) -> str:
    # These are rendered as a clickable href and the API accepts them as plain
    # strings, so only http(s) is linkable; anything else is shown as text.
    value = str(url or "").strip()
    return value if value.lower().startswith(("http://", "https://")) else ""


def _verified_text(path: Path, expected: str) -> str:
    # Stored model text is shown only when it still hashes to what was
    # recorded, matching how the evidence endpoint serves artifacts.
    try:
        body = path.read_bytes()
    except OSError as exc:
        return f"[unavailable: {exc}]"
    if hashlib.sha256(body).hexdigest() != expected:
        return "[hash mismatch; not shown]"
    return body.decode("utf-8", "replace")


def _environment_details(job: dict[str, Any]) -> dict[str, Any]:
    # Live state, not evidence: written when the environment came up and
    # deleted when it is torn down, so nothing hashes it.
    path = Path(str(job.get("attempt_dir") or "")) / "environment.json"
    try:
        return dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return {}


def _rebuild_candidates(conn: sqlite3.Connection, data_dir: Path) -> list[dict[str, Any]]:
    # The most recent completed job per CVE. A rebuild takes only that job's
    # target id and CVE id: the image, the setup script and the pinned PoC all
    # come from the checked-in TargetInstance, so there is nothing to fetch and
    # no link check to depend on. The job is the unit offered because it is the
    # evidence that this target did build - not because it stores the inputs.
    #
    # A derived target used to be excluded here, because rebuilding one means
    # rebuilding the target itself and there is no checked-in instance to look
    # up by id. That reason was only half right: the facts the check ADMITTED
    # are stored, and so now is the release that answered, so a derived
    # rebuild replays both rather than looking anything up.
    #
    # What it cannot survive is the retention sweep - the store keeps a check
    # for sourcestore.RETENTION_S and prunes by age - so a derived job is
    # offered only while its facts are still there. That keeps the original
    # rule intact: offering a rebuild that fails on the click is worse than
    # not offering it.
    rows = conn.execute(
        "SELECT j.id AS job_id, j.cve_id, j.target_id, j.poc_url, j.check_id, "
        "MAX(j.created_at) AS created_at "
        "FROM jobs j WHERE j.kind='job' AND j.outcome='completed' "
        "AND j.cve_id IS NOT NULL AND j.target_id IS NOT NULL "
        "GROUP BY j.cve_id ORDER BY j.cve_id",
    ).fetchall()
    offered = []
    for row in rows:
        item = dict(row)
        if str(item.get("target_id") or "") == generic.GENERIC_ID and not (
            item.get("check_id")
            and sourcestore.load_facts(data_dir, str(item["check_id"]))
        ):
            continue
        offered.append(item)
    return offered


def _criteria(artifacts: list[dict[str, Any]], attempt_dir: Path) -> dict[str, Any]:
    """The claims this job recorded at plan time, checked against their digest."""
    path = attempt_dir / "criteria.json"
    expected = ""
    for item in artifacts:
        if str(item.get("name") or "") == "criteria.json":
            expected = str(item.get("sha256") or "")
    try:
        raw = path.read_bytes()
    except OSError:
        return {}
    if expected and hashlib.sha256(raw).hexdigest() != expected:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _held_details(job: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    # list_artifacts does not return paths, so the record is located from the
    # attempt directory and still checked against the digest that was recorded.
    expected = ""
    for item in artifacts:
        if str(item.get("kind") or "") == "held_vms":
            expected = str(item.get("sha256") or "")
    if not expected:
        return {}
    path = Path(str(job.get("attempt_dir") or "")) / "held-vms.json"
    try:
        parsed = json.loads(_verified_text(path, expected))
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


HEREDOC_RE = re.compile(r"<<-?\s*'?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)'?")


def evidence_media(path: Path) -> str:
    """Classify an artifact by its contents, which is the only reliable way.

    The CVE artifact is still written as cve.html but now holds NVD's JSON
    record, so the file name says nothing about what is in it.
    """
    try:
        with path.open("rb") as handle:
            head = handle.read(512).lstrip()
    except OSError:
        return "text"
    if head[:1] in (b"{", b"["):
        return "json"
    if head[:14].lower() in (b"<!doctype html", b"<html") or head[:5].lower() == b"<html":
        return "html"
    return "text"


def asset_version() -> str:
    """A cache key for the static assets, taken from their CONTENT.

    A hand-maintained ?v= string is one forgotten bump away from a browser
    serving a stale script from cache under an unchanged URL, which is how a
    working page can look broken after a deploy. Derived here instead, so it
    cannot be forgotten - and now from the bytes rather than from mtimes,
    which had two holes: the list of files was hand-written, so a third asset
    would have been invisible to it, and int(st_mtime) has one-second
    resolution, so two writes in the same second shared a key. Content cannot
    be wrong about whether it changed, and with Cache-Control immutable on
    /static this string is the only thing that expires a cached asset.
    """
    digest = hashlib.sha256()
    for path in sorted(STATIC.rglob("*")):
        if not path.is_file():
            continue
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _provision_plan(job: dict[str, Any], limit: int = 300) -> list[str]:
    # The provisioning script is recorded before the step runs, so the commands
    # it is about to run can be shown while the step is still in flight. This is
    # source order, not progress: it says what will run, never where it is.
    path = Path(str(job.get("attempt_dir") or "")) / "setup.sh"
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    commands: list[str] = []
    pending = ""
    heredoc = ""
    for raw in source.splitlines():
        line = raw.rstrip()
        if heredoc:
            # Heredoc bodies are data the script writes out, not commands.
            if line.strip() == heredoc:
                heredoc = ""
            continue
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        pending = f"{pending} {stripped}" if pending else stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        found = HEREDOC_RE.search(pending)
        if found:
            heredoc = found.group("tag")
        commands.append(pending)
        pending = ""
    if pending:
        commands.append(pending)
    return commands[:limit]


TRACED_STEPS = ("provision", "real_actor")


def _step_commands(job: dict[str, Any], limit: int = 300) -> dict[str, list[str]]:
    # Collected by the runner for the steps it traces, keyed by step name. The
    # leading xtrace markers are stripped so each line reads as a command, and
    # only the tail is sent because this is re-sent on every stream tick.
    root = Path(str(job.get("attempt_dir") or ""))
    found: dict[str, list[str]] = {}
    for name in TRACED_STEPS:
        try:
            raw = (root / f"{name}-commands.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rows = [stripped for line in raw.splitlines() if (stripped := line.lstrip("+ ").strip())]
        if rows:
            found[name] = rows[-limit:]
    return found


def _llm_calls(artifacts: list[dict[str, Any]], attempt_dir: Path) -> list[dict[str, Any]]:
    # Transcripts are recorded as artifacts named llm_<stage>_<prompt|response>.
    # The bundle keeps only file names and a relative attempt directory, by
    # design, so the real directory is passed in from the job row.
    root = attempt_dir / "llm"
    stages: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        parts = str(item.get("kind") or "").split("_")
        if len(parts) != 3 or parts[0] != "llm":
            continue
        _, stage, part = parts
        entry = stages.setdefault(
            stage,
            {
                "stage": stage,
                "prompt": "",
                "response": "",
                "prompt_sha256": "",
                "response_sha256": "",
                "prompt_bytes": 0,
                "response_bytes": 0,
            },
        )
        entry[part] = _verified_text(
            root / str(item.get("name") or ""), str(item.get("sha256") or "")
        )
        entry[f"{part}_sha256"] = str(item.get("sha256") or "")
        entry[f"{part}_bytes"] = item.get("bytes")
    return [stages[name] for name in sorted(stages)]


def _needs_artifact_plan(exc: Any, payload: Any, data_dir: Path) -> dict[str, Any]:
    """A check the operator can make runnable by approving one download."""
    now_dt = datetime.now(UTC)
    bundle = bundle_sha256([exc.cve, exc.poc])
    check_id = getattr(exc, "check_id", "") or uuid.uuid4().hex
    items = {"cve": exc.cve, "poc": exc.poc}
    if exc.nvd is not None:
        items["nvd"] = exc.nvd
    sourcestore.save(data_dir, check_id, items)
    # Under its own prefix: the operator's approval replaces every "artifact",
    # and a file from the PoC's repository is not theirs to replace.
    if getattr(exc, "repo_file", None) is not None:
        sourcestore.add(data_dir, check_id, "repo0", exc.repo_file)
    return {
        "state": "needs_artifact",
        "check_id": check_id,
        "cve_id": exc.cve_id,
        # What it will be once a file is approved; the apt step is the same
        # step either way, which is why there is no third target id.
        "target_id": generic.GENERIC_ID,
        "bundle_sha256": bundle,
        "created_at": now_dt.isoformat(),
        "expires_at": (now_dt + timedelta(minutes=30)).isoformat(),
        "detail": exc.detail,
        # In the order they were tried. This is the record that the download
        # is a last resort and not a shortcut past the archives.
        "channels": exc.channels,
        "accepts": sorted(generic.INSTALL_VERBS),
        # Prefilled into the approval input when an archive still publishes the
        # affected version, so the usual answer is "yes, that one" rather than
        # going to find it. Empty leaves the field as it was.
        "suggested_urls": list(getattr(exc, "suggested", []) or []),
    }


def _suggested_file(facts: Any, poc_url: str) -> list[str]:
    """Every file the card should offer, in the order to install them.

    One function, called from both last-resort paths, because having it inline
    at one of them meant the other offered nothing. A placement needs the file
    the PoC itself ships - the config that makes the software vulnerable, which
    no archive carries because it is not part of any package. A missing package
    needs the software. These are ALTERNATIVES, not a set: offering both made
    CVE-2021-41773 read as though the archive had not been used, when apache2
    2.4.49-4 resolves from Debian sid and only the config is missing - see
    ADR 34e.
    """
    # A file from the PoC's own repository is NOT suggested, because it is
    # not asked for: the check above fetches it and attaches it to this very
    # refusal as repo_file. Suggesting it put kozmer's own
    # target/log4shell-1.0-SNAPSHOT.war in the approval box for
    # CVE-2021-44228, asking the operator to approve bytes the harness had
    # already taken on the stated grounds that a file beside the exploit is no
    # new decision. What a card still has to offer is the software itself,
    # which no repository ships: an official .deb of the affected version.
    wanted = release.deb_url(
        facts.setup_packages[0] if facts.setup_packages else "",
        facts.affected_range,
        fetch,
    )
    return [wanted] if wanted else []


class _NeedsArtifact(Exception):
    """Every channel was tried and only a download is missing.

    Carried rather than raised as an HTTP error because the answer is not "no":
    it is "not from any archive, and here is what was tried". The channels are
    the evidence an operator needs to judge whether approving a download is
    reasonable, and they are collected as each one is actually attempted -
    which is what makes the offer a last resort rather than a first guess.
    """

    def __init__(
        self,
        channels: list[dict[str, str]],
        detail: str,
        *,
        cve: Any = None,
        poc: Any = None,
        nvd: Any = None,
        cve_id: str = "",
        check_id: str = "",
        suggested: list[str] | None = None,
        repo_file: Any = None,
    ) -> None:
        super().__init__(detail)
        self.channels = channels
        self.detail = detail
        # The fetched sources travel with the signal: the plan has to store
        # the same bytes any other check stores, and re-fetching them would
        # produce a different bundle digest.
        self.cve = cve
        self.poc = poc
        self.nvd = nvd
        self.cve_id = cve_id
        # The same id the transcript was filed under, so a plan, a refusal and
        # the model's own reply are all findable from one string.
        self.check_id = check_id
        # An official .deb for the affected version, if an archive still has
        # one. Offered, never used on its own: the operator still approves it.
        self.suggested = suggested or []
        # Already fetched from the PoC's own repository, so it travels with the
        # signal: a check that still needs something else must not lose the
        # file it already has.
        self.repo_file = repo_file


def _link_check(cve_url: str, poc_url: str, *, store_root: Path | None = None) -> dict[str, Any]:
    target_hint = by_poc_url(poc_url)
    cve = fetch_cve_evidence(cve_url, fetch)
    if target_hint is not None:
        poc = fetch(_raw_poc_url(target_hint))
    else:
        poc = fetch_poc_evidence(poc_url, fetch)
    # NVD's record as a third artifact when it answers. It carries CVSS
    # metrics the CNA record usually does not, and that is what the extractor
    # reads a protocol out of when the advisory prose names none.
    nvd = fetch_cve_enrichment(cve_url, fetch)
    artifacts = [
        ArtifactText("cve", cve.sha256, cve.text),
        ArtifactText("poc", poc.sha256, poc.text),
    ]
    if nvd is not None:
        artifacts.append(ArtifactText("nvd", nvd.sha256, nvd.text))
    # An id and a transcript for EVERY check, refusal included.
    # transcript.record() returns early when no sink is installed and the web
    # app installed none, so a check's extraction was recorded nowhere at all:
    # every question about a refusal had to be answered by running it again and
    # reading an error string. The id is generated here rather than at the end
    # so a refusal can carry it too.
    check_id = uuid.uuid4().hex
    if store_root is not None:
        def _sink(stage: str, prompt: str, response: str) -> None:
            where = store_root / "checks" / check_id
            where.mkdir(parents=True, exist_ok=True)
            (where / f"{stage}.prompt.txt").write_text(prompt, encoding="utf-8")
            (where / f"{stage}.response.txt").write_text(response, encoding="utf-8")

        transcript.set_sink(_sink)
    try:
        facts = extract(artifacts)
    except ExtractorError as exc:
        # The transcript exists for refusals above all, and until now the id it
        # was filed under died with the exception: the reply to a refused check
        # was written to disk and then made unreachable.
        exc.check_id = check_id
        raise
    finally:
        # Per thread, so leaving it installed would file the NEXT request's
        # extraction under this check's id.
        transcript.set_sink(None)
    target = by_cve(facts.cve_id)
    derived = target is None
    # Appended to as each channel is tried, in the order they are tried. The
    # download approval is offered only once this list is complete.
    channels: list[dict[str, str]] = [
        {
            "channel": "a checked-in target",
            "verdict": "none is pinned for this CVE"
            if target is None
            else f"{target.target_id}, reviewed and pinned",
        }
    ]
    # Named on either last-resort path, because "no archive carries this" is
    # the wrong answer when the archive that does was never built here.
    # CVE-2021-41773 is Apache 2.4.49: only Debian ever carried it, and with
    # debian-12-generic-image unpinned the resolver had nothing but Ubuntu to
    # ask - and said nothing about that.
    _pinned = resolved_artifacts()
    _unbuilt = [item for item in release.RELEASES if item.artifact_id not in _pinned]
    unbuilt_note = (
        {
            "channel": "an apt archive, not consulted",
            "verdict": "no image is built and pinned for "
            + ", ".join(f"{item.archive} {item.suite}" for item in _unbuilt)
            + "; build with scripts/build-images.sh --execute"
            + "".join(f" --only {item.image_id}" for item in _unbuilt),
        }
        if _unbuilt
        else None
    )
    # One day before publication, needed by the release sweep below as well as
    # by the plan, so it is derived once here rather than at each use.
    serial = generic.snapshot_for(generic.advisory_published(cve.text))
    ecosystem_target = None
    # Set on the derived path only, but read at the end by every path - a
    # checked-in target never reaches the block that assigns it.
    from_repo = None
    resolution = None
    usable: tuple[release.Release, ...] = ()
    if target is None:
        # No checked-in target: derive one, or say why this CVE cannot be run.
        # The refusal reaches the form, so a reader learns at submit time rather
        # than from a failed job.
        # An application-package lab first, on the same terms as the runner:
        # the lab's package.json is read as evidence, nothing in it is run, and
        # the job is offered only if a closure for that exact dependency set is
        # already pinned. The refusal names the command that pins it, which is
        # the whole reason this runs at the form rather than in the job.
        if facts.app_dir is not None:
            try:
                manifest = fetch(ecosystem.manifest_url(poc_url, facts.app_dir))
                ecosystem_target, _ = ecosystem.select(
                    facts, poc_url, manifest.body.decode("utf-8", "replace")
                )
                if ecosystem_target is not None and not generic.cutoff_for(
                    generic.advisory_published(cve.text)
                ):
                    # The mirror is dated from the advisory, so an advisory
                    # with no usable date has nothing to resolve against.
                    # Refused here rather than at the fourth step of a job
                    # that has already built a network and a VM.
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            f"no_observable [{check_id}]: this advisory carries no "
                            "usable publication date, so there is no date to resolve "
                            "the lab's dependencies at; an ecosystem target cannot be "
                            "pinned without one"
                        ),
                    )
            except FetchError:
                ecosystem_target = None
                channels.append({
                    "channel": "an application-package lab",
                    "verdict": f"no manifest at {facts.app_dir or 'the repository root'}",
                })
            except ecosystem.NoEnvironment as exc:
                # The apt path may still run this CVE: app_dir is a model's
                # reading of a README, not a guarantee.
                ecosystem_target = None
                channels.append({
                    "channel": "an application-package lab",
                    "verdict": str(exc),
                })
        else:
            channels.append({
                "channel": "an application-package lab",
                "verdict": "the PoC ships no directory that builds the application",
            })
        if ecosystem_target is not None:
            channels.append({
                "channel": "an application-package lab",
                "verdict": f"{facts.app_dir or 'the repository root'}, resolved against "
                "the dated registry mirror",
            })
        # A file from the PoC's OWN repository needs no approval. If that
        # repository were malicious its exploit already is, and that exploit
        # runs either way - so a config or a .war sitting beside it is no
        # decision the operator has not already made by submitting the URL.
        #
        # The URL is built by the harness from the pinned poc_url and a
        # repo-relative path, never taken from the model: it can name a file
        # INSIDE that repository and nowhere else, and poc_file_url refuses
        # anything that climbs out. The digest is still recorded, because the
        # approval was never only a gate - it is also how the record says what
        # the job installed.
        #
        # One asymmetry worth naming rather than glossing: the PoC runs
        # unprivileged on the ATTACKER, while a .deb from the same repository
        # is dpkg -i as root on the TARGET. Both are inside the same
        # disposable VM, which decision 1 makes the boundary, so this is not
        # an escalation - but it is not identical either.
        wanted = poc_file_url(poc_url, facts.place_file or "")
        if wanted:
            try:
                from_repo = fetch(wanted)
                generic.install_verb(
                    generic.artifact_name(
                        Path(urlsplit(from_repo.final_url).path).name
                    )
                )
            except (FetchError, generic.NoObservable) as exc:
                raise HTTPException(422, f"{wanted} [{check_id}]: {exc}") from exc
        repo_sha = from_repo.sha256 if from_repo is not None else ""
        try:
            if ecosystem_target is not None:
                generic.entrypoint(facts)
            else:
                # The entrypoint first, because it is the most fundamental
                # thing that can be missing and derive() does not check it:
                # blasty's CVE-2021-41773 repository is a vulnerable-target
                # recipe - a Dockerfile, a compose file, four vendored .debs -
                # with the exploit written as a curl line in the README and no
                # script anywhere. Checked second, it was reported as "names no
                # Ubuntu package to install", which sent the reader looking for
                # a package when nothing was ever going to be run.
                generic.entrypoint(facts)
                # Then admission, so a CVE this harness cannot observe is
                # refused before any archive lookup: derive() raises that.
                generic.derive(facts, poc_url, artifact=repo_sha)
                generic.tokens(facts.setup_packages, "package")
                generic.tokens(facts.setup_units, "unit")
        except generic.NoObservable as exc:
            if generic.needs_a_download(facts):
                # Every other reason to refuse is absent: remote PoC, a known
                # port, a protocol the harness opens. The only gap is that
                # nothing here says how to install the affected software, and
                # that is the one gap a download can close.
                channels.append({
                    "channel": "an apt archive",
                    "verdict": str(exc),
                })
                if unbuilt_note:
                    channels.append(unbuilt_note)
                raise _NeedsArtifact(
                    channels,
                    str(exc),
                    cve=cve,
                    poc=poc,
                    nvd=nvd,
                    cve_id=facts.cve_id,
                    check_id=check_id,
                    # This site had no suggestion at all, which is the one the
                    # placement refusal actually comes out of - so the card
                    # appeared with an empty field for exactly the case the
                    # suggestion was written for.
                    suggested=_suggested_file(facts, poc_url),
                    repo_file=from_repo,
                ) from exc
            # Whatever the extractor said and could not back up goes in the
            # message. Without it a dropped poc_command reads as "the PoC text
            # does not name a file that runs the exploit" - true, and silent
            # about the command that WAS found and then failed its quote check.
            # And an id, so a refusal can be referred to at all: a 422 carried
            # no check_id, so there was nothing to quote back.
            dropped = "; ".join(facts.dropped_citations)[:400]
            raise HTTPException(
                status_code=422,
                detail=f"no_observable [{check_id}]: {exc}"
                # "also" read as a contributing cause. It is not one: a
                # dropped citation is a note about the reply, and the refusal
                # above stands on its own. CVE-2021-43798 refused for having
                # no entrypoint and the message trailed a dropped '= 8.3.0',
                # which looked like the reason and was not.
                + (f" (separately, a citation the extractor could not back "
                   f"up was dropped: {dropped})" if dropped else ""),
            ) from exc
        if ecosystem_target is not None:
            target = ecosystem_target
        # Which release can install the affected version, looked up in the
        # archive's own publication record. Done here as well as in the runner
        # so the answer is in the plan the reader approves, and so a CVE no
        # built release can host is refused at the form.
        if target is None:
            usable = tuple(release.available(release.RELEASES, resolved_artifacts()))
        if target is None:
            if not usable:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"no built release existed at {serial or 'this serial'} "
                        f"[{check_id}]; every generic base image is newer than "
                        "the advisory, or none is built - build one with "
                        "scripts/build-images.py"
                    ),
                )
            # EVERY built release answers before anything is refused.
            #
            # Driving this off release.resolve() over a shrinking pool did NOT
            # do that, and claiming it did was wrong: resolve matches on what
            # an archive EVER carried and returns None for its own reasons - no
            # version prefix, no ceiling, no hit - so it gives up while the
            # pool still holds a release whose DATED index carries an affected
            # build, and the sweep then refused without that release ever being
            # asked. by_package, the fallback the undated path uses, was not
            # being tried per release either.
            #
            # So the loop is over the releases themselves, resolve is asked
            # about one release at a time, and every release contributes a
            # sentence to `answers` whether it matched, missed, or carried the
            # wrong build. A refusal prints all of them, so "all of them were
            # asked" is visible rather than asserted.
            # Asking one release at a time inverts resolve()'s nesting, and
            # resolve's docstring names the bug that causes: "nested the other
            # way round that fallback was tried on the first release before
            # the exact prefix was tried on any later one". Measured on
            # CVE-2021-44790 - it chose focal's 2.4.41 on the fallback prefix
            # "2.4" while sid carries the exact 2.4.51. So the pass runs twice:
            # exact matches across every release first, fallback matches only
            # after all of them have been tried. Resolution.exact is the flag
            # for that distinction and already exists.
            answers: list[str] = []
            for exact_only in (True, False) if serial else ():
                for item in usable:
                    candidate = release.resolve(
                        facts.setup_packages, facts.affected_range, (item,), fetch,
                        facts.fixed_versions,
                    )
                    if candidate is None and not release.version_prefixes(
                        facts.affected_range
                    ):
                        candidate = release.by_package(
                            facts.setup_packages, (item,), fetch
                        )
                    if candidate is None:
                        # Recorded on the second pass only, or every release
                        # would answer twice in the refusal.
                        if not exact_only:
                            answers.append(
                                f"{item.archive} {item.suite} publishes no version "
                                f"this advisory names"
                            )
                        continue
                    # Each release is handled by exactly one pass - the
                    # exact one if its match is exact - so no release answers
                    # twice and no index is fetched twice.
                    if exact_only != candidate.exact:
                        continue
                    gap = archive.refusal(
                        candidate.package, candidate.prefix, serial,
                        item.suite, item.archive, fetch,
                        release.upper_bound(
                            facts.affected_range,
                            facts.fixed_versions or [],
                            candidate.prefix,
                        ),
                        release.segments(facts.affected_range),
                    )
                    if not gap and not release.existed(item, serial):
                        # It ANSWERED - the guarantee that every built release
                        # does is untouched - but it cannot be chosen: its
                        # dated index exists only because it was in development
                        # then, and a development suite is not the archive as
                        # it was. CVE-2022-0543 resolved to jammy at 20220217,
                        # two months before jammy released, and the job then
                        # asked the proxy for a released index that has never
                        # existed.
                        gap = (
                            f"{item.archive} {item.suite} had not been released at "
                            f"{serial}: version {item.version} dates it later"
                        )
                    if not gap:
                        resolution = candidate
                        break
                    answers.append(gap)
                if resolution is not None:
                    break
            if not serial:
                resolution = release.resolve(
                    facts.setup_packages,
                    facts.affected_range,
                    usable,
                    fetch,
                    facts.fixed_versions,
                )
            if resolution is None and not serial and not release.version_prefixes(
                facts.affected_range
            ):
                # No version to match is not the same gap as no archive
                # carrying the affected build, and it does not have to stop
                # the job: the serial is already one day before publication,
                # so whatever it carries predates the fix. The version simply
                # cannot be asserted, which the target says in its caveats.
                resolution = release.by_package(facts.setup_packages, usable, fetch)
            if facts.setup_packages and resolution is None:
                # The archives were queried and none of them carries it. This
                # is the other shape of the same gap: CVE-2021-41773 lands
                # here when Debian is not built, and a product that was never
                # packaged lands here whenever its PoC names a package name.
                detail = release.unresolved(
                    facts.setup_packages, facts.affected_range
                )
                if answers:
                    # What EVERY built release answered, so a reader can see
                    # that each was asked rather than take it on trust. Not a
                    # hard refusal: this is the gap the artifact path already
                    # covers, so approving a build stays open.
                    detail += (
                        f" - every built release was asked at {serial}: "
                        + "; ".join(answers)
                    )
                channels.append({
                    "channel": "an apt archive ("
                    + ", ".join(f"{item.archive} {item.suite}" for item in usable)
                    + ")",
                    "verdict": detail,
                })
                if unbuilt_note:
                    channels.append(unbuilt_note)
                raise _NeedsArtifact(
                    channels,
                    detail,
                    cve=cve,
                    poc=poc,
                    nvd=nvd,
                    cve_id=facts.cve_id,
                    check_id=check_id,
                    suggested=_suggested_file(facts, poc_url),
                    repo_file=from_repo,
                )
            channels.append({
                "channel": f"an apt archive ({resolution.release.archive} "
                f"{resolution.release.suite})" if resolution else "an apt archive",
                "verdict": release.verdict(resolution, facts.affected_range),
            })
            # Derived again, now with the release this CVE resolved to.
            target = generic.derive(
                facts, poc_url, resolution, usable[0], repo_sha
            )
    else:
        normalized = poc_url.rstrip("/").removesuffix(".git")
        expected = target.poc.repository.rstrip("/").removesuffix(".git")
        if normalized != expected:
            raise HTTPException(status_code=422, detail=f"PoC does not match the target pin [{check_id}]")
    # The apt path and the ecosystem path are both "derived"; only the first
    # resolves an archive release, so only its fields are filled in below.
    # A privesc PoC that demands root cannot be run by the actor, and running
    # it as root would prove nothing - root reading a root-only nonce is not an
    # escalation. Refused here rather than after a VM, a provision and a
    # readiness probe: CVE-2026-96512 reached the exploit step, thirteen steps
    # in, to say "run as root - this rewrites /etc/sudoers".
    if derived and facts.poc_context == "local" and generic.wants_root(poc.text):
        raise HTTPException(
            status_code=422,
            detail=(
                f"unsupported_poc [{check_id}]: this PoC refuses to run as anyone but "
                "the unprivileged actor cannot run it - and running it as root "
                "would prove nothing, because root reading a root-only file is "
                "not an escalation. It is written to build its own vulnerable "
                "configuration and then test it, which is a lab rather than an "
                "exploit this harness can witness"
            ),
        )
    # A Dockerfile build is refused HERE if it cannot be built offline, rather
    # than after a VM, a provision and a container build: CVE-2025-32433 spent
    # seven steps to reach "Temporary failure resolving 'deb.debian.org'", and
    # the Dockerfile text says so at the check. The base image is no longer the
    # question - the mirror serves any Docker Hub repository now - so what is
    # left to ask is whether the build adds undated software.
    if derived and facts.dockerfile is not None:
        where = f"{facts.dockerfile}/Dockerfile".lstrip("/")
        try:
            body = fetch(poc_file_url(poc_url, where)).text
        except FetchError:
            body = ""
        gap = generic.docker_refusal(body)
        if gap:
            raise HTTPException(status_code=422, detail=f"unsupported_poc [{check_id}]: {gap}")
    apt = derived and ecosystem_target is None
    # The archive's OWN answer, before a VM exists. published_versions says
    # what an archive ever carried and defers the dated question to readiness;
    # readiness cannot answer it when expected_version is empty, which the
    # by_package and ceiling-sweep paths leave so on purpose. Measured over the
    # checks admitted on 2026-11-15: ten of fifteen would have failed at
    # provisioning, and two of those would have provisioned an already-fixed
    # build and reported "did not reproduce".
    if apt and not serial:
        raise HTTPException(status_code=422, detail=(
            f"unsupported_target [{check_id}]: this advisory carries no date this "
            "provision from. It installs from one day before publication and "
            f"verifies no archive older than {generic.SNAPSHOT_FLOOR.date()}; "
            "today's would reproduce nothing"
        ))
    if apt and resolution is not None and target is not None:
        chosen = generic.release_for(resolution, usable[0] if usable else None)
        # Every OTHER package provisioning installs has to exist too - the
        # sweep above already asked this release's dated index about the
        # subject at this very prefix, so re-asking refetches 8.8 MB of sid
        # for an answer already in hand. A placement's package is the one that
        # bites: "tomcat" is not a Debian package - tomcat9 is - and
        # PLACEMENT_NEEDS admits it on a substring, so the job provisioned and
        # died in the guest with "no tomcat webapps directory".
        installs = {
            name
            for name in list(facts.setup_packages)
            + [generic.PLACEMENT_NEEDS.get(facts.place or "", "")]
            if name and name != resolution.package
        }
        for name in sorted(installs):
            gap = archive.refusal(name, "", serial,
                                  chosen.suite, chosen.archive, fetch)
            if gap:
                raise HTTPException(
                    status_code=422, detail=f"unsupported_target [{check_id}]: {gap}"
                )
    bundle = bundle_sha256([cve, poc])
    # The job run must use these exact bytes. Re-fetching cannot prove the sources
    # are unchanged: a CDN-served page carries per-request data (a Cloudflare ray
    # id, a beacon token), so a second fetch of identical content hashes
    # differently and the bundle digest never matches.
    if store_root is not None:
        # The bundle digest stays over cve and poc, which is what the job was
        # told to expect; the enrichment rides along so the job's extraction
        # sees exactly what the form's did.
        items = {"cve": cve, "poc": poc}
        if nvd is not None:
            items["nvd"] = nvd
        sourcestore.save(store_root, check_id, items)
        # And the facts this check admitted, so the job runs the plan the
        # operator approved rather than a second reading of the same bytes.
        sourcestore.save_facts(store_root, check_id, facts.model_dump_json())
        # Added, not saved with the rest, so the bundle digest stays over the
        # sources the job was told to expect.
        if from_repo is not None:
            sourcestore.add(store_root, check_id, "repo0", from_repo)
    now_dt = datetime.now(UTC)
    return {
        "check_id": check_id,
        "cve_id": facts.cve_id,
        "target_id": target.target_id,
        "bundle_sha256": bundle,
        "created_at": now_dt.isoformat(),
        "expires_at": (now_dt + timedelta(minutes=30)).isoformat(),
        "plan": {
            "target_id": target.target_id,
            "cve_id": facts.cve_id,
            "base_image_id": target.base_image_id,
            "attacker_profile_id": target.attacker_profile_id,
            "network_profile_id": target.network_profile_id,
            "target_ports": list(target.target_ports),
            "nonce_path": target.nonce.path,
            "nonce_owner": target.nonce.owner,
            "nonce_mode": target.nonce.mode,
            "probe_step_id": target.probe_step_id,
            "poc_commit": target.poc.commit,
            "setup_sha256": target.setup_sha256,
            # Stated in the plan the reader approves, not only in the verdict:
            # a derived target has had no human look at its setup or its
            # evidence design, and its evidence is attacker-attested.
            "derived": derived,
            "authority": (
                "guest_attested+llm_assessed" if derived else "runner_observed+llm_assessed"
            ),
            "packages": " ".join(facts.setup_packages) if apt else "",
            # An ecosystem target resolves the lab's dependencies against the
            # job's dated registry mirror, and runs a second build with the
            # subject moved to the fixed version when the advisory names one.
            "control_port": target.control_port,
            "subject_package": target.subject_package,
            "fixed_version": target.fixed_version,
            # The release chosen for this CVE and why: which package version
            # the archive carries, and what readiness will assert.
            "release": target.base_image_id if apt else "",
            "suite": generic.release_for(resolution, usable[0]).suite if apt else "",
            "resolved_package": resolution.package if apt and resolution else "",
            "archive_version": resolution.version if apt and resolution else "",
            "expected_version": target.expected_version if apt else "",
            # Which archive state the packages come from. Empty means the
            # advisory carried no usable date and the broker's default applies,
            # which for a CVE this recent usually means the patched build.
            "apt_snapshot": serial if apt else "",
            "poc_entrypoint": facts.poc_entrypoint if derived else "",
            "caveats": list(target.what_does_not_prove) if derived else [],
        },
    }


def build_app(
    *,
    data_dir: Path,
    db_path: Path,
    broker_socket: Path,
    runner: JobRunner | None = None,
    allowed_hosts: str | None = None,
) -> FastAPI:
    hosts = _allowed_hosts(allowed_hosts)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        conn = init_db(db_path)
        conn.close()
        app.state.token = _token_path(data_dir).read_text(encoding="utf-8").strip()
        app.state.runner = runner or JobRunner(
            db_path=db_path,
            data_dir=data_dir,
            broker_socket=broker_socket,
            hold_s=float(os.environ.get("XENTRY_HOLD_S", "0")),
            job_deadline_s=float(os.environ.get("XENTRY_JOB_DEADLINE_S", "7200")),
            target_deadlines={
                "php2shell": float(os.environ.get("XENTRY_JOB_TIMEOUT_PHP", "5400")),
                "gitlab": float(os.environ.get("XENTRY_JOB_TIMEOUT_GITLAB", "7200")),
                "dirtyfrag": float(os.environ.get("XENTRY_JOB_TIMEOUT_DIRTYFRAG", "5400")),
            },
        )
        app.state.runner.start()
        yield
        app.state.runner.stop()

    app = FastAPI(title="xentry", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    templates = Jinja2Templates(directory=str(TEMPLATES))
    # A callable, so an asset edited without a restart is still picked up.
    templates.env.globals["asset_v"] = asset_version

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method not in SAFE_METHODS:
            host = _request_host(request)
            if not host or host not in hosts:
                return _error(403, "host_invalid", "Host header is not allowed")
            origin = request.headers.get("origin")
            if origin is not None and not _origin_matches_authority(origin, request):
                return _error(403, "origin_invalid", "Origin does not match this host")

            token = getattr(request.app.state, "token", "")
            cookie = request.cookies.get("xentry_token", "")
            header = request.headers.get("x-xentry-csrf", "")
            if not token or not cookie:
                return _error(401, "token_missing", "missing token cookie")
            if not constant_time_equal(cookie, token):
                return _error(401, "token_invalid", "invalid token cookie")
            if not header or not constant_time_equal(header, token):
                return _error(403, "csrf_invalid", "missing or invalid CSRF header")

            media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                return _error(400, "validation", "JSON content type required")
        response = await call_next(request)
        # setdefault: a route that serves fetched HTML sets a stricter
        # sandbox policy of its own, and it must survive this.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        # Nothing here was cacheable and nothing said so. GET / is what SETS
        # the token cookie, so a browser serving that page from its own cache
        # never receives the Set-Cookie and every POST then fails
        # token_missing - a page that looks fine and is dead until a hard
        # reload, which is the question "do I have to refresh the page?" in
        # its purest form. An /api GET served from cache freezes a job list
        # the same way. /static is the opposite: it carries ?v=<content
        # digest> in its URL, so it may be cached hard and for a year.
        if request.url.path.startswith("/static/"):
            response.headers.setdefault(
                "Cache-Control", "public, max-age=31536000, immutable"
            )
        else:
            response.headers["Cache-Control"] = "no-store"
        return response

    def db() -> sqlite3.Connection:
        return connect(db_path)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        conn = db()
        try:
            jobs = list_jobs(conn)
        finally:
            conn.close()
        response = templates.TemplateResponse(
            request,
            "index.html",
            {"jobs": jobs, "csrf": app.state.token},
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token",
                app.state.token,
                httponly=True,
                samesite="strict",
            )
        return response

    @app.post("/api/experiments")
    def submit_experiment_api(payload: ExperimentRequest) -> dict[str, Any]:
        """Queue an experiment from a CVE link alone.

        No link check and no PoC: a model writes the exploit from the advisory.
        Nothing here is pinned, which is why these never enter the job list.
        """
        if not os.environ.get("XENTRY_POC_MODEL"):
            raise HTTPException(
                status_code=422,
                detail="XENTRY_POC_MODEL is not set; no model is configured to write a PoC",
            )
        try:
            job_id = app.state.runner.submit_experiment(payload.cve_url)
        except RunnerFailure as exc:
            raise HTTPException(status_code=422, detail=f"{exc.code}: {exc}") from exc
        return {"job_id": job_id, "state": "queued"}

    @app.get("/experiments", response_class=HTMLResponse)
    def experiments_page(request: Request) -> HTMLResponse:
        conn = db()
        try:
            runs = list_experiments(conn)
            held = [
                {"job": job, "held": _held_details(job, list_artifacts(conn, job["id"]))}
                for job in list_held_jobs(conn, kind="experiment")
            ]
        finally:
            conn.close()
        response = templates.TemplateResponse(
            request,
            "experiments.html",
            {
                "runs": runs,
                "held": held,
                "model": os.environ.get("XENTRY_POC_MODEL", ""),
                "attempts": os.environ.get("XENTRY_POC_ATTEMPTS", "3"),
                "csrf": app.state.token,
            },
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token", app.state.token, httponly=True, samesite="strict"
            )
        return response

    @app.post("/api/environments")
    def build_environment_api(payload: EnvironmentRequest) -> dict[str, Any]:
        conn = db()
        try:
            offered = {item["job_id"] for item in _rebuild_candidates(conn, data_dir)}
            # One runner, one thing at a time: a rebuild queued while a job is
            # in flight waits for it, and a held job waits for the user.
            # Reported so the page can say that rather than look stuck.
            waiting_for = count_live_jobs(conn)
        finally:
            conn.close()
        if payload.job_id not in offered:
            raise HTTPException(status_code=404, detail="no completed job with that id")
        try:
            job_id = app.state.runner.build_environment(payload.job_id)
        except RunnerFailure as exc:
            # The picker should never offer a job the runner will refuse, but a
            # refusal must reach the page as a refusal rather than a 500.
            raise HTTPException(status_code=422, detail=f"{exc.code}: {exc}") from exc
        return {"job_id": job_id, "state": "queued", "waiting_for": waiting_for}

    @app.post("/api/environments/{env_id}/destroy")
    def destroy_environment_api(env_id: str) -> dict[str, Any]:
        try:
            app.state.runner.destroy_environment(env_id)
        except Exception as exc:  # surfaced to the caller rather than logged
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"job_id": env_id, "destroyed": True}

    @app.get("/vms", response_class=HTMLResponse)
    def vms_page(request: Request) -> HTMLResponse:
        conn = db()
        try:
            held = [
                {"job": job, "held": _held_details(job, list_artifacts(conn, job["id"]))}
                for job in list_held_jobs(conn)
            ]
            environments = [
                {"job": job, "env": _environment_details(job)} for job in list_environments(conn)
            ]
            candidates = _rebuild_candidates(conn, data_dir)
        finally:
            conn.close()
        response = templates.TemplateResponse(
            request,
            "vms.html",
            {
                "held": held,
                "environments": environments,
                "candidates": candidates,
                "csrf": app.state.token,
            },
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token",
                app.state.token,
                httponly=True,
                samesite="strict",
            )
        return response

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str) -> HTMLResponse:
        conn = db()
        try:
            job = get_job(conn, job_id)
            steps = list_steps(conn, job_id)
            validations = list_validations(conn, job_id)
            artifacts = list_artifacts(conn, job_id)
            # Classified here so the page can offer a rendered view only where
            # rendering means anything.
            media = {
                str(row["id"]): evidence_media(Path(str(row["path"])))
                for row in conn.execute(
                    "SELECT id, path FROM artifacts WHERE job_id=?", (job_id,)
                ).fetchall()
            }
            check = get_check(conn, str((job or {}).get("check_id") or ""))
        finally:
            conn.close()
        if job is None:
            raise HTTPException(status_code=404, detail="unknown job")
        cve_url = str((check or {}).get("cve_url") or "")
        poc_url = str(job.get("poc_url") or "")
        response = templates.TemplateResponse(
            request,
            "job.html",
            {
                "job": job,
                "steps": steps,
                "validations": validations,
                "artifacts": artifacts,
                "media": media,
                "commands": _step_commands(job),
                "plan": _provision_plan(job),
                "links": {
                    "cve_text": cve_url,
                    "cve_href": _safe_link(cve_url),
                    "poc_text": poc_url,
                    "poc_href": _safe_link(poc_url),
                },
                "csrf": app.state.token,
            },
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token",
                app.state.token,
                httponly=True,
                samesite="strict",
            )
        return response

    @app.post("/api/links/check")
    def link_check(payload: LinkCheckRequest) -> dict[str, Any]:
        try:
            plan = _link_check(payload.cve_url, payload.poc_url, store_root=data_dir)
        except FetchError as exc:
            # Which URL. A bare "HTTP status 404" left the operator unable to
            # tell whether the advisory link or the PoC link was the dead one,
            # and a mistyped repository name is the commonest way to get here.
            raise HTTPException(
                status_code=422,
                detail=f"could not fetch a source for this check: {exc} "
                f"(cve={payload.cve_url} poc={payload.poc_url})",
            ) from exc
        except ExtractorError as exc:
            # The MESSAGE, not just the code. `detail=exc.code` sent back the
            # bare word "evidence_insufficient" and threw away the sentence
            # that says which citations failed and why - so every one of them
            # was unanswerable, and they are the most common refusal there is.
            where = f" [{exc.check_id}]" if exc.check_id else ""
            raise HTTPException(
                status_code=422, detail=f"{exc.code}{where}: {exc}"
            ) from exc
        except _NeedsArtifact as exc:
            # Not an error: a check the operator can still make runnable by
            # approving one download. The row and the stored sources are
            # created so the approval has something to bind to, and the check
            # expires on the same clock as any other.
            plan = _needs_artifact_plan(exc, payload, data_dir)
        conn = db()
        try:
            conn.execute(
                "INSERT INTO link_checks(check_id, cve_url, poc_url, cve_id, target_id, "
                "bundle_sha256, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    plan["check_id"],
                    payload.cve_url,
                    payload.poc_url,
                    plan["cve_id"],
                    plan["target_id"],
                    plan["bundle_sha256"],
                    plan["created_at"],
                    plan["expires_at"],
                ),
            )
            conn.commit()
        finally:
            conn.close()
        sourcestore.prune(data_dir)
        return plan

    @app.post("/api/artifacts/approve")
    def approve_artifact(payload: ArtifactApprovalRequest) -> dict[str, Any]:
        """Fetch one operator-named file on the host and pin it to this check.

        The approval is of *bytes*, not of a URL. Fetching here and recording
        the digest is what keeps "the version pin is ours" true: a URL
        approved now and fetched at job time could serve something else, and
        nothing downstream would know. It is the same guarantee
        pin-artifact.py gives the catalog, at a gate a person can use.

        resolve_public is the SSRF guard the advisory fetch already uses: an
        operator-supplied URL is fetched by the host, so loopback, private and
        link-local addresses are refused before a request is made.
        """
        conn = db()
        try:
            row = conn.execute(
                "SELECT * FROM link_checks WHERE check_id=?", (payload.check_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown check")
            if row["used_at"] is not None:
                raise HTTPException(status_code=409, detail="check already used")
            if row["expires_at"] < now():
                raise HTTPException(status_code=409, detail="check expired")
        finally:
            conn.close()
        wanted = [line.strip() for line in payload.urls if line.strip()]
        if not wanted or len(wanted) > generic.MAX_APPROVED:
            raise HTTPException(
                status_code=422,
                detail=f"approve between 1 and {generic.MAX_APPROVED} files, "
                f"one URL per line; got {len(wanted)}",
            )
        # Fetched and checked as a SET before any of it is stored: a run that
        # kept the first three and refused the fourth would leave the check
        # holding a partial set the operator never approved, and the job would
        # install it.
        files = []
        for url in wanted:
            try:
                fetched = fetch(url)
            except FetchError as exc:
                raise HTTPException(status_code=422, detail=f"{url}: {exc}") from exc
            name = Path(urlsplit(fetched.final_url).path).name or "download"
            try:
                install = generic.install_verb(name)
                guest = generic.artifact_name(name)
            except generic.NoObservable as exc:
                raise HTTPException(status_code=422, detail=f"{url}: {exc}") from exc
            files.append((fetched, guest, install))
        placed = [item for item in files if item[2] == "file"]
        if len(placed) > 1:
            raise HTTPException(
                status_code=422,
                detail="only one placed file per job: `place` names one kind, and "
                f"these are both placed - {placed[0][1]}, {placed[1][1]}",
            )
        if len({guest for _f, guest, _i in files}) != len(files):
            raise HTTPException(
                status_code=422, detail="two of those URLs have the same filename"
            )
        try:
            # The whole previous set first: an approval is of a set of bytes, so
            # re-approving two files after three has to leave two, not two plus
            # the third nobody looked at again.
            sourcestore.drop(data_dir, payload.check_id, "artifact")
            for index, (fetched, _guest, _install) in enumerate(files):
                sourcestore.add(data_dir, payload.check_id, f"artifact{index}", fetched)
        except sourcestore.SourceStoreError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "check_id": payload.check_id,
            "files": [
                {
                    "url": fetched.final_url,
                    "filename": guest,
                    "bytes": len(fetched.body),
                    "sha256": fetched.sha256,
                    "install": install,
                }
                for fetched, guest, install in files
            ],
        }

    @app.post("/api/jobs")
    def create_job_api(payload: JobCreateRequest) -> dict[str, Any]:
        conn = db()
        try:
            row = conn.execute(
                "SELECT * FROM link_checks WHERE check_id=?", (payload.check_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown check")
            if row["used_at"] is not None:
                raise HTTPException(status_code=409, detail="check already used")
            timestamp = now()
            if row["expires_at"] < timestamp:
                raise HTTPException(status_code=409, detail="check expired")
            if row["cve_url"] != payload.cve_url or row["poc_url"] != payload.poc_url:
                raise HTTPException(status_code=409, detail="check URL mismatch")
            claimed = conn.execute(
                "UPDATE link_checks SET used_at=? WHERE check_id=? AND used_at IS NULL "
                "AND expires_at >= ?",
                (timestamp, payload.check_id, timestamp),
            )
            if claimed.rowcount != 1:
                raise HTTPException(status_code=409, detail="check already used")
            conn.commit()
            try:
                job_id = app.state.runner.submit(
                    payload.cve_url,
                    payload.poc_url,
                    check_id=payload.check_id,
                    bundle_sha256=str(row["bundle_sha256"]),
                )
            except BrokerError as exc:
                conn.execute(
                    "UPDATE link_checks SET used_at=NULL WHERE check_id=?",
                    (payload.check_id,),
                )
                conn.commit()
                status = 503 if exc.code == "broker_unavailable" else 409
                # The fourth site that threw the message away. A broker refusal
                # carries the only sentence that says WHICH id or step it
                # refused; `detail=exc.code` turned every one of them into the
                # same bare "invalid_request" in the submit form.
                raise HTTPException(
                    status_code=status, detail=f"{exc.code}: {exc}"
                ) from exc
        finally:
            conn.close()
        return {"job_id": job_id, "state": "queued"}

    @app.get("/api/jobs")
    def jobs_api() -> dict[str, Any]:
        conn = db()
        try:
            return {"items": list_jobs(conn)}
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}")
    def job_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            job = get_job(conn, job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown job")
            return {
                "job": job,
                "steps": list_steps(conn, job_id),
                "validations": list_validations(conn, job_id),
            }
        finally:
            conn.close()

    @app.get("/api/checks/{check_id}/log")
    def check_log_api(check_id: str) -> dict[str, Any]:
        """What the extractor was asked and what it answered, for one check.

        The reason a refusal was unanswerable: nothing recorded a check's
        extraction, so "it says evidence_insufficient" could only be
        investigated by running it again and hoping for the same reply - which
        at temperature 0 it is not.

        Hex-only, because the id names a directory.
        """
        if not re.fullmatch(r"[0-9a-f]{32}", check_id):
            raise HTTPException(status_code=400, detail="bad check id")
        where = data_dir / "checks" / check_id
        if not where.is_dir():
            raise HTTPException(status_code=404, detail="no transcript for that check")
        return {
            "check_id": check_id,
            "items": {
                # 20,000 was below a full prompt, so reading this endpoint
                # showed a prompt with its artifacts cut off and nothing
                # saying so - which cost two wrong inferences in one session
                # ("the listing is missing", "NVD was not fetched"). The
                # transcript on disk was complete both times.
                item.name: item.read_text(encoding="utf-8", errors="replace")[:400_000]
                for item in sorted(where.glob("*.txt"))
            },
        }

    @app.get("/api/jobs/{job_id}/steps")
    def steps_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            if get_job(conn, job_id) is None:
                raise HTTPException(status_code=404, detail="unknown job")
            return {"items": list_steps(conn, job_id)}
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}/validations")
    def validations_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            if get_job(conn, job_id) is None:
                raise HTTPException(status_code=404, detail="unknown job")
            return {"items": list_validations(conn, job_id)}
        finally:
            conn.close()

    @app.get("/api/jobs/{job_id}/evidence/{artifact_id}")
    def evidence_api(job_id: str, artifact_id: str, view: str = "inline") -> FileResponse:
        conn = db()
        try:
            row = conn.execute(
                "SELECT path, sha256 FROM artifacts WHERE id=? AND job_id=?",
                (artifact_id, job_id),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise HTTPException(status_code=404, detail="unknown artifact")
        path = Path(str(row["path"]))
        if not path.is_file():
            raise HTTPException(status_code=404, detail="artifact file missing")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != str(row["sha256"]):
            raise HTTPException(status_code=409, detail="artifact hash mismatch")
        if view == "download":
            return FileResponse(path, media_type="application/octet-stream", filename=path.name)
        media = evidence_media(path)
        if view == "render":
            if media != "html":
                raise HTTPException(status_code=409, detail="artifact is not html")
            # Fetched from the internet, so it is rendered under its own
            # Content-Security-Policy: `sandbox` with no allow- tokens blocks
            # scripts and gives the document an opaque origin, so it cannot
            # reach this app's cookies. The middleware leaves a policy the
            # route already set alone.
            return FileResponse(
                path,
                media_type="text/html; charset=utf-8",
                content_disposition_type="inline",
                headers={"Content-Security-Policy": "sandbox"},
            )
        # Anything else is shown as its own source, never executed: HTML is
        # served as text so the browser displays it instead of running it.
        return FileResponse(
            path,
            media_type="application/json" if media == "json" else "text/plain; charset=utf-8",
            content_disposition_type="inline",
        )

    @app.post("/api/jobs/{job_id}/release")
    def release_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            if get_job(conn, job_id) is None:
                raise HTTPException(status_code=404, detail="unknown job")
            # Refused unless the job is actually held, so this cannot disturb a
            # job that is still running or already torn down.
            if not request_release(conn, job_id):
                raise HTTPException(status_code=409, detail="job is not held")
        finally:
            conn.close()
        return {"job_id": job_id, "release_requested": True}

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_api(job_id: str) -> dict[str, Any]:
        conn = db()
        try:
            row = conn.execute("SELECT outcome FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="unknown job")
            if row["outcome"] is not None:
                raise HTTPException(status_code=409, detail="job already finished")
            request_cancel(conn, job_id)
        finally:
            conn.close()
        return {"cancelled": True, "job_id": job_id}

    @app.get("/api/jobs/{job_id}/events")
    async def events_api(job_id: str) -> EventSourceResponse:
        conn = connect(db_path)
        try:
            exists = get_job(conn, job_id) is not None
        finally:
            conn.close()
        if not exists:
            raise HTTPException(status_code=404, detail="unknown job")

        async def stream() -> AsyncIterator[dict[str, str]]:
            last = ""
            while True:
                conn = connect(db_path)
                try:
                    job = get_job(conn, job_id)
                    steps = list_steps(conn, job_id)
                finally:
                    conn.close()
                payload = json.dumps(
                    {
                        "job": job,
                        "steps": steps,
                        "commands": _step_commands(job or {}),
                        "plan": _provision_plan(job or {}),
                    },
                    sort_keys=True,
                    default=str,
                )
                if payload != last:
                    last = payload
                    yield {"event": "state", "data": payload}
                if job is None or job.get("outcome") is not None:
                    break
                await asyncio.sleep(1)

        return EventSourceResponse(stream())

    @app.get("/jobs/{job_id}/audit", response_class=HTMLResponse)
    def audit_page(request: Request, job_id: str) -> HTMLResponse:
        conn = db()
        try:
            job_row = get_job(conn, job_id)
            try:
                bundle = build_bundle(conn, job_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail="unknown job") from exc
        finally:
            conn.close()
        attempt_dir = Path(str((job_row or {}).get("attempt_dir") or ""))
        target_id = str(bundle["job"].get("target_id") or "")
        target = by_id(target_id)
        # A derived target records its own claims, because they are decided per
        # job rather than checked in: an ecosystem job that ran a control says
        # more, and names the versions. The module's constants are the fallback
        # for jobs recorded before that, and an unknown target id gets neither
        # list rather than borrowing another target's.
        recorded = _criteria(bundle["artifacts"], attempt_dir)
        fallback: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
            generic.GENERIC_ID: (generic.PROVES, generic.DOES_NOT_PROVE)
        }
        proves, not_proves = fallback.get(target_id, ((), ()))
        if target is not None:
            proves, not_proves = target.what_proves, target.what_does_not_prove
        elif recorded:
            proves = tuple(recorded.get("proves") or ())
            not_proves = tuple(recorded.get("not_proves") or ())
        response = templates.TemplateResponse(
            request,
            "audit.html",
            {
                "bundle": bundle,
                "llm": _llm_calls(bundle["artifacts"], attempt_dir),
                # A derived target is not in TARGETS, and it is the one whose
                # caveats most need showing. Any other unknown target_id gets
                # neither list rather than borrowing these.
                "proves": list(proves),
                "not_proves": list(not_proves),
                "csrf": app.state.token,
            },
        )
        if request.cookies.get("xentry_token") != app.state.token:
            response.set_cookie(
                "xentry_token",
                app.state.token,
                httponly=True,
                samesite="strict",
            )
        return response

    @app.get("/api/jobs/{job_id}/bundle")
    def bundle_api(job_id: str) -> JSONResponse:
        conn = db()
        try:
            try:
                bundle = build_bundle(conn, job_id)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail="unknown job") from exc
        finally:
            conn.close()
        return JSONResponse(
            bundle,
            headers={"Content-Disposition": f'attachment; filename="xentry-{job_id}-bundle.json"'},
        )

    @app.post("/api/preflight")
    def preflight() -> dict[str, Any]:
        images = Path(
            os.environ.get("XENTRY_IMAGES_MANIFEST", ROOT / "var" / "images" / "build-results.json")
        )
        artifacts = Path(
            os.environ.get("XENTRY_ARTIFACT_MANIFEST", ROOT / "var" / "artifacts" / "manifest.json")
        )
        checks = {
            "broker_socket": broker_socket.exists(),
            "database": db_path.exists(),
            "images": images.exists(),
            "artifacts": artifacts.exists(),
        }
        return {"checks": checks, "ok": all(checks.values())}

    @app.get("/api/system")
    def system() -> dict[str, Any]:
        # The broker's own answer about which proxies it started. Asked rather
        # than assumed: a job that needs the image mirror fails saying "set
        # XENTRY_START_OCI_MIRROR=1 on the broker", and nothing else in this
        # app could say whether it already was.
        started: dict[str, Any] = {}
        try:
            answer = BrokerClient(broker_socket).ping()
            started = {
                key: value for key, value in answer.items() if key != "pong"
            }
            # And whether the broker is reading the same files this app is. A
            # relative default plus a different working directory made them
            # diverge silently, and the job failure blamed the artifact.
            for key, mine in (
                ("catalog_path", CATALOG),
                ("steps_manifest", STEPS),
            ):
                theirs = str(started.get(key) or "")
                if theirs and theirs != str(Path(mine).resolve()):
                    started[f"{key}_mismatch"] = f"app reads {mine}"
        except BrokerError as exc:
            started = {"error": str(exc)}
        return {
            "version": "0.1.0",
            "broker_socket": str(broker_socket),
            "broker_available": broker_socket.exists(),
            "database": str(db_path),
            "broker_started": started,
        }

    return app


app = build_app(
    data_dir=Path(os.environ.get("XENTRY_DATA_DIR", ROOT / "var" / "instance")),
    db_path=Path(os.environ.get("XENTRY_DB_PATH", ROOT / "var" / "instance" / "xentry.db")),
    broker_socket=Path(os.environ.get("XENTRY_BROKER_SOCKET", "/run/xentry/broker.sock")),
)
