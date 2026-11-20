"""Ordered job runner for V1 remote targets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import re
import sqlite3
import tarfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from xentry import ecosystem, generic, harness, pocgen, release, sourcestore, transcript
from xentry.broker import BrokerClient, BrokerError
from xentry.db import connect
from xentry.extract import ArtifactText, ExtractorError, extract
from xentry.fetch import (
    MAX_POC_BYTES,
    Fetched,
    FetchError,
    bundle_sha256,
    fetch,
    fetch_cve_enrichment,
    fetch_cve_evidence,
    fetch_poc_evidence,
)
from xentry.jobstore import (
    begin_step,
    create_job,
    finish_step,
    get_job,
    is_cancel_requested,
    is_release_requested,
    now,
    record_artifact,
    record_broker_call,
    record_nonce,
    record_outcome,
    record_validation,
    request_cancel,
    session_event,
    set_cleanup_state,
    set_final_attempt,
    set_plan,
)
from xentry.models import Facts
from xentry.pocgen import PocGenError
from xentry.security import new_nonce, redact
from xentry.targets import (
    TARGETS,
    TargetInstance,
    by_cve,
    by_poc_url,
    resolved_artifacts,
    setup_script_path,
)
from xentry.validator import (
    NarrativeBundle,
    RunnerFacts,
    ValidatorError,
    assess,
)

GUEST_TRACE_REL = ".xentry-trace"
# What a dying kernel prints to the console. A guest that panicked mid-exploit
# is a RESULT - the exploit crashed it - and it used to arrive as an SSH error,
# which is what the broker breaking looks like too.
PANIC_MARKS = (
    "Kernel panic - not syncing",
    "BUG: unable to handle",
    "general protection fault",
    "Oops: ",
)


# How many revert-and-rebuild verifications one harness job may pay for. A
# settings page owns this later; three is enough to see a model converge and
# few enough that a wrong one costs minutes rather than an afternoon.
# A PoC THAT DIALS LOOPBACK WAS NEVER POINTED AT THE TARGET.
#
# redis CVE-2024-31449's PoC takes an address as argv[1], is handed the
# target's, and calls remote("localhost", 6379) anyway - it is written to run
# ON the vulnerable host. The attacker VM runs nothing on loopback, so the
# connection is refused and the job reported exploit_failed, which reads as
# "the exploit did not work against this target". It never reached the target:
# the step before it had already proved 10.43.1.10:6379 accepts a connection.
#
# The distinction matters when the report is read later. exploit_failed is a
# statement about the CVE; this is a statement about the PoC. Re-running cannot
# change it and neither can anything done to the target.
POC_DIALLED_LOOPBACK = re.compile(
    r"(?:connect\w*|connection)\b[^\n]{0,48}?\b(?:localhost|127\.0\.0\.1|::1)\b",
    re.IGNORECASE,
)

HARNESS_READINESS_CALLS = 3


class RunnerFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def panic_in(serial: str) -> str:
    """The panic, if the serial log shows one, with its surrounding lines."""
    for mark in PANIC_MARKS:
        index = serial.find(mark)
        if index >= 0:
            return serial[max(0, index - 600) : index + 600]
    return ""


class _JobBrokerClient:
    """Attach job/attempt identity and a call sequence to every broker verb."""

    def __init__(self, inner: BrokerClient, job_id: str, attempt_id: str, on_call: Any):
        self.inner = inner
        self.job_id = job_id
        self.attempt_id = attempt_id
        self.on_call = on_call
        self.seq = 0

    def call(
        self,
        verb: str,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        self.seq += 1
        kwargs.setdefault("job_id", self.job_id)
        kwargs.setdefault("attempt_id", self.attempt_id)
        kwargs.setdefault("seq", self.seq)
        try:
            result = self.inner.call(verb, params, **kwargs)
        except BrokerError as exc:
            self.on_call(exc.call)
            raise
        self.on_call(getattr(self.inner, "last_call", None))
        return result


@dataclass(frozen=True)
class EnvironmentPlan:
    """What a rebuild needs, which is only which target to bring up.

    Everything that provisions a target - the base image, the setup script and
    its hash, the resources, the actor, the pinned PoC artifact - lives on the
    checked-in TargetInstance. A job's first three steps fetch the CVE page,
    ask the extractor for facts and match them to one of those instances; they
    exist to *choose* the target, not to build it. A rebuild already knows the
    choice, so it skips all three: no fetch, no extractor call, and no
    dependency on a link check.

    A DERIVED target has no checked-in instance, so a rebuild of one replays
    what its check stored: the facts that were admitted and the release that
    answered. It still asks no model and fetches nothing - the facts are read
    back rather than re-extracted, which is the guarantee the job path relies
    on for the same reason. The extractor is not deterministic, so the plan
    that was approved has to be the plan that runs.
    """

    target_id: str
    # Carried from the source job rather than taken from the target, because
    # one target can cover several CVEs (dirtyfrag covers two) and the page
    # should name the one that was run.
    cve_id: str
    # The source job's check, for a DERIVED rebuild. generic has no checked-in
    # instance to look up, so its target is rebuilt from the facts and the
    # resolution that check stored - read back, never re-extracted, which is
    # the guarantee the job path relies on for the same reason: the extractor
    # is not deterministic, so the plan that was approved is the plan that
    # runs. Empty for a checked-in target, which needs neither, and last
    # because it is the only field with a default.
    check_id: str = ""


@dataclass(frozen=True)
class _Work:
    """One queued unit. A tuple grew a field per mode and stopped reading."""

    job_id: str
    attempt_id: str
    cve_url: str
    poc_url: str = ""
    expected_bundle: str | None = None
    environment: EnvironmentPlan | None = None
    # The experimental pipeline: no PoC is supplied, a model writes one.
    experiment: bool = False


# The broker's copy_in lands every artifact here, digest-checked on both sides.
GUEST_ARTIFACT_DIR = "/var/lib/xentry/artifacts"
# The lab's own repository, staged for the target. The attacker gets the same
# bytes under the target's PoC artifact id; this is the target's copy of them.
APP_ARCHIVE_ID = "app-source"
# After every real step, so the synthetic row a between-steps failure writes
# sorts last in the table a reader is looking at.
LAST_SEQ = 99
# apt's progress lines, which crowd out the diagnosis in a failure's tail.
PROGRESS = re.compile(
    # "(Reading database" has a PAREN before the word, so "Reading" alone never
    # matched it. dpkg prints that line once per percent - twenty-one lines per
    # package - and on the redis job those lines filled the entire 3000-char
    # detail, pushing the actual error out of the record. The job ran for five
    # and a half minutes and reported nothing but a progress counter.
    r"\s*\(?(Selecting|Preparing to unpack|Unpacking|Setting up|Get:|Hit:|Ign:|"
    r"Reading|Building|Processing triggers|Created symlink|update-alternatives:|"
    r"Restarting services|Service restarts|No services need)"
)
# Codes whose detail adds nothing to the code itself.
SELF_EVIDENT = ("cancelled", "deadline_exceeded")
def _approved_from(stored: dict[str, Fetched]) -> list[Fetched]:
    """The operator-approved files a check stored, in install order.

    Two provenances, and the order is the install order: what the operator
    approved first, then what came from the PoC's own repository - a config
    lands on a package that already exists.

    Sorted by the NUMBER, not the string: past nine files "artifact10" sorts
    before "artifact2" and a .deb would install after the config that
    configures it. Unreachable at MAX_APPROVED today and a trap if it rises.

    Shared with the rebuild path, which needs the same files in the same order:
    a derived target that has to place a config is not vulnerable without it,
    and two orderings of the same list would be a difference nothing reports.
    """
    found: list[Fetched] = []
    for prefix in ("artifact", "repo"):
        names = [key for key in stored if key.startswith(prefix)]
        names.sort(key=lambda key: int(key[len(prefix) :] or "-1"))
        found.extend(stored[name] for name in names)
    return found


# The one operator-approved download a job may carry.
APPROVED_ID = "approved-artifact"
# The attacker image's own suite. Its packages come from Ubuntu at the
# current serial, never from the target's archive, which is frequently
# neither Ubuntu nor current.
ATTACKER_SUITE = "noble"
ATTACKER_IMAGE = "ubuntu-24.04-attacker"
APPROVED_NAME = "approved-artifact"


def _poc_attempts() -> int:
    """How many times the experimental pipeline may rewrite its PoC."""
    try:
        value = int(os.environ.get("XENTRY_POC_ATTEMPTS", "3"))
    except ValueError:
        return 3
    return max(1, min(value, 10))


def _entrypoint(facts: Any, experiment: bool) -> str:
    return generic.AUTHORED_ENTRYPOINT if experiment else generic.entrypoint(facts)


def _latest_attempt(conn: sqlite3.Connection, job_id: str) -> str:
    # job_outcomes has a foreign key to attempts, and an environment never
    # reaches the point where final_attempt_id is set.
    row = conn.execute(
        "SELECT id FROM attempts WHERE job_id=? ORDER BY attempt_no DESC LIMIT 1",
        (job_id,),
    ).fetchone()
    return str(row["id"]) if row is not None else ""


class _JobLocal(threading.local):
    """One job's own state, per worker thread.

    These were plain attributes on the runner. With a single worker that was
    indistinguishable from per-job state; with more than one, two jobs would
    share a deadline and - the part that matters - a secrets list, which is
    what keeps a nonce out of any message or trace written to disk. A
    threading.local subclass re-runs __init__ for each thread that touches it,
    so a worker always starts from these defaults.
    """

    def __init__(self) -> None:
        self.deadline_at: float | None = None
        self.job_started_at = 0.0
        self.secrets: list[str] = []


class JobRunner:
    def __init__(
        self,
        *,
        db_path: Path,
        data_dir: Path,
        broker_socket: Path,
        extract_fn: Callable[[list[ArtifactText]], Any] = extract,
        validate_fn: Callable[[RunnerFacts, NarrativeBundle], Any] = assess,
        provision_fn: Callable[
            [str, Callable[[str, dict[str, Any]], dict[str, Any]]], Callable[[str], str]
        ]
        | None = None,
        fetch_fn: Callable[..., Any] = fetch,
        broker_factory: Callable[[], BrokerClient] | None = None,
        keep_on_failure: bool = False,
        hold_s: float = 0.0,
        job_deadline_s: float | None = 7200.0,
        target_deadlines: dict[str, float] | None = None,
    ) -> None:
        self.db_path = db_path
        self.data_dir = data_dir
        self.broker_socket = broker_socket
        self.extract_fn = extract_fn
        self.validate_fn = validate_fn
        self.provision_fn = provision_fn
        self.fetch_fn = fetch_fn
        self.keep_on_failure = keep_on_failure
        self.hold_s = hold_s
        self.job_deadline_s = job_deadline_s
        self.target_deadlines = target_deadlines or {}
        self._job = _JobLocal()
        self.broker_factory = broker_factory or (
            lambda: BrokerClient(self.broker_socket, timeout=2400)
        )
        self._queue: queue.Queue[_Work | None] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._stopped = threading.Event()

    def start(self) -> None:
        if self._worker is None:
            # Once, before the worker exists: it marks every outcome-less job
            # interrupted and destroys its resources.
            self.recover_interrupted()
            self._worker = threading.Thread(target=self._work, name="xentry-runner", daemon=True)
            self._worker.start()

    def _resolved_images(self) -> set[str]:
        """Artifact ids the catalog pins, so a release with no built image is
        never resolved to: that would turn a clean refusal into a late and
        confusing boot failure."""
        try:
            return resolved_artifacts()
        except (OSError, ValueError):
            return set()

    def recover_interrupted(self) -> list[str]:
        """Mark unfinished jobs interrupted and destroy their managed resources.

        The in-memory queue is lost on restart, so a job without an outcome
        cannot resume. Cleanup is idempotent and follows attacker -> target ->
        network; when the broker is unavailable the job is still marked
        interrupted and cleanup stays pending for ``xentry cleanup --force``.
        """
        conn = connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT id FROM jobs WHERE outcome IS NULL ORDER BY created_at"
            ).fetchall()
            if not rows:
                return []
            managed: dict[str, Any] | None = None
            client: BrokerClient | None = None
            try:
                client = self.broker_factory()
                managed = client.call("list_managed")
            except (BrokerError, OSError):
                managed = None
            recovered: list[str] = []
            for row in rows:
                job_id = str(row["id"])
                attempt = conn.execute(
                    "SELECT id FROM attempts WHERE job_id=? ORDER BY attempt_no LIMIT 1",
                    (job_id,),
                ).fetchone()
                cleanup_ok = managed is not None
                if client is not None and managed is not None:
                    domains = [
                        str(item.get("name", ""))
                        for item in managed.get("domains") or []
                        if str(item.get("name", "")).startswith(f"xentry-{job_id}-")
                    ]
                    domains.sort(key=lambda name: 0 if name.endswith("-attacker") else 1)
                    for domain in domains:
                        try:
                            client.call(
                                "destroy_vm",
                                {"vm_id": domain},
                                job_id=job_id,
                                attempt_id=str(attempt["id"]) if attempt is not None else "",
                            )
                        except BrokerError:
                            cleanup_ok = False
                    networks = [
                        str(item.get("name", ""))
                        for item in managed.get("networks") or []
                        if str(item.get("name", "")) == f"xentry-{job_id}"
                    ]
                    for network in networks:
                        try:
                            client.call(
                                "destroy_network",
                                {"network_id": network},
                                job_id=job_id,
                                attempt_id=str(attempt["id"]) if attempt is not None else "",
                            )
                        except BrokerError:
                            cleanup_ok = False
                set_cleanup_state(conn, job_id, "done" if cleanup_ok else "failed" if managed else "pending")
                if attempt is not None:
                    record_outcome(
                        conn,
                        job_id=job_id,
                        attempt_id=str(attempt["id"]),
                        outcome="interrupted",
                        verdict="not_run",
                        authority="runner_observed",
                        reason_code=(
                            "security_cleanup_failed" if managed is not None and not cleanup_ok
                            else "interrupted"
                        ),
                    )
                    conn.execute(
                        "UPDATE attempts SET finished_at=? WHERE id=?",
                        (now(), str(attempt["id"])),
                    )
                    conn.commit()
                recovered.append(job_id)
            return recovered
        finally:
            conn.close()

    def stop(self) -> None:
        self._stopped.set()
        self._queue.put(None)
        if self._worker is not None:
            self._worker.join(timeout=5)

    def submit(
        self,
        cve_url: str,
        poc_url: str,
        *,
        check_id: str | None = None,
        bundle_sha256: str | None = None,
        harness: bool = False,
    ) -> str:
        conn = connect(self.db_path)
        try:
            blocked = [
                str(row["id"])
                for row in conn.execute(
                    "SELECT id FROM jobs WHERE cleanup_state='failed'"
                ).fetchall()
            ]
            if blocked:
                client = self.broker_factory()
                managed = client.call("list_managed")
                names = {
                    str(item.get("name", ""))
                    for item in (managed.get("domains") or [])
                    + (managed.get("networks") or [])
                }
                remaining = [
                    job_id
                    for job_id in blocked
                    if any(
                        name == f"xentry-{job_id}" or name.startswith(f"xentry-{job_id}-")
                        for name in names
                    )
                ]
                if remaining:
                    raise BrokerError(
                        "security_cleanup_failed",
                        f"cleanup failed for {remaining[0]}; run xentry cleanup --force",
                    )
                for job_id in blocked:
                    set_cleanup_state(conn, job_id, "done")
            job_id, attempt_id, _attempt_dir = create_job(
                conn,
                data_dir=self.data_dir,
                poc_url=poc_url,
                cve_url=cve_url,
                check_id=check_id,
                bundle_sha256=bundle_sha256,
                # Recorded, not acted on: this slice only makes the route
                # selectable and visible, so the run itself is unchanged.
                kind="harness_job" if harness else "job",
            )
        finally:
            conn.close()
        self._queue.put(
            _Work(
                job_id=job_id,
                attempt_id=attempt_id,
                cve_url=cve_url,
                poc_url=poc_url,
                expected_bundle=bundle_sha256,
            )
        )
        return job_id

    def submit_experiment(self, cve_url: str) -> str:
        """Queue an experiment: the advisory only, and a model writes the PoC.

        Recorded with kind='experiment', so it never appears in the job list,
        is never counted as a job in flight, and cannot be mistaken for a run
        whose PoC somebody chose.
        """
        conn = connect(self.db_path)
        try:
            job_id, attempt_id, _attempt_dir = create_job(
                conn,
                data_dir=self.data_dir,
                poc_url="",
                cve_url=cve_url,
                kind="experiment",
            )
        finally:
            conn.close()
        self._queue.put(
            _Work(
                job_id=job_id,
                attempt_id=attempt_id,
                cve_url=cve_url,
                experiment=True,
            )
        )
        return job_id

    def build_environment(self, source_job_id: str) -> str:
        """Queue a rebuild of the target an earlier job ran, left running.

        The source job supplies only its target and CVE. Nothing is fetched and
        no bundle is expected: an environment makes no claim about any source,
        so there is nothing for a byte digest to protect.

        It is queued like any other job and takes the same island when its turn
        comes: 10.43.1.10 for the target, 10.43.2.20 for the attacker, on the
        proxy VM's bridges. It does NOT get a subnet of its own - that was true
        when the broker allocated 10.42.N.0/24 per job from an octet pool, a
        path deleted with the host-side mirrors. One island is enough because
        the runner is one thread: an environment left running holds it exactly
        as a held job does, and the next job waits.
        """
        conn = connect(self.db_path)
        try:
            source = get_job(conn, source_job_id)
            if source is None:
                raise RunnerFailure("unknown_job", f"no such job: {source_job_id}")
            target_id = str(source.get("target_id") or "")
            cve_id = str(source.get("cve_id") or "")
            check_id = str(source.get("check_id") or "")
            derived = target_id == generic.GENERIC_ID
            if derived and not sourcestore.load_facts(self.data_dir, check_id):
                # The facts are kept for sourcestore.RETENTION_S and pruned by
                # age, so an old derived job has nothing left to rebuild FROM.
                # Refused here with the reason rather than offered and failed
                # on the click.
                raise RunnerFailure(
                    "unsupported_target",
                    f"job {source_job_id} was a derived target and its stored "
                    "facts have aged out, so there is nothing to rebuild from",
                )
            if not derived and target_id not in TARGETS:
                raise RunnerFailure(
                    "unsupported_target", f"job {source_job_id} has no known target"
                )
            job_id, attempt_id, _attempt_dir = create_job(
                conn,
                data_dir=self.data_dir,
                poc_url=str(source.get("poc_url") or ""),
                kind="environment",
            )
        finally:
            conn.close()
        plan = EnvironmentPlan(target_id=target_id, cve_id=cve_id, check_id=check_id)
        self._queue.put(
            _Work(
                job_id=job_id,
                attempt_id=attempt_id,
                cve_url="",
                poc_url=str(source.get("poc_url") or ""),
                environment=plan,
            )
        )
        return job_id

    def destroy_environment(self, job_id: str) -> None:
        """Tear down a rebuilt environment and close out its row."""
        conn = connect(self.db_path)
        try:
            row = get_job(conn, job_id)
            if row is None or str(row.get("kind")) != "environment":
                raise RunnerFailure("unknown_environment", f"not an environment: {job_id}")
            if row.get("outcome") is not None:
                raise RunnerFailure("environment_gone", f"already destroyed: {job_id}")
            record = Path(str(row.get("attempt_dir") or "")) / "environment.json"
            if not record.exists():
                # Still building, so the worker owns these VMs and is about to
                # take another step with them. Tearing them down from here
                # would race it and leave the ones it creates next orphaned;
                # asking it to stop runs the same cleanup every job uses, and
                # that records the outcome.
                request_cancel(conn, job_id)
                return
            details: dict[str, Any] = {}
            try:
                details = json.loads(record.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                details = {}
            client = self.broker_factory()
            self._destroy(
                client,
                str(details.get("attacker_vm") or "") or None,
                str(details.get("target_vm") or "") or None,
                str(details.get("network_id") or "") or None,
            )
            record.unlink(missing_ok=True)
            set_cleanup_state(conn, job_id, "done")
            # cancelled, because the outcome CHECK admits only four values and
            # an environment is ended deliberately rather than completed. It
            # carries no verdict: nothing about it was ever measured.
            record_outcome(
                conn,
                job_id=job_id,
                attempt_id=_latest_attempt(conn, job_id),
                outcome="cancelled",
                verdict="not_run",
                authority="runner_observed",
                reason_code="environment_destroyed",
            )
        finally:
            conn.close()

    def _work(self) -> None:
        while not self._stopped.is_set():
            item = self._queue.get()
            if item is None:
                return
            try:
                self.run_job(
                    item.job_id,
                    item.cve_url,
                    item.poc_url,
                    item.attempt_id,
                    item.expected_bundle,
                    environment=item.environment,
                    experiment=item.experiment,
                )
            except Exception:  # noqa: BLE001, S112 - the step layer records the failure
                # The per-step handling records the failure; this is a last resort.
                continue

    def run_job(
        self,
        job_id: str,
        cve_url: str,
        poc_url: str,
        attempt_id: str,
        expected_bundle: str | None = None,
        *,
        environment: EnvironmentPlan | None = None,
        experiment: bool = False,
    ) -> None:
        """Run a job, or build an environment and leave it running.

        An environment is this same sequence stopped after build_poc: the
        target provisioned from its pinned image by its pinned setup script,
        an attacker beside it with the PoC built, and nothing measured. It
        never reaches the freeze, so no nonce is placed, no probe is taken and
        validation never runs - it is a machine, not a run.
        """
        conn = connect(self.db_path)
        attempt_dir = self.data_dir / "jobs" / job_id / "attempt-0"
        check_id = str((get_job(conn, job_id) or {}).get("check_id") or "")

        def capture(stage: str, prompt: str, response: str) -> None:
            # The model calls are single-shot, so one prompt and one reply per
            # stage. Recorded as artifacts, which the audit page verifies by
            # hash before it renders them.
            llm_dir = attempt_dir / "llm"
            llm_dir.mkdir(parents=True, exist_ok=True)
            for part, text in (("prompt", prompt), ("response", response)):
                path = llm_dir / f"{stage}.{part}.txt"
                body = text.encode("utf-8")
                path.write_bytes(body)
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind=f"llm_{stage}_{part}",
                    path=path,
                    sha256=hashlib.sha256(body).hexdigest(),
                    size=len(body),
                )

        transcript.set_sink(capture)
        self._job.job_started_at = time.monotonic()
        self._job.deadline_at = (
            self._job.job_started_at + self.job_deadline_s
            if self.job_deadline_s is not None
            else None
        )
        # Redacted out of any message stored on a step: a failing step's stderr
        # can quote the command that carried a nonce.
        self._job.secrets = []
        target: TargetInstance | None = None
        # Set only on the derived path: the facts a generic target's steps take
        # their packages, units and entrypoint from.
        derived_facts: Any = None
        derived_release: Any = None
        # Set only on the ecosystem path: the lab's validated package.json. It
        # is the marker for that path throughout - derived_facts means "this
        # target was derived rather than checked in", which both derived paths
        # are, while derived_release means "apt resolved a package for it",
        # which only the generic one does.
        ecosystem_env: Any = None
        # Set when the check's stored sources carry an operator-approved file.
        # It is the last resort: the form offers it only after both apt
        # archives and the ecosystem path have been tried and failed.
        approved: list[Any] = []
        nvd_artifact: Any = None
        app_archive_sha = ""
        poc_archive_sha = ""
        # The experimental pipeline rewrites its PoC after a failed attempt,
        # from the previous output with every nonce redacted out of it: feeding
        # a nonce back would let the next attempt print it without reading it.
        poc_attempt = 1
        last_failure = ""
        target_vm: str | None = None
        attacker_vm: str | None = None
        attacker_ip = ""
        network_id: str | None = None
        client: Any = None
        cleanup_ok = True
        destroyed = False
        keep_running = False
        failure: RunnerFailure | None = None
        cve_id: str | None = None
        null_nonce = ""
        control_nonce = ""
        control_output = ""
        real_nonce = ""
        real_nonce_id = ""
        target_response = ""
        target_probe_sha = ""
        host_evidence_sha = ""
        host_evidence_text = ""
        attacker_transcript = ""
        null_output = ""
        real_observed = False
        try:
            raw_client = self.broker_factory()

            def on_broker_call(call: Any) -> None:
                if isinstance(call, dict):
                    record_broker_call(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        call=call,
                    )

            client = _JobBrokerClient(raw_client, job_id, attempt_id, on_broker_call)

            def fetch_step() -> tuple[ArtifactText, ArtifactText, str]:
                # Prefer the bytes the link check approved. Re-fetching a
                # CDN-served page returns different bytes for unchanged content,
                # which failed every job with source_unavailable; an absent or
                # altered store falls back to fetching and lets the bundle
                # comparison below decide whether to proceed.
                stored: dict[str, Fetched] = {}
                if check_id:
                    try:
                        stored = sourcestore.load(self.data_dir, check_id)
                    except sourcestore.SourceStoreError:
                        pass
                if experiment:
                    # No PoC URL exists to fetch: a model writes one later from
                    # this advisory text.
                    fetched_cve = fetch_cve_evidence(cve_url, self.fetch_fn)
                    cve_path = attempt_dir / "cve.html"
                    cve_path.write_bytes(fetched_cve.body)
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="evidence",
                        path=cve_path,
                        sha256=fetched_cve.sha256,
                        size=len(fetched_cve.body),
                    )
                    text = ArtifactText("cve", fetched_cve.sha256, fetched_cve.text)
                    return text, text, bundle_sha256([fetched_cve])
                if stored.keys() >= {"cve", "poc"}:
                    fetched_cve, fetched_poc = stored["cve"], stored["poc"]
                    nonlocal approved
                    # "artifact" is also the single-file name earlier checks
                    # used, and is still read, so a check stored before this
                    # change still runs.
                    approved = _approved_from(stored)
                else:
                    fetched_cve = fetch_cve_evidence(cve_url, self.fetch_fn)
                    target_hint = by_poc_url(poc_url)
                    if target_hint is not None:
                        repo = target_hint.poc.repository.removeprefix("https://github.com/")
                        raw_url = (
                            f"https://raw.githubusercontent.com/{repo}/"
                            f"{target_hint.poc.commit}/README.md"
                        )
                        fetched_poc = self.fetch_fn(raw_url)
                    else:
                        # A repository URL names a page, not evidence: read the
                        # README the way a pinned target does.
                        fetched_poc = fetch_poc_evidence(poc_url, self.fetch_fn)
                cve_path = attempt_dir / "cve.html"
                poc_path = attempt_dir / "poc.html"
                cve_path.write_bytes(fetched_cve.body)
                poc_path.write_bytes(fetched_poc.body)
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind="evidence",
                    path=cve_path,
                    sha256=fetched_cve.sha256,
                    size=len(fetched_cve.body),
                )
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind="poc",
                    path=poc_path,
                    sha256=fetched_poc.sha256,
                    size=len(fetched_poc.body),
                )
                bundle = bundle_sha256([fetched_cve, fetched_poc])
                # NVD's record as a third artifact when it answers: it carries
                # the CVSS metrics the CNA record usually lacks, and that is
                # what a protocol gets read out of when the prose names none.
                # Replayed from the check when it was stored there, so the
                # job's extraction sees exactly what the form's did.
                nonlocal nvd_artifact
                extra = stored.get("nvd") or fetch_cve_enrichment(cve_url, self.fetch_fn)
                if extra is not None:
                    nvd_artifact = ArtifactText("nvd", extra.sha256, extra.text)
                return (
                    ArtifactText("cve", fetched_cve.sha256, fetched_cve.text),
                    ArtifactText("poc", fetched_poc.sha256, fetched_poc.text),
                    bundle,
                )

            bundle = ""
            if environment is None:
                cve_artifact, poc_artifact, bundle = self._step(
                    conn, job_id, attempt_id, 1, "fetch", None, fetch_step
                )
                if expected_bundle and bundle != expected_bundle:
                    raise RunnerFailure(
                        "source_unavailable", "source bundle changed since check"
                    )

            def extract_step() -> tuple[TargetInstance, str]:
                nonlocal target, cve_id, derived_facts, derived_release, ecosystem_env
                # The check's own facts when it stored them. Not a cache: the
                # operator approved a PLAN, and a second reading of the same
                # bytes can produce a different one - job f062e5c1 refused
                # CVE-2021-41773 at step 2 for want of an entrypoint its check
                # had found as a quoted command, on byte-identical artifacts.
                kept = sourcestore.load_facts(self.data_dir, check_id) if check_id else ""
                facts = (
                    Facts.model_validate_json(kept)
                    if kept
                    else self.extract_fn(
                        [cve_artifact, poc_artifact]
                        + ([nvd_artifact] if nvd_artifact is not None else [])
                    )
                )
                target = None if experiment else by_cve(facts.cve_id)
                if target is None:
                    # No checked-in target, so try to derive one. This is the
                    # path a pasted CVE takes; it admits only the shape whose
                    # evidence design is the same for every remote PoC, and
                    # refuses the rest rather than guessing an observation.
                    try:
                        # An application-package lab first. Its package.json is
                        # read as evidence about the environment - the author's
                        # Dockerfile and RUN lines are never executed - and the
                        # job runs only if a closure for that exact dependency
                        # set is already pinned. A lab this harness cannot
                        # rebuild falls through to the apt path below rather
                        # than failing here, so a repository that merely
                        # happens to carry a package.json is not refused.
                        if facts.app_dir is not None:
                            try:
                                manifest = self.fetch_fn(
                                    ecosystem.manifest_url(poc_url, facts.app_dir)
                                )
                                target, ecosystem_env = ecosystem.select(
                                    facts,
                                    poc_url,
                                    manifest.body.decode("utf-8", "replace"),
                                )
                            except FetchError:
                                ecosystem_env = None
                            except ecosystem.NoEnvironment:
                                # A lab this harness cannot rebuild is not a
                                # refusal: the apt path below may still run
                                # this CVE, and app_dir was a model's reading
                                # of a README rather than a guarantee.
                                ecosystem_env = None
                        if ecosystem_env is not None:
                            assert target is not None
                            generic.entrypoint(facts)
                            derived_facts = facts
                            cve_id = facts.cve_id
                            return target, facts.cve_id
                        # Which release can install the affected version is a
                        # lookup against the archive's own publication record,
                        # not a guess: a wrong release costs an image build and
                        # fails indistinguishably from a bad package name.
                        serial_at_hand = generic.snapshot_for(
                            generic.advisory_published(cve_artifact.text)
                        )
                        # Narrowed to what EXISTED at this serial, because the
                        # runner RE-RESOLVES rather than reading the check's
                        # answer, and release.resolve is serial-agnostic. For
                        # an advisory with no version at all - CVE-2022-0543
                        # reads "n/a" - version_prefixes returns [], resolve
                        # returns None, and by_package takes the first usable
                        # release: noble, which did not exist at 20220217. The
                        # app would plan focal and the runner would provision
                        # noble, and the two must not disagree.
                        #
                        # Narrowed HERE and not in the app's sweep: there, every
                        # built release has to answer before anything is
                        # refused, so a release that did not exist answers with
                        # that fact instead of being removed from the pool.
                        usable = tuple(
                            item
                            for item in release.available(
                                release.RELEASES, self._resolved_images()
                            )
                            if release.existed(item, serial_at_hand)
                        )
                        if not usable:
                            raise RunnerFailure(
                                "unsupported_target",
                                "no generic base image is built; build one with "
                                "scripts/build-images.py",
                            )
                        resolution = release.resolve(
                            facts.setup_packages,
                            facts.affected_range,
                            usable,
                            self.fetch_fn,
                            facts.fixed_versions,
                        )
                        if resolution is None and not release.version_prefixes(
                            facts.affected_range
                        ):
                            resolution = release.by_package(
                                facts.setup_packages, usable, self.fetch_fn
                            )
                        if facts.setup_packages and resolution is None and not approved:
                            raise RunnerFailure(
                                "unsupported_target",
                                release.unresolved(
                                    facts.setup_packages, facts.affected_range
                                ),
                            )
                        derived_release = resolution
                        if check_id:
                            # Beside the facts, so a rebuild replays the same
                            # release instead of re-asking every dated index -
                            # which is a network round trip per release and
                            # could answer differently, or refuse, months later.
                            sourcestore.save_resolution(
                                self.data_dir, check_id, release.dump(resolution)
                            )
                        target = generic.derive(
                            facts,
                            poc_url or "generated",
                            resolution,
                            fallback=usable[0],
                            artifact=bundle_sha256(approved) if approved else "",
                        )
                        if not experiment:
                            # An experiment's entrypoint is the harness's own,
                            # not one the advisory named.
                            generic.entrypoint(facts)
                        generic.tokens(facts.setup_packages, "package")
                        generic.tokens(facts.setup_units, "unit")
                    except generic.NoObservable as exc:
                        raise RunnerFailure("no_observable", str(exc)) from exc
                    derived_facts = facts
                cve_id = facts.cve_id
                if facts.dropped_citations:
                    # Recorded as evidence rather than swallowed, so a reader
                    # can see what the model cited and could not back up.
                    note = (
                        f"{len(facts.citations)} citation(s) verified, "
                        f"{len(facts.dropped_citations)} dropped\n\n"
                        + "\n".join(facts.dropped_citations)
                    ).encode("utf-8")
                    note_path = attempt_dir / "citations-dropped.txt"
                    note_path.write_bytes(note)
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="evidence",
                        path=note_path,
                        sha256=hashlib.sha256(note).hexdigest(),
                        size=len(note),
                    )
                return target, facts.cve_id

            def plan_step() -> TargetInstance:
                assert target is not None and cve_id is not None
                # Only a checked-in target has a pinned repository to match.
                # A derived target's pin *is* the submitted URL, and an
                # experiment has no URL at all - a model writes the PoC.
                if derived_facts is None:
                    normalized = poc_url.rstrip("/").removesuffix(".git")
                    expected = target.poc.repository.rstrip("/").removesuffix(".git")
                    if normalized != expected:
                        raise RunnerFailure(
                            "unsupported_poc", "PoC URL does not match the target pin"
                        )
                if derived_facts is not None:
                    # A derived target's claims are not a constant the audit
                    # page can look up by target id: an ecosystem job that ran
                    # a fixed-version control says more than one that could
                    # not, and names the versions it moved. Recorded as
                    # evidence at the moment they were decided.
                    criteria = json.dumps(
                        {
                            "proves": list(target.what_proves),
                            "not_proves": list(target.what_does_not_prove),
                        },
                        indent=2,
                    ).encode("utf-8")
                    criteria_path = attempt_dir / "criteria.json"
                    criteria_path.write_bytes(criteria)
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="evidence",
                        path=criteria_path,
                        sha256=hashlib.sha256(criteria).hexdigest(),
                        size=len(criteria),
                    )
                set_plan(
                    conn,
                    job_id,
                    cve_id=cve_id,
                    target_id=target.target_id,
                    bundle_sha256=bundle,
                )
                return target

            def derived_target(plan: EnvironmentPlan) -> TargetInstance:
                """Rebuild a derived target from what its check stored.

                No extractor call and no release lookup: both ran once, at
                admission, and their answers were kept. Re-asking either risks
                standing up a DIFFERENT lab than the one being reproduced -
                the extractor is not deterministic, and a dated index can
                answer differently, or refuse, months later.

                The facts are checked again here even though
                build_environment checked them: an environment can wait in the
                queue long enough for the 7-day retention sweep to remove the
                store underneath it.
                """
                nonlocal approved, cve_artifact, derived_facts, derived_release
                facts_json = sourcestore.load_facts(self.data_dir, plan.check_id)
                if not facts_json:
                    raise RunnerFailure(
                        "unsupported_target",
                        "the stored facts for this derived target have aged out",
                    )
                derived_facts = Facts.model_validate_json(facts_json)
                derived_release = release.restore(
                    sourcestore.load_resolution(self.data_dir, plan.check_id)
                )
                try:
                    held = sourcestore.load(self.data_dir, plan.check_id)
                except sourcestore.SourceStoreError:
                    held = {}
                # The approved files, which derive REFUSES without when the
                # facts name a placement: blasty's 000-default.conf is what
                # makes apache2 2.4.49 vulnerable, and without it the rebuild
                # died with "it needs a file placed as apache-site".
                # stage_approved then runs off this list on the shared path,
                # with no environment-specific step.
                approved = _approved_from(held)
                # And the advisory, for the snapshot serial. The comment on
                # `published` below says cve_artifact is never assigned on a
                # rebuild - true until now, because a rebuild had no
                # derived_release and the guard short-circuited. A DERIVED
                # rebuild has one, so the serial is computed and the advisory
                # has to be there: it is in the same store, pinned by the same
                # digest the check recorded.
                if "cve" in held:
                    cve_artifact = ArtifactText(
                        "cve", held["cve"].sha256, held["cve"].text
                    )
                try:
                    return generic.derive(
                        derived_facts,
                        # run_job's own parameter. self._job is a
                        # threading.local holding a deadline and a secrets
                        # list, and never carried a poc_url - reaching for one
                        # there raised AttributeError and failed the rebuild at
                        # select_target with "harness_error", which says
                        # nothing about what was wrong.
                        poc_url or "generated",
                        derived_release,
                        fallback=release.RELEASES[0],
                        artifact=bundle_sha256(approved) if approved else "",
                    )
                except generic.NoObservable as exc:
                    raise RunnerFailure("no_observable", str(exc)) from exc

            def select_step() -> TargetInstance:
                # The whole of steps 1-3, for a rebuild: the target is already
                # known, so there is nothing to fetch and nothing to ask a
                # model. Recorded as a step anyway, so the page shows what was
                # chosen and on whose say-so.
                assert environment is not None
                chosen: TargetInstance | None
                if environment.target_id == generic.GENERIC_ID:
                    chosen = derived_target(environment)
                else:
                    chosen = TARGETS.get(environment.target_id)
                if chosen is None:
                    raise RunnerFailure(
                        "unsupported_target", f"unknown target: {environment.target_id}"
                    )
                set_plan(
                    conn,
                    job_id,
                    cve_id=environment.cve_id,
                    target_id=chosen.target_id,
                    bundle_sha256="",
                )
                return chosen

            if environment is not None:
                target = self._step(
                    conn, job_id, attempt_id, 1, "select_target", None, select_step
                )
                cve_id = environment.cve_id
            else:
                # Extract and plan are separate steps so failures are attributable.
                target, cve_id = self._step(
                    conn, job_id, attempt_id, 2, "extract", None, extract_step
                )
                target = self._step(conn, job_id, attempt_id, 3, "plan", None, plan_step)
            target_deadline = self.target_deadlines.get(target.target_id)
            if target_deadline is not None:
                self._job.deadline_at = self._job.job_started_at + target_deadline

            def create_network() -> dict[str, Any]:
                nonlocal network_id
                assert client is not None
                params: dict[str, Any] = {
                    "job_id": job_id,
                    "profile_id": target.network_profile_id,
                }
                # Only a derived path has fetched an advisory at all: an
                # environment rebuild starts at select_target and cve_artifact
                # is never assigned, so reading it unconditionally here turned
                # every rebuild into a harness_error at create_network.
                published = (
                    generic.advisory_published(cve_artifact.text)
                    if derived_release is not None or ecosystem_env is not None
                    else ""
                )
                if derived_release is not None:
                    # Provision from just before the advisory, so apt resolves
                    # the build that was current while the flaw was still
                    # unpublished.
                    serial = generic.snapshot_for(published)
                    if not serial:
                        # "" used to leave the broker's default in force, and
                        # that default is 20261101 - now. So an advisory older
                        # than SNAPSHOT_FLOOR installed TODAY'S packages:
                        # sudo CVE-2019-18634 resolved 1.8.23 and job 5bd509cb
                        # installed 1.9.17p2-9. Readiness caught that one only
                        # because expected_version was set; the by_package and
                        # ceiling-sweep paths leave it empty by design, and
                        # there the exploit would have run against a patched
                        # build and reported that it did not reproduce.
                        raise RunnerFailure(
                            "unsupported_target",
                            f"no snapshot serial for {published or 'an undated advisory'}:"
                            f" this harness provisions from one day before the advisory"
                            f" and verifies no archive older than"
                            f" {generic.SNAPSHOT_FLOOR.date()}; today's would reproduce"
                            f" nothing",
                        )
                    params["apt_snapshot"] = serial
                    # Which archive this release's serials index. Ubuntu never
                    # published some affected versions at all, and its snapshot
                    # service begins in 2023; Debian's reaches back far enough
                    # to still hold them.
                    params["apt_archive"] = generic.release_for(derived_release).archive
                # Two callers, one rule: a package registry publishes no
                # snapshot of its own, so the proxy serves an index holding only
                # what existed on that date. "" is not "today" - the broker
                # starts no proxy without a cutoff, because "an unpinned
                # registry is the one thing this must never serve" - so an
                # install fails rather than pinning whatever semver answers now.
                #
                # The ecosystem target needs it for the lab's dependencies. An
                # apt target needs it when the PoC imports something the
                # attacker image lacks: job 76007d7f armed setup-attacker and
                # then refused, with the proxy running and no date to serve it.
                pip_wanted = derived_facts is not None and derived_facts.attacker_pip
                if ecosystem_env is not None or pip_wanted:
                    cutoff = generic.cutoff_for(published)
                    if not cutoff:
                        raise RunnerFailure(
                            "no_observable",
                            "this advisory carries no usable publication date, so there "
                            "is no date to pin a package index at, and neither an "
                            "ecosystem lab's dependencies nor a PoC's own imports can be "
                            "resolved without one",
                        )
                    params["registry_cutoff"] = cutoff
                result = client.call("create_network", params)
                network_id = str(result["network_id"])
                return result

            network = self._step(conn, job_id, attempt_id, 4, "create_network", None, create_network)
            # The broker journals only a hash of each result, so the inputs the
            # guest was given are recorded here as readable evidence. The apt
            # snapshot serial is the load-bearing one: without it, "it
            # installed apache2" does not say which apache2, and a provision
            # nobody can pin down is not a provision anyone can repeat.
            inputs = json.dumps(
                {
                    "network_id": network.get("network_id", ""),
                    "subnet": network.get("subnet", ""),
                    "proxy_url": network.get("proxy_url", ""),
                    "apt_proxy_url": network.get("apt_proxy_url", ""),
                    "apt_snapshot": network.get("apt_snapshot", ""),
                    "apt_archive": network.get("apt_archive", ""),
                    # The registry cutoff is the same kind of fact: without it,
                    # "it installed next 16.4.0" does not say why that version.
                    "registry_proxy_url": network.get("registry_proxy_url", ""),
                    "registry_cutoff": network.get("registry_cutoff", ""),
                },
                indent=2,
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            inputs_path = attempt_dir / "provision-inputs.json"
            inputs_path.write_bytes(inputs)
            record_artifact(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                kind="evidence",
                path=inputs_path,
                sha256=hashlib.sha256(inputs).hexdigest(),
                size=len(inputs),
            )

            def create_target() -> dict[str, Any]:
                nonlocal target_vm
                assert client is not None and target is not None
                result = client.call(
                    "create_target",
                    {
                        "job_id": job_id,
                        "target_id": target.target_id,
                        "image_id": target.base_image_id,
                    },
                )
                target_vm = str(result["vm_id"])
                return result

            target_info = self._step(conn, job_id, attempt_id, 5, "create_target", None, create_target)

            def stage_app() -> dict[str, Any]:
                """Put the lab's source inside the target.

                Only the source: the dependencies come from the job's registry
                mirror during provisioning, and the runtime with them. The
                archive is copied in by the broker, which verifies its digest
                on the host and again in the guest, and the same bytes are the
                PoC the attacker runs - so they are fetched once rather than
                twice from a repository that could move between two reads.
                """
                nonlocal app_archive_sha, poc_archive_sha
                assert client is not None and target is not None
                repository = target.poc.repository
                if not repository.startswith("https://github.com/"):
                    raise RunnerFailure(
                        "unsupported_poc",
                        f"only github.com PoC repositories can be staged: {repository}",
                    )
                slug = repository.removeprefix("https://github.com/")
                fetched = self.fetch_fn(
                    f"https://codeload.github.com/{slug}/tar.gz/HEAD",
                    max_bytes=MAX_POC_BYTES,
                )
                archive_path = attempt_dir / "app-source.tar.gz"
                archive_path.write_bytes(fetched.body)
                app_archive_sha = fetched.sha256
                # The same bytes are the PoC the attacker runs, so they are
                # fetched once and staged once rather than twice from a
                # repository that could move between the two reads.
                poc_archive_sha = fetched.sha256
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind="poc",
                    path=archive_path,
                    sha256=fetched.sha256,
                    size=len(fetched.body),
                )
                copied = []
                for artifact_id in (APP_ARCHIVE_ID, target.poc.artifact_id):
                    client.call(
                        "stage_artifact",
                        {
                            "job_id": job_id,
                            "artifact_id": artifact_id,
                            "path": str(archive_path),
                            "sha256": fetched.sha256,
                        },
                    )
                result = client.call(
                    "copy_in",
                    {
                        "vm_id": target_vm,
                        "artifact_id": APP_ARCHIVE_ID,
                        "guest_path": f"{APP_ARCHIVE_ID}.tar.gz",
                    },
                )
                copied.append(str(result["remote_path"]))
                return {"copied": copied, "app_sha256": fetched.sha256}

            def stage_approved() -> dict[str, Any]:
                """Put the operator-approved file inside the target.

                The bytes were fetched on the host at approval time and their
                digest recorded with the check, so this re-verifies rather than
                trusts: the broker checks the digest before copying and the
                guest's copy is checked again after. It happens before
                provisioning, which is before lock_network, because nothing can
                be downloaded afterwards.
                """
                assert client is not None and target is not None and approved
                result: dict[str, Any] = {}
                for index, item in enumerate(_approved_names(approved)):
                    fetched, name = item
                    path = attempt_dir / name
                    path.write_bytes(fetched.body)
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="package",
                        path=path,
                        sha256=fetched.sha256,
                        size=len(fetched.body),
                    )
                    staged_id = f"{APPROVED_ID}-{index}"
                    client.call(
                        "stage_artifact",
                        {
                            "job_id": job_id,
                            "artifact_id": staged_id,
                            "path": str(path),
                            "sha256": fetched.sha256,
                        },
                    )
                    # Its own name inside the guest, because the SUFFIX is what
                    # decides the install and the step derives it per file.
                    result = dict(
                        client.call(
                            "copy_in",
                            {
                                "vm_id": target_vm,
                                "artifact_id": staged_id,
                                "guest_path": name,
                            },
                        )
                    )
                return result

            # A docker target needs the repository inside the TARGET too: the
            # build context is the PoC's own tree, .debs and config and all.
            dockerfile = (
                derived_facts.dockerfile if derived_facts is not None else None
            )
            # BOTH staging steps can fire in one job, and both used seq 6.
            # blasty's CVE-2021-41773 repository ships an approved .deb set AND
            # a Dockerfile at its root - "" is the root, not "no Dockerfile" -
            # so the job took both paths and the second INSERT hit "UNIQUE
            # constraint failed: job_steps.job_id, attempt_id, seq". It then
            # died as a bare harness_error; the synthetic runner step is what
            # finally carried the message out.
            #
            # app_staged COUNTS the staging steps rather than flagging that any
            # ran, so every later seq shifts by the right amount: 7 when one
            # staged, 8 when both did.
            approved_staged = 1 if approved else 0
            docker_staged = 1 if ecosystem_env is not None or dockerfile is not None else 0
            app_staged = approved_staged + docker_staged
            if approved:
                self._step(
                    conn, job_id, attempt_id, 6, "stage_approved", None, stage_approved
                )
            if docker_staged:
                self._step(
                    conn, job_id, attempt_id, 6 + approved_staged, "stage_app", None,
                    stage_app,
                )

            def setup_params() -> dict[str, str]:
                assert target is not None
                proxy_url = str(network["proxy_url"])
                if ecosystem_env is not None:
                    registry_url = str(network.get("registry_proxy_url") or "")
                    if not registry_url:
                        raise RunnerFailure(
                            "provision_failed",
                            "this target installs from the dated registry mirror but "
                            "none is running: set XENTRY_START_REGISTRY_PROXY=1 on the "
                            "broker",
                        )
                    params = {
                        "registry_url": registry_url.rstrip("/") + "/",
                        "node_version": ecosystem.NODE_VERSION,
                        "node_sha256": ecosystem.NODE_SHA256,
                        "app_archive": _guest_artifact(APP_ARCHIVE_ID),
                        "app_dir": str(derived_facts.app_dir or ""),
                        "build": ecosystem_env.build,
                        "start": ecosystem_env.start,
                        "port": str(ecosystem_env.port),
                    }
                    if target.control_port:
                        params["fixed_subject"] = target.subject_package
                        params["fixed_version"] = target.fixed_version
                        params["control_port"] = str(target.control_port)
                    return params
                if dockerfile is not None:
                    oci_url = str(network.get("oci_mirror_url") or "")
                    if not oci_url:
                        raise RunnerFailure(
                            "provision_failed",
                            "this target builds the PoC's own Dockerfile but no "
                            "image mirror is running: set XENTRY_START_OCI_MIRROR=1 "
                            "on the broker",
                        )
                    chosen = generic.release_for(derived_release)
                    return {
                        "apt_proxy_url": str(network.get("apt_proxy_url") or ""),
                        "suite": chosen.suite,
                        "sources_format": chosen.sources_format,
                        "archive": str(network.get("apt_archive") or chosen.archive),
                        "check_valid_until": (
                            "1" if network.get("apt_check_valid_until", True) else "0"
                        ),
                        "oci_mirror_url": oci_url,
                        "app_archive": _guest_artifact(APP_ARCHIVE_ID),
                        "dockerfile_dir": dockerfile,
                        "container_apt_host": str(network.get("container_apt_host") or ""),
                        "ports": " ".join(str(port) for port in target.target_ports),
                    }
                if derived_facts is not None:
                    apt_proxy_url = str(network.get("apt_proxy_url") or "")
                    wanted = list(derived_facts.setup_packages)
                    if target.poc_context == "local":
                        # Most privesc PoCs are C, the generic image carries
                        # three packages and a keyring, and the guest has no
                        # network - so without a toolchain every C exploit
                        # fails at the build step. Installed from the same
                        # dated serial as everything else and listed in this
                        # step's own parameters, so a reader sees it.
                        wanted += [
                            name
                            for name in generic.LOCAL_TOOLCHAIN
                            if name not in wanted
                        ]
                    packages = generic.tokens(wanted, "package")
                    if packages and not apt_proxy_url:
                        raise RunnerFailure(
                            "provision_failed",
                            "this target needs packages but no apt mirror is running: "
                            "set XENTRY_START_APT_PROXY=1 on the broker",
                        )
                    chosen = generic.release_for(derived_release)
                    return {
                        "apt_proxy_url": apt_proxy_url or "http://0.0.0.0:0",
                        "suite": chosen.suite,
                        # The archive's own path under the proxy, and whether
                        # its Release is still inside its freshness window. A
                        # Debian snapshot Release expired the week it was made,
                        # with its signature perfectly good, so apt refuses it
                        # on freshness alone unless told not to.
                        "archive": str(network.get("apt_archive") or chosen.archive),
                        "check_valid_until": (
                            "1" if network.get("apt_check_valid_until", True) else "0"
                        ),
                        "packages": packages,
                        "units": generic.tokens(derived_facts.setup_units, "unit"),
                        "sources_format": chosen.sources_format,
                        # The setup step proves these are served before it
                        # reports success, so a service that never came up, or
                        # came up on loopback only, is named here rather than
                        # five minutes later as "port N never accepted".
                        "ports": " ".join(str(port) for port in target.target_ports),
                        **(
                            {
                                # Names, not paths: the step resolves each under
                                # its own directory, and each file's suffix
                                # decides its install. One token list, like
                                # packages and units, rather than two parallel
                                # lists that could fall out of step.
                                "artifacts": " ".join(
                                    name for _f, name in _approved_names(approved)
                                ),
                                # "" when the extractor named none, which the
                                # setup step refuses straight after unpacking
                                # rather than at the port wait.
                                "launch": generic.tokens(
                                    [derived_facts.launch or ""], "launch"
                                ),
                                "place": generic.placement(derived_facts),
                            }
                            if approved
                            else {}
                        ),
                    }
                if target.target_id == "php2shell":
                    return {
                        "proxy_url": proxy_url,
                        "php_artifact_id": "php-8.4.26-src",
                        "php_sha256": _artifact_sha("php-8.4.26-src"),
                    }
                if target.target_id == "gitlab":
                    return {
                        "proxy_url": proxy_url,
                        "gitlab_artifact_id": "gitlab-19.2.5-deb",
                        "gitlab_sha256": _artifact_sha("gitlab-19.2.5-deb"),
                    }
                return {
                    "proxy_url": proxy_url,
                    "kernel_artifact_id": "kernel-6.17.0-23",
                    "kernel_sha256": _artifact_sha("kernel-6.17.0-23"),
                    "kernel_modules_artifact_id": "kernel-modules-6.17.0-23",
                    "kernel_modules_sha256": _artifact_sha("kernel-modules-6.17.0-23"),
                }

            # ONE BUILDER FOR READINESS PARAMETERS, called by the reviewed
            # provisioning path and by the harness path beside it. It was
            # inline in readiness_step, which is defined AFTER the provision
            # step runs - so a harness branch could not reuse it and would have
            # rebuilt this three-way conditional from scratch. Two copies of
            # "what readiness is asked" is how two paths start disagreeing
            # about what a ready target even is.
            def readiness_params() -> dict[str, Any]:
                assert target is not None
                if ecosystem_env is not None:
                    return {
                        "ports": " ".join(str(port) for port in target.target_ports),
                        # The version to expect is read from the pinned lockfile
                        # inside the guest, not passed in: npm resolves, so what
                        # the lab declared need not survive. Only the name travels.
                        "package": target.subject_package,
                    }
                if derived_facts is None:
                    return {}
                package = derived_release.package if derived_release is not None else ""
                # The CVE id, so readiness can ask the installed package's own
                # changelog whether it already carries this fix - the backported
                # case no version check can see.
                common = {
                    "package": package,
                    "expected_version": target.expected_version,
                    "cve_id": target.cve_ids[0] if target.cve_ids else "",
                    # Every branch the advisory marks affected, not just the one
                    # resolve() chose. It collapses a multi-branch range to its
                    # lowest bound, so CVE-2025-32433 - affected below 27.3.3,
                    # 26.2.5.11 AND 25.3.2.20 - reduced to "25.3.2" and readiness
                    # rejected the installed 27.3.2 that the first branch covers.
                }
                # Omitted entirely for a single-branch advisory rather than sent
                # empty: validate_params fills a missing param with "", so the
                # script sees the same argument either way, and every existing
                # caller's parameter set is unchanged.
                branches = " ".join(
                    f"{floor}:{ceiling}:{1 if inclusive else 0}"
                    for floor, ceiling, inclusive in release.segments(
                        getattr(derived_facts, "affected_range", "") or ""
                    )
                )
                if branches:
                    common["affected_ranges"] = branches
                if target.poc_context == "local":
                    # No ports: nothing listens for a local PoC, and
                    # readiness-local checks the evidence channel is shut to
                    # this actor instead.
                    return common
                return {
                    "ports": " ".join(str(port) for port in target.target_ports),
                    **common,
                }

            def harness_provision() -> dict[str, Any]:
                """A model builds the target; a rebuild decides whether it worked.

                Nothing it does by hand reaches the measured machine: the
                verification reverts to a snapshot taken before it touched
                anything, runs only its digest-checked script, compares the
                result against the state it explored, and only then asks
                readiness. ADR 0003.
                """
                assert client is not None and target is not None and target_vm is not None
                if self.provision_fn is None:
                    raise RunnerFailure(
                        "harness_error", "harness mode needs a provisioner model"
                    )
                layer = harness.ToolLayer(
                    call_broker=client.call,
                    job_id=job_id,
                    target_vm_id=target_vm,
                    record=lambda verb, sent: session_event(
                        conn, job_id, "tool_call", {"verb": verb, "params": sent}
                    ),
                )

                def run(command: str) -> str:
                    result = layer.call("free_exec_target", {"command": command})
                    return str(result.get("stdout") or "")

                # Taken before the model touches anything, so every verification
                # starts from a machine with no history.
                # "disk", not a name of my own: the broker allows exactly
                # {"disk", "memory"} and answered "invalid snapshot kind" to
                # an invented "harness-clean" on the first live run. Disk is
                # the right one anyway - the revert wants the base image's
                # filesystem, not a RAM image of a machine mid-exploration.
                snapshot = client.call("snapshot", {"vm_id": target_vm, "kind": "disk"})
                reference = harness.capture(run)

                def check_ready(payload: dict[str, Any]) -> harness.Verification:
                    assert client is not None and target is not None
                    script = self.data_dir / "jobs" / job_id / "out" / "provision.sh"
                    if not script.is_file():
                        return harness.Verification(
                            False,
                            "no_script",
                            "nothing was copied out under the name provision.sh",
                        )
                    # Hashed here and checked again in the broker: the digest
                    # recorded is the digest executed, so a script regenerated
                    # between the declaration and the run refuses.
                    digest = hashlib.sha256(script.read_bytes()).hexdigest()
                    declared = str(payload.get("declared_version") or "")
                    verdict = harness.verify(
                        revert=lambda: client.call(
                            "restore",
                            {
                                "vm_id": target_vm,
                                "snapshot_id": snapshot["snapshot_id"],
                            },
                        ),
                        run_script=lambda: client.call(
                            "exec",
                            {
                                "vm_id": target_vm,
                                "step_id": "provision-generated",
                                "script_sha256": digest,
                                "timeout_s": target.timeouts.provision_s,
                            },
                        ),
                        run=run,
                        readiness=lambda: client.call(
                            "exec",
                            {
                                "vm_id": target_vm,
                                "step_id": target.readiness_step_id,
                                # The one builder both paths use. A from-source
                                # build has no package database to ask, so the
                                # version the model DECLARED is what readiness
                                # verifies by running the binary.
                                "params": {
                                    **readiness_params(),
                                    **({"expected_version": declared} if declared else {}),
                                },
                                "tty": False,
                                "timeout_s": target.timeouts.readiness_s,
                            },
                        ),
                        reference=reference,
                    )
                    session_event(
                        conn,
                        job_id,
                        "readiness",
                        {
                            "passed": verdict.passed,
                            "reason_code": verdict.reason_code,
                            "detail": verdict.detail[:4000],
                        },
                    )
                    return verdict

                prompt = harness.prompt_for(derived_facts, HARNESS_READINESS_CALLS)
                prompt_path = attempt_dir / "provision.prompt.txt"
                prompt_path.write_text(prompt, encoding="utf-8")
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind="llm_provision_prompt",
                    path=prompt_path,
                    sha256=hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                    size=len(prompt.encode("utf-8")),
                )
                outcome = harness.run_session(
                    self.provision_fn(prompt, layer.call),
                    check_ready,
                    lambda: cve_artifact.text[:20000],
                    max_readiness=HARNESS_READINESS_CALLS,
                )
                session_event(
                    conn,
                    job_id,
                    "declaration",
                    {
                        "declaration": outcome.outcome,
                        "reason_code": outcome.reason_code,
                        "summary": outcome.detail[:4000],
                    },
                )
                if outcome.outcome != "ready":
                    # The give-up reasoning is the whole value of a failed
                    # harness run, and _detail truncates - so it is an
                    # artifact, not only a step detail.
                    gave_up = attempt_dir / "provision-gave-up.txt"
                    body = f"{outcome.reason_code}\n\n{outcome.detail}"
                    gave_up.write_text(body, encoding="utf-8")
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="evidence",
                        path=gave_up,
                        sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
                        size=len(body.encode("utf-8")),
                    )
                    raise RunnerFailure(
                        "provision_failed", outcome.detail or outcome.reason_code
                    )
                return {
                    "readiness_calls": outcome.readiness_calls,
                    "script_sha256": outcome.payload.get("script"),
                }

            def setup_step() -> dict[str, Any]:
                assert client is not None and target is not None and target_vm is not None
                result = client.call(
                    "exec",
                    {
                        "vm_id": target_vm,
                        "step_id": target.setup_step_id,
                        "params": setup_params(),
                        "tty": False,
                        "timeout_s": target.timeouts.provision_s,
                        # Only this step's trace is collected, and provisioning
                        # runs before any nonce exists, so no nonce value can
                        # reach a traced command line.
                        "trace": True,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure(
                        "provision_failed",
                        self._output(result) or "setup failed",
                    )
                return result

            # Recorded before the step runs, so a failed provision still shows
            # which script was executed. These are the same bytes the broker
            # re-verifies on the guest, so this digest must equal the step's
            # pinned sha256 in targets/steps.yaml.
            setup_bytes = setup_script_path(target).read_bytes()
            setup_copy = attempt_dir / "setup.sh"
            setup_copy.write_bytes(setup_bytes)
            record_artifact(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                kind="setup_script",
                path=setup_copy,
                sha256=hashlib.sha256(setup_bytes).hexdigest(),
                size=len(setup_bytes),
            )
            # Collected once the step returns, not followed live: every broker
            # call is attributed, sequenced in arrival order and recorded
            # one-for-one, and a second thread polling during the exec cannot
            # hold that ordering. Provisioning also runs before any nonce is
            # placed, so no nonce value can appear in this trace.
            commands_path = attempt_dir / "provision-commands.txt"
            # Harness mode replaces the provisioning step and nothing else:
            # the same position, the same seq, a different way of getting there.
            harnessed = str((get_job(conn, job_id) or {}).get("kind")) == "harness_job"
            try:
                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    6 + app_staged,
                    "provision",
                    "provision-generated" if harnessed else target.setup_step_id,
                    harness_provision if harnessed else setup_step,
                )
            finally:
                if target_vm:
                    self._collect_step_trace(client, target_vm, target.setup_step_id, commands_path)
                if commands_path.is_file():
                    trace_bytes = commands_path.read_bytes()
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="evidence",
                        path=commands_path,
                        sha256=hashlib.sha256(trace_bytes).hexdigest(),
                        size=len(trace_bytes),
                    )

            rebooted = False
            # A kernel on disk is not the kernel that is running. The setup
            # step has installed it and pointed grub at it; this is where the
            # machine actually becomes the thing under test, and readiness
            # refuses to continue unless `uname -r` is what was installed.
            kernel_job = derived_facts is not None and generic.is_kernel(derived_facts)
            if target.target_id == "dirtyfrag" or kernel_job:
                def reboot_step() -> dict[str, Any]:
                    assert client is not None and target_vm is not None
                    return client.call("reboot", {"vm_id": target_vm, "timeout_s": 300})

                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    7 + app_staged,
                    "reboot",
                    "reboot-dirtyfrag" if not kernel_job else "reboot-generic",
                    reboot_step,
                )
                rebooted = True

            def readiness_step() -> dict[str, Any]:
                assert client is not None and target is not None and target_vm is not None
                result = client.call(
                    "exec",
                    {
                        "vm_id": target_vm,
                        "step_id": target.readiness_step_id,
                        "params": readiness_params(),
                        "tty": False,
                        "timeout_s": target.timeouts.readiness_s,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure(
                        "target_unhealthy",
                        self._output(result) or "readiness failed",
                    )
                return result

            self._step(
                conn,
                job_id,
                attempt_id,
                (8 if rebooted else 7) + app_staged,
                "readiness",
                target.readiness_step_id,
                readiness_step,
            )

            # The attacker's own provisioning, in the one window it has: after
            # the VM exists and before lock_network takes its network away.
            # Its archive is not the target's - the target's proxy serves one
            # archive at one serial, and for a 2021 advisory that is Debian sid
            # at 20211004, which would ask Ubuntu noble to install Debian
            # packages. The broker runs a second proxy, Ubuntu at the current
            # serial, for exactly this.
            attacker_packages = (
                generic.tokens(derived_facts.attacker_packages, "package")
                if derived_facts is not None
                else ""
            )
            # What the PoC imports, taken from the job's date-pinned PyPI index
            # rather than baked into the attacker image. CVE-2023-48795 passed
            # sixteen steps and died on `from termcolor import colored`: the
            # image carries colorama and not termcolor, and the network is
            # locked before the exploit so nothing can be fetched later. The
            # registry proxy already filters PyPI by upload-time - it was built
            # for the npm path and the PyPI half had no caller - so this
            # installs what PyPI held one day before the advisory, which is the
            # rule the apt side has always followed. A pinned wheel in the image
            # could not do that: it would be one undated version for every job.
            attacker_pip = (
                generic.tokens(derived_facts.attacker_pip, "pip")
                if derived_facts is not None
                else ""
            )
            attacker_apt = str(network.get("attacker_apt_proxy_url") or "")
            attacker_registry = str(network.get("registry_proxy_url") or "")
            armed = (
                1
                if (attacker_packages or attacker_pip) and target.attacker_profile_id
                else 0
            )
            if target.attacker_profile_id:
                def create_attacker() -> dict[str, Any]:
                    nonlocal attacker_vm
                    assert client is not None and target is not None
                    result = client.call(
                        "create_attacker",
                        {
                            "job_id": job_id,
                            "profile_id": target.attacker_profile_id,
                            "image_id": ATTACKER_IMAGE,
                        },
                    )
                    attacker_vm = str(result["vm_id"])
                    nonlocal attacker_ip
                    attacker_ip = str(result.get("guest_ip") or "")
                    return result

                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    8 + app_staged,
                    "create_attacker",
                    None,
                    create_attacker,
                )

            if armed:
                def setup_attacker() -> dict[str, Any]:
                    assert client is not None
                    if attacker_packages and not attacker_apt:
                        raise RunnerFailure(
                            "provision_failed",
                            "the PoC needs packages on the attacker but no "
                            "attacker apt mirror is running: set "
                            "XENTRY_START_APT_PROXY=1 on the broker",
                        )
                    if attacker_pip and not attacker_registry:
                        raise RunnerFailure(
                            "provision_failed",
                            f"the PoC imports {attacker_pip}, which the attacker "
                            "image does not carry, and no registry proxy is "
                            "running to install them from the advisory's date: "
                            "set XENTRY_START_REGISTRY_PROXY=1 on the broker",
                        )
                    result = client.call(
                        "exec",
                        {
                            "vm_id": attacker_vm,
                            "step_id": "setup-attacker",
                            "params": {
                                "apt_proxy_url": attacker_apt,
                                # ATTACKER_SUITE, not the target's: this has to
                                # match the attacker image, and the test beside
                                # it keeps the two from drifting.
                                "suite": ATTACKER_SUITE,
                                "archive": "ubuntu",
                                "check_valid_until": "1",
                                "sources_format": "deb822",
                                "packages": attacker_packages,
                                "registry_url": attacker_registry,
                                "pip_packages": attacker_pip,
                            },
                            "tty": False,
                            "timeout_s": 1800,
                        },
                    )
                    if result["exit_code"] != 0:
                        raise RunnerFailure(
                            "provision_failed",
                            "the attacker could not install "
                            f"{attacker_packages or attacker_pip}: "
                            f"{self._output(result)}",
                        )
                    return dict(result)

                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    9 + app_staged,
                    "setup_attacker",
                    "setup-attacker",
                    setup_attacker,
                )

            assert target is not None and target_vm is not None
            guest_ip = str(target_info["guest_ip"])

            def lock_network() -> dict[str, Any]:
                """Close the provisioning channel before any PoC code runs.

                Provisioning reached two host services over the job bridge: the
                artifact mirror and the apt snapshot proxy. Nothing after
                readiness needs either - the PoC arrives by scp from the host,
                and every step from here on talks to the target or to nothing.
                Leaving them reachable would give a stranger's exploit, running
                as a live process, the one path off its own bridge.
                """
                assert client is not None and target is not None
                return client.call(
                    "lock_network",
                    {
                        "job_id": job_id,
                        "target_ports": [int(port) for port in target.target_ports],
                    },
                )

            # An environment is held for an operator to work in and runs no PoC,
            # so it keeps its apt path: the reason to close it does not apply.
            if not environment:
                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    9 + app_staged + armed,
                    "lock_network",
                    None,
                    lock_network,
                )

            def author_poc() -> dict[str, Any]:
                """Ask a model for a PoC and stage it like any other artifact.

                The generated file goes in as a tarball through the same
                stage_artifact/copy_in path a GitHub PoC takes, and is run by
                the same checked-in step as the same unprivileged actor. The
                boundary does not move; only the provenance does.
                """
                nonlocal poc_archive_sha
                assert client is not None and derived_facts is not None
                code = pocgen.author(
                    cve_artifact.text,
                    derived_facts,
                    guest_ip,
                    redact(last_failure, self._job.secrets),
                )
                source_path = attempt_dir / f"exploit-{poc_attempt}.py"
                source_path.write_text(code, encoding="utf-8")
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind="poc",
                    path=source_path,
                    sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
                    size=len(code.encode("utf-8")),
                )
                # Tarred so the checked-in build step unpacks it unchanged:
                # --strip-components=1 puts poc/exploit.py at poc_dir/exploit.py.
                archive_path = attempt_dir / "poc-generic.tar.gz"
                archive_path.unlink(missing_ok=True)
                with tarfile.open(archive_path, "w:gz") as archive:
                    archive.add(source_path, arcname=f"poc/{generic.AUTHORED_ENTRYPOINT}")
                body = archive_path.read_bytes()
                poc_archive_sha = hashlib.sha256(body).hexdigest()
                return dict(
                    client.call(
                        "stage_artifact",
                        {
                            "job_id": job_id,
                            "artifact_id": target.poc.artifact_id,
                            "path": str(archive_path),
                            "sha256": poc_archive_sha,
                        },
                    )
                )

            def stage_poc() -> dict[str, Any]:
                # The PoC of a derived target is a repository nobody pinned, so
                # the bytes are fetched here, recorded as evidence, and handed
                # to the broker with their digest. The broker re-verifies it,
                # keeps the file inside this job's directory, and scopes the
                # registration to this job.
                nonlocal poc_archive_sha
                assert client is not None and derived_facts is not None
                repository = target.poc.repository
                if not repository.startswith("https://github.com/"):
                    raise RunnerFailure(
                        "unsupported_poc",
                        f"only github.com PoC repositories can be staged: {repository}",
                    )
                archive_path = attempt_dir / "poc-generic.tar.gz"
                if generic.has_command(derived_facts):
                    # A command-only PoC: the repository has nothing to run and
                    # the exploit is a line the extractor quoted from its text.
                    # Built here, tarred into the shape the checked-in build
                    # step unpacks, and from there indistinguishable from a
                    # repository's own script - same step, same actor.
                    script = generic.command_script(derived_facts)
                    source_path = attempt_dir / generic.COMMAND_ENTRYPOINT
                    source_path.write_text(script, encoding="utf-8")
                    archive_path.unlink(missing_ok=True)
                    with tarfile.open(archive_path, "w:gz") as archive:
                        archive.add(
                            source_path, arcname=f"poc/{generic.COMMAND_ENTRYPOINT}"
                        )
                    body = archive_path.read_bytes()
                else:
                    slug = repository.removeprefix("https://github.com/")
                    archive_url = f"https://codeload.github.com/{slug}/tar.gz/HEAD"
                    body = self.fetch_fn(archive_url, max_bytes=MAX_POC_BYTES).body
                    archive_path.write_bytes(body)
                poc_archive_sha = hashlib.sha256(body).hexdigest()
                record_artifact(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    kind="poc",
                    path=archive_path,
                    sha256=poc_archive_sha,
                    size=len(body),
                )
                staged_result = client.call(
                    "stage_artifact",
                    {
                        "job_id": job_id,
                        "artifact_id": target.poc.artifact_id,
                        "path": str(archive_path),
                        "sha256": poc_archive_sha,
                    },
                )
                return dict(staged_result)

            # A derived target has one step the pinned ones do not, so every
            # sequence number after it shifts by one - the same way a
            # dirtyfrag reboot shifts readiness.
            # not docker_staged, NOT not app_staged. Only stage_app registers the
            # PoC archive - it stages the same bytes under both APP_ARCHIVE_ID
            # and the poc id - while stage_approved stages the approved FILE and
            # nothing else. Counting both meant an approved-artifact job skipped
            # stage_poc and then failed copy_poc with "unknown artifact_id:
            # poc-generic", which is what blasty's CVE-2021-41773 did at seq 11.
            staged = 1 if derived_facts is not None and not docker_staged else 0
            if experiment:
                self._step(
                    conn, job_id, attempt_id, 10 + app_staged + armed, "author_poc", None, author_poc
                )
            elif staged:
                self._step(
                    conn, job_id, attempt_id, 10 + app_staged + armed, "stage_poc", None, stage_poc
                )

            def copy_poc() -> str:
                assert client is not None
                guest_path = f"poc-{target.target_id}.tar.gz"
                result = client.call(
                    "copy_in",
                    {
                        "vm_id": attacker_vm or target_vm,
                        "artifact_id": target.poc.artifact_id,
                        "guest_path": guest_path,
                    },
                )
                return str(result["remote_path"])

            poc_archive = self._step(
                conn,
                job_id,
                attempt_id,
                10 + staged + app_staged + armed,
                "copy_poc",
                None,
                copy_poc,
            )

            def build_step() -> dict[str, Any]:
                assert client is not None
                result = client.call(
                    "exec",
                    {
                        "vm_id": attacker_vm or target_vm,
                        "step_id": target.build_step_id,
                        "params": {
                            "poc_archive": poc_archive,
                            "poc_sha256": poc_archive_sha or target.poc.sha256,
                            "poc_dir": target.poc_dir,
                            **(
                                {"entrypoint": _entrypoint(derived_facts, experiment)}
                                if derived_facts is not None
                                else {}
                            ),
                        },
                        "tty": False,
                        "timeout_s": 600,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure("poc_build_failed", self._output(result))
                return result

            self._step(
                conn,
                job_id,
                attempt_id,
                11 + staged + app_staged + armed,
                "build_poc",
                target.build_step_id,
                build_step,
            )

            if environment:
                # Everything a PoC needs is now up. Recorded as live state
                # rather than evidence: the page reads it, nothing hashes it.
                keep_running = True
                (attempt_dir / "environment.json").write_text(
                    json.dumps(
                        {
                            "target_vm": target_vm,
                            "attacker_vm": attacker_vm,
                            "network_id": network_id,
                            "target_ip": guest_ip,
                            "attacker_ip": attacker_ip,
                            "keys_dir": str(attempt_dir.parent / "keys"),
                            "poc_dir": target.poc_dir,
                            "built_at": now(),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return

            next_seq = 12 + staged + app_staged + armed
            snapshot_id: str | None = None
            if target.poc_context == "remote":
                def freeze_step() -> dict[str, Any]:
                    assert client is not None and target_vm is not None
                    return client.call("snapshot", {"vm_id": target_vm, "kind": "memory"})

                frozen = self._step(
                    conn, job_id, attempt_id, next_seq, "freeze", None, freeze_step
                )
                snapshot_id = str(frozen["snapshot_id"])
                next_seq += 1

            def place_phase(phase: str) -> tuple[str, str]:
                assert client is not None
                nonce = new_nonce()
                # Keep the value out of any captured model transcript.
                transcript.add_secret(nonce)
                nonce_id = f"{phase}-{uuid.uuid4().hex}"
                result = client.call(
                    "place_nonce",
                    {
                        "vm_id": target_vm,
                        "nonce_id": nonce_id,
                        "path": target.nonce.path,
                        "owner": target.nonce.owner,
                        "mode": target.nonce.mode,
                        "value": nonce,
                    },
                )
                record_nonce(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    phase=phase,
                    nonce_id=nonce_id,
                    sha256=str(result["sha256"]),
                    path=target.nonce.path,
                    owner=target.nonce.owner,
                    mode=target.nonce.mode,
                    # A rewritten PoC gets a fresh nonce for its next try.
                    replace=experiment and phase == "real",
                )
                return nonce, nonce_id

            def null_actor() -> dict[str, Any]:
                nonlocal null_nonce, null_output
                assert client is not None
                null_nonce, _ = place_phase("null")
                self._job.secrets.append(null_nonce)
                params = {"target_ip": guest_ip} if target.attacker_profile_id else {}
                if derived_facts is not None and target.poc_context == "local":
                    # The control the whole observation rests on: try to read
                    # the nonce and write the console with no exploit, and be
                    # denied both.
                    params = {"nonce_path": target.nonce.path}
                elif derived_facts is not None:
                    params["port"] = str(target.target_ports[0])
                result = client.call(
                    "exec",
                    {
                        "vm_id": attacker_vm or target_vm,
                        "step_id": target.null_step_id,
                        "params": params,
                        "tty": False,
                        "timeout_s": 300,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure("probe_failed", "null actor failed")
                null_output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
                return result

            self._step(
                conn, job_id, attempt_id, next_seq, "null_actor", target.null_step_id, null_actor
            )
            next_seq += 1

            def host_serial() -> tuple[str, str]:
                """The host's serial log for this VM, and its digest.

                Read on the host side of a device the guest cannot write, so
                what it contains was observed outside the guest. ("", "") when
                the broker cannot produce it, which the caller treats as the
                nonce being absent - never as the nonce being present.
                """
                assert client is not None
                try:
                    evidence = client.call(
                        "read_host_evidence",
                        {"vm_id": target_vm, "channel": "org.xentry.evidence.0"},
                    )
                    raw = base64.b64decode(str(evidence["bytes_b64"]))
                    return raw.decode("utf-8", "replace"), str(evidence["sha256"])
                except (BrokerError, ValueError, KeyError):
                    return "", ""

            def probe_null() -> None:
                assert client is not None
                if null_nonce in null_output:
                    raise RunnerFailure(
                        "null_actor_observed_nonce",
                        "null actor transcript contained the nonce",
                    )
                if derived_facts is not None and target.poc_context == "local":
                    # The transcript is not the decisive channel here, so
                    # checking only the transcript would leave the control
                    # blind to exactly the failure it exists to catch.
                    serial, _sha = host_serial()
                    if null_nonce in serial:
                        raise RunnerFailure(
                            "null_actor_observed_nonce",
                            "the null actor's nonce reached the serial console "
                            "without any exploit, so a value appearing there "
                            "proves nothing about privilege",
                        )
                    return
                if target.target_id != "php2shell":
                    return
                result = client.call(
                    "http_probe",
                    {
                        "vm_id": target_vm,
                        "network_id": network_id,
                        "port": 8088,
                        "method": "GET",
                        "path": "/xentry-leak.txt",
                        "timeout_s": 10,
                        "max_bytes": 4096,
                    },
                )
                if result["status"] == 200 and null_nonce in str(result.get("body_text", "")):
                    raise RunnerFailure("null_actor_observed_nonce", "null actor produced the nonce")

            self._step(
                conn, job_id, attempt_id, next_seq, "probe_null", None, probe_null
            )
            next_seq += 1

            def actor_params(port: int) -> dict[str, str]:
                params: dict[str, str] = {"nonce_path": target.nonce.path}
                if target.attacker_profile_id:
                    params["target_ip"] = guest_ip
                params["poc_dir"] = target.poc_dir
                if target.target_id == "php2shell":
                    params["zif_offset"] = target.zif_offset
                    params["dtor_offset"] = target.dtor_offset
                if derived_facts is not None:
                    params["entrypoint"] = _entrypoint(derived_facts, experiment)
                    if target.poc_context != "local":
                        # The invocation the PoC documents, when it is not this
                        # harness's three positionals - and the port, for the
                        # same reason: only run-poc-generic declares either.
                        #
                        # poc_args was set unconditionally here, so every LOCAL
                        # PoC reached its last step and died on
                        #     unknown step params: ['poc_args']
                        # because the six run-poc-local-* steps declare only
                        # poc_dir, entrypoint and nonce_path. CVE-2025-32463
                        # passed 14 of 15 steps that way. A local relay has no
                        # use for a documented argv in any case: the argument
                        # it passes is the harness's own command, not one the
                        # advisory wrote.
                        params["poc_args"] = generic.tokens(
                            derived_facts.poc_argv, "argv"
                        )
                        params["port"] = str(port)
                    if derived_facts.privesc_shape in generic.QUOTED_SHAPES:
                        # Both verified against the artifact: the quote locates
                        # the file that holds it, and the span is the only text
                        # the step replaces.
                        assert derived_facts.poc_command is not None
                        params["command"] = derived_facts.poc_command.quote
                        if derived_facts.privesc_shape == "fixed-command":
                            params["span"] = derived_facts.poc_command_exec or ""
                return params

            if target.control_port:
                def control_actor() -> dict[str, Any]:
                    """The same exploit against the same stack, one version on.

                    The null run shows the wrapper does not print the value by
                    itself. It cannot show that the vulnerability is why the
                    real run does: an environment the PoC author built to make
                    the exploit work would pass it too. This run is the
                    difference - same VM, same kernel, same node, same app
                    source, same nonce file, and one package moved to the
                    version the advisory says fixes it.

                    It runs here, before the restore, so the real exploit has
                    not touched this target yet. A control run after a
                    successful compromise would be asking a machine the PoC
                    already owns whether the PoC works.
                    """
                    nonlocal control_nonce, control_output
                    assert client is not None
                    control_nonce, _ = place_phase("control")
                    self._job.secrets.append(control_nonce)
                    result = client.call(
                        "exec",
                        {
                            "vm_id": attacker_vm or target_vm,
                            "step_id": target.invocation_step_id,
                            "params": actor_params(target.control_port),
                            "tty": False,
                            "timeout_s": target.timeouts.poc_s,
                        },
                    )
                    # A non-zero exit is the expected outcome here and is not a
                    # failure: the exploit is supposed to fail against the fixed
                    # build. Only the nonce decides.
                    control_output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
                    return result

                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    next_seq,
                    "control_actor",
                    target.invocation_step_id,
                    control_actor,
                )
                next_seq += 1

                def probe_control() -> None:
                    if control_nonce in control_output:
                        raise RunnerFailure(
                            "control_actor_observed_nonce",
                            "the PoC also succeeded against the fixed version, so "
                            "this run does not show the vulnerability is the reason "
                            "it succeeds",
                        )

                self._step(
                    conn, job_id, attempt_id, next_seq, "probe_control", None, probe_control
                )
                next_seq += 1

            if snapshot_id is not None:
                def restore_step() -> dict[str, Any]:
                    assert client is not None and target_vm is not None
                    return client.call(
                        "restore",
                        {"vm_id": target_vm, "snapshot_id": snapshot_id},
                    )

                self._step(
                    conn, job_id, attempt_id, next_seq, "restore", None, restore_step
                )
                next_seq += 1
            elif target.target_id == "dirtyfrag":
                def fresh_boot_step() -> dict[str, Any]:
                    assert client is not None and target_vm is not None
                    return client.call("reboot", {"vm_id": target_vm, "timeout_s": 300})

                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    next_seq,
                    "fresh_boot",
                    "reboot-dirtyfrag",
                    fresh_boot_step,
                )
                next_seq += 1
                self._step(
                    conn,
                    job_id,
                    attempt_id,
                    next_seq,
                    "readiness_after_boot",
                    target.readiness_step_id,
                    readiness_step,
                )
                next_seq += 1

            capture_result: dict[str, Any] | None = None
            capture_error: BaseException | None = None
            capture_call: dict[str, Any] | None = None
            capture_thread: threading.Thread | None = None

            def start_gitlab_capture() -> None:
                nonlocal capture_thread

                def capture() -> None:
                    nonlocal capture_result, capture_error, capture_call
                    assert network_id is not None
                    capture_client = self.broker_factory()
                    try:
                        capture_result = capture_client.call(
                            "proxy_capture",
                            {
                                "vm_id": target_vm,
                                "network_id": network_id,
                                "target_port": 80,
                                "timeout_s": target.decisive_probe().timeout_s,
                            },
                            job_id=job_id,
                            attempt_id=attempt_id,
                            seq=next_seq,
                        )
                    except BaseException as exc:  # noqa: BLE001 - surfaced at target_probe
                        capture_error = exc
                    finally:
                        capture_call = getattr(capture_client, "last_call", None)

                if target.target_id != "gitlab":
                    return
                capture_thread = threading.Thread(
                    target=capture,
                    name="xentry-gitlab-capture",
                    daemon=True,
                )
                capture_thread.start()
                # The broker needs a moment to open the tap capture before the
                # attacker's SSH session starts sending requests.
                time.sleep(1.0)

            def real_actor() -> dict[str, Any]:
                nonlocal real_nonce, real_nonce_id, attacker_transcript, real_observed
                assert client is not None
                real_nonce, real_nonce_id = place_phase("real")
                self._job.secrets.append(real_nonce)
                if target.target_id == "gitlab":
                    prefix = client.call(
                        "exec",
                        {
                            "vm_id": target_vm,
                            "step_id": "prefix-gitlab-nonce",
                            "params": {"nonce_path": target.nonce.path},
                            "tty": False,
                            "timeout_s": 30,
                        },
                    )
                    if prefix["exit_code"] != 0:
                        raise RunnerFailure(
                            "nonce_place_failed",
                            self._output(prefix) or "prefix failed",
                        )
                # dirtyfrag is local and opens no port at all, so the index is
                # not taken unless a port is what the step will be given.
                params = actor_params(target.target_ports[0] if target.target_ports else 0)
                start_gitlab_capture()
                try:
                    result = client.call(
                        "exec",
                        {
                            "vm_id": attacker_vm or target_vm,
                            "step_id": target.invocation_step_id,
                            "params": params,
                            "tty": False,
                            "timeout_s": target.timeouts.poc_s,
                            "trace": True,
                        },
                    )
                except BrokerError as exc:
                    # The exploit may have taken the guest with it, and that is
                    # a result rather than a broker fault: an exec against a
                    # machine that just panicked fails the same way the broker
                    # failing does. The console already has the panic, and it
                    # is read on the host side.
                    panic = (
                        panic_in(host_serial()[0])
                        if target.evidence_channel.kind == "host_serial"
                        else ""
                    )
                    if not panic:
                        raise
                    raise RunnerFailure(
                        "target_panicked",
                        "the target's kernel died while the PoC ran, so no "
                        f"observation was possible:\n{panic}",
                    ) from exc
                finally:
                    if capture_thread is not None:
                        capture_thread.join(timeout=150)
                raw_output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
                real_observed = real_nonce in raw_output
                attacker_transcript = redact(raw_output, [real_nonce])
                if result["exit_code"] != 0:
                    # Which of the two it is, from what the PoC said it did.
                    reason = (
                        "poc_ignored_target"
                        if POC_DIALLED_LOOPBACK.search(attacker_transcript)
                        else "exploit_failed"
                    )
                    raise RunnerFailure(reason, attacker_transcript[-2000:])
                return result

            def rebuild_poc() -> None:
                """Re-author, re-stage and re-build after a failed attempt."""
                assert client is not None and target_vm is not None
                author_poc()
                archive = copy_poc()
                result = client.call(
                    "exec",
                    {
                        "vm_id": attacker_vm or target_vm,
                        "step_id": target.build_step_id,
                        "params": {
                            "poc_archive": archive,
                            "poc_sha256": poc_archive_sha,
                            "poc_dir": target.poc_dir,
                            "entrypoint": generic.AUTHORED_ENTRYPOINT,
                        },
                        "tty": False,
                        "timeout_s": 600,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure("poc_build_failed", self._output(result))
                if snapshot_id is not None:
                    # Each attempt starts from the frozen machine, or a broken
                    # service from the last one decides the next one's outcome.
                    client.call("restore", {"vm_id": target_vm, "snapshot_id": snapshot_id})

            poc_commands = attempt_dir / "real_actor-commands.txt"
            attempts = _poc_attempts() if experiment else 1
            try:
                for index in range(attempts):
                    poc_attempt = index + 1
                    final = poc_attempt == attempts
                    try:
                        self._step(
                            conn,
                            job_id,
                            attempt_id,
                            next_seq,
                            "real_actor" if final else f"real_actor_try_{poc_attempt}",
                            target.invocation_step_id,
                            real_actor,
                        )
                    except RunnerFailure as exc:
                        if final:
                            raise
                        # Redacted: the failure text can quote the nonce, and
                        # handing that to the author would let the next attempt
                        # print it without reading it from the target.
                        last_failure = redact(str(exc), self._job.secrets)
                        next_seq += 1
                        self._step(
                            conn,
                            job_id,
                            attempt_id,
                            next_seq,
                            f"author_poc_try_{poc_attempt + 1}",
                            None,
                            rebuild_poc,
                        )
                        next_seq += 1
                        continue
                    if real_observed or final:
                        break
                    last_failure = redact(
                        attacker_transcript or "the PoC produced no nonce",
                        self._job.secrets,
                    )
                    next_seq += 1
                    self._step(
                        conn,
                        job_id,
                        attempt_id,
                        next_seq,
                        f"author_poc_try_{poc_attempt + 1}",
                        None,
                        rebuild_poc,
                    )
                    next_seq += 1
            finally:
                poc_vm = attacker_vm or target_vm
                if poc_vm:
                    self._collect_step_trace(
                        client, poc_vm, target.invocation_step_id, poc_commands
                    )
                if poc_commands.is_file():
                    body = poc_commands.read_bytes()
                    record_artifact(
                        conn,
                        job_id=job_id,
                        attempt_id=attempt_id,
                        kind="evidence",
                        path=poc_commands,
                        sha256=hashlib.sha256(body).hexdigest(),
                        size=len(body),
                    )
            next_seq += 1

            def target_probe() -> None:
                nonlocal target_response, target_probe_sha, host_evidence_sha, host_evidence_text
                assert client is not None
                if derived_facts is not None and target.poc_context == "local":
                    # A local job has no attacker to attest from. The decisive
                    # channel is the host's serial log: the nonce is readable
                    # only by root and /dev/ttyS0 is writable only by root, and
                    # readiness asserted both were shut to this actor before
                    # the exploit ran. No fallback to the transcript - the
                    # transcript is the guest's own words, and falling back to
                    # it is what makes dirtyfrag's "decisive" channel optional.
                    serial, serial_sha = host_serial()
                    if real_nonce not in serial:
                        raise RunnerFailure(
                            "nonce_not_observed",
                            "the root-only nonce never reached the host's serial "
                            "log, so nothing outside the guest saw the escalation"
                            # The guest's own words, as DIAGNOSIS and labelled
                            # as such. The decisive channel above is unchanged
                            # and the verdict is still nonce_not_observed: this
                            # is here so a privesc that failed for a dull
                            # reason - a missing compiler, a wrong argv - says
                            # so instead of reading as "the exploit did not
                            # escalate".
                            + (
                                "\nThe PoC printed this (not evidence, the guest "
                                "attesting about itself):\n"
                                + redact(attacker_transcript, self._job.secrets).strip()[
                                    -1200:
                                ]
                                if attacker_transcript.strip()
                                else ""
                            )
                            + (
                                ""
                                if serial
                                else " (the serial log was empty or unreadable)"
                            ),
                        )
                    index = serial.find(real_nonce)
                    host_evidence_text = redact(
                        serial[max(0, index - 4000) : index + 4000], [real_nonce]
                    )
                    host_evidence_sha = serial_sha
                    target_response = host_evidence_text
                    target_probe_sha = serial_sha
                    return
                if derived_facts is not None:
                    # The decisive evidence for a derived target is the
                    # attacker's own transcript: the nonce is a root-owned file
                    # on the target that nothing serves, the control run on the
                    # attacker did not print it (probe_null already failed the
                    # job if it had), and this run must. Nothing on the target
                    # is inspected, which is why the authority below says
                    # guest_attested rather than runner_observed.
                    if not real_observed:
                        # WITH the transcript, which is the only record of what
                        # the exploit actually did. It became evidence on the
                        # success path below and was discarded here, so this
                        # failure said "no nonce" and nothing else - and
                        # CVE-2021-41773 then reached 18 of 19 steps, with
                        # real_actor exiting 0 against an apache2 2.4.49-4 whose
                        # changelog carries no fix, and neither the record nor I
                        # could say whether the server refused the traversal,
                        # answered with an empty body, or served something that
                        # was not the nonce. exploit_failed six lines above
                        # already reports its transcript; this is the same
                        # failure with the evidence left in.
                        shown = redact(attacker_transcript, self._job.secrets).strip()
                        raise RunnerFailure(
                            "nonce_not_observed",
                            "the PoC ran and exited 0, but the nonce is not in "
                            "what it printed. Its output was:\n"
                            + (shown[-1500:] if shown else "(nothing at all)"),
                        )
                    target_response = attacker_transcript
                    target_probe_sha = hashlib.sha256(
                        attacker_transcript.encode()
                    ).hexdigest()
                    return
                if target.target_id == "dirtyfrag":
                    if not real_observed:
                        raise RunnerFailure("nonce_not_observed", "root nonce was not observed")
                    try:
                        evidence = client.call(
                            "read_host_evidence",
                            {
                                "vm_id": target_vm,
                                "channel": "org.xentry.evidence.0",
                            },
                        )
                        serial_bytes = base64.b64decode(str(evidence["bytes_b64"]))
                        serial_text = serial_bytes.decode("utf-8", "replace")
                    except (BrokerError, ValueError, KeyError):
                        serial_text = ""
                    if real_nonce in serial_text:
                        index = serial_text.find(real_nonce)
                        excerpt = serial_text[max(0, index - 4000) : index + 4000]
                        host_evidence_text = redact(excerpt, [real_nonce])
                        host_evidence_sha = str(evidence["sha256"])
                        target_response = host_evidence_text
                        target_probe_sha = host_evidence_sha
                        return
                    target_response = attacker_transcript
                    target_probe_sha = hashlib.sha256(attacker_transcript.encode()).hexdigest()
                    return
                if target.target_id == "gitlab":
                    if capture_thread is not None:
                        capture_thread.join(timeout=150)
                    on_broker_call(capture_call)
                    if capture_error is not None:
                        raise RunnerFailure("proxy_capture_failed", str(capture_error))
                    if capture_result is None:
                        raise RunnerFailure(
                            "proxy_capture_failed", "target capture did not complete"
                        )
                    captured = str(capture_result.get("text", ""))
                    if real_nonce in captured:
                        target_response = redact(captured, [real_nonce])
                        target_probe_sha = str(capture_result["sha256"])
                        return
                    raise RunnerFailure(
                        "nonce_not_observed",
                        "target capture did not contain the nonce",
                    )
                if target.target_id != "php2shell":
                    raise RunnerFailure("probe_failed", "target probe is only implemented for PHP")
                for _ in range(30):
                    result = client.call(
                        "http_probe",
                        {
                            "vm_id": target_vm,
                            "network_id": network_id,
                            "port": 8088,
                            "method": "GET",
                            "path": "/xentry-leak.txt",
                            "timeout_s": 10,
                            "max_bytes": 4096,
                        },
                    )
                    body = str(result.get("body_text", ""))
                    if result["status"] == 200 and real_nonce in body:
                        target_response = redact(body, [real_nonce])
                        target_probe_sha = str(result["body_sha256"])
                        return
                    time.sleep(2)
                raise RunnerFailure("nonce_not_observed", "target response did not contain the nonce")

            self._step(
                conn,
                job_id,
                attempt_id,
                next_seq,
                "target_probe",
                None,
                target_probe,
            )

            # Destroy before validation, as required by the contract. A hold
            # inserts a human gate ahead of the teardown without reordering it.
            if self.hold_s != 0:
                self._hold(
                    conn,
                    job_id,
                    attempt_id,
                    attempt_dir,
                    {
                        "target_vm": target_vm,
                        "attacker_vm": attacker_vm,
                        "network_id": network_id,
                        "target_ip": guest_ip,
                        "attacker_ip": attacker_ip,
                        # The broker generates a per-job keypair here. virsh
                        # console cannot reach these domains: their serial is a
                        # TCP char device, not a PTY, and the broker already
                        # holds that socket to collect serial evidence.
                        "keys_dir": str(attempt_dir.parent / "keys"),
                        # There is no verdict yet - validation runs after the
                        # teardown below - but the runner's half of it is
                        # already settled, and reaching this line is the proof:
                        # a control phase that saw the nonce fails at
                        # null_actor, and a probe that did not see it fails at
                        # target_probe. Both digests are recorded so a reader
                        # can check the match without being shown the nonce.
                        "runner_nonce_observed": True,
                        "null_actor_observed_nonce": False,
                        "nonce_sha256": str(_nonce_sha(conn, attempt_id, "real")),
                        "probe_sha256": target_probe_sha,
                    },
                )
            self._destroy(client, attacker_vm, target_vm, network_id)
            destroyed = True
            cleanup_ok = True
            set_cleanup_state(conn, job_id, "done")
            self._validate_and_project(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                target=target,
                target_vm=target_vm,
                attacker_vm=attacker_vm,
                network_id=network_id or "",
                target_id=target.target_id,
                authority=(
                    # A derived target is attested by the attacker, exactly as
                    # dirtyfrag's root shell is attested by the guest: the
                    # runner read a transcript, it did not observe the target.
                    "guest_attested+llm_assessed"
                    if target.target_id == "dirtyfrag" or derived_facts is not None
                    else "runner_observed+llm_assessed"
                ),
                nonce_id=real_nonce_id,
                nonce_sha=str(_nonce_sha(conn, attempt_id, "real")),
                null_observed=False,
                target_response=target_response,
                target_probe_sha=target_probe_sha,
                host_evidence_sha=host_evidence_sha,
                host_evidence_text=host_evidence_text,
                attacker_transcript=attacker_transcript,
                poc_text=poc_artifact.text,
                setup_text=setup_script_path(target).read_text(encoding="utf-8"),
            )
        except RunnerFailure as exc:
            failure = exc
        except BrokerError as exc:
            failure = RunnerFailure(exc.code, str(exc))
        except (FetchError, ExtractorError, ValidatorError, PocGenError) as exc:
            failure = RunnerFailure(getattr(exc, "code", "harness_error"), str(exc))
        except Exception as exc:  # noqa: BLE001 - last-resort runner failure
            failure = RunnerFailure("harness_error", str(exc))
        finally:
            transcript.set_sink(None)
            if (
                client is not None
                and not destroyed
                and not keep_running
                and (attacker_vm or target_vm or network_id)
            ):
                if failure is not None and self.keep_on_failure:
                    # Debug-only: leave the VMs for inspection. The operator must
                    # run the cleanup CLI or destroy them manually.
                    pass
                else:
                    try:
                        self._destroy(client, attacker_vm, target_vm, network_id)
                        set_cleanup_state(conn, job_id, "done")
                        cleanup_ok = True
                    except Exception:  # noqa: BLE001 - cleanup failure is recorded
                        set_cleanup_state(conn, job_id, "failed")
                        cleanup_ok = False
            if (
                failure is not None
                and cleanup_ok
                and not keep_running
                and not (self.keep_on_failure and (attacker_vm or target_vm or network_id))
            ):
                set_cleanup_state(conn, job_id, "done")
            if failure is not None:
                reason = failure.code
                if not cleanup_ok:
                    reason = "security_cleanup_failed"
                # A failure raised BETWEEN steps had nowhere to be written. The
                # per-step handler records detail on its own row; this one kept
                # str(exc) in a local and dropped it. Job 9cca773bf56c failed
                # after stage_approved with reason_code harness_error, no failed
                # step, nothing in the journal - uvicorn never sees the
                # exception either - and so no way at all to learn what it was.
                # One synthetic row puts it where a reader already looks.
                # Not for a code whose message only restates it: "cancelled"
                # and "deadline_exceeded" say everything in the reason_code, and
                # a row per cancelled job is noise in the table this is meant to
                # make readable.
                if reason not in SELF_EVIDENT and not conn.execute(
                    "SELECT 1 FROM job_steps WHERE attempt_id=? AND state='failed'",
                    (attempt_id,),
                ).fetchone():
                    finish_step(
                        conn,
                        begin_step(
                            conn, job_id=job_id, attempt_id=attempt_id,
                            seq=LAST_SEQ, name="runner",
                        ),
                        state="failed",
                        reason_code=reason,
                        detail=self._detail(failure),
                    )
                record_outcome(
                    conn,
                    job_id=job_id,
                    attempt_id=attempt_id,
                    outcome="cancelled" if failure.code == "cancelled" else "failed",
                    verdict="not_run",
                    authority="runner_observed",
                    reason_code=reason,
                )
                conn.execute(
                    "UPDATE attempts SET finished_at=?, failure_code=? WHERE id=?",
                    (now(), reason, attempt_id),
                )
                conn.commit()
            self._job.deadline_at = None
            conn.close()

    def _validate_and_project(
        self,
        conn: sqlite3.Connection,
        *,
        job_id: str,
        attempt_id: str,
        target: TargetInstance,
        target_vm: str,
        attacker_vm: str | None,
        network_id: str,
        target_id: str,
        authority: str,
        nonce_id: str,
        nonce_sha: str,
        null_observed: bool,
        target_response: str,
        target_probe_sha: str,
        host_evidence_sha: str,
        host_evidence_text: str,
        attacker_transcript: str,
        poc_text: str,
        setup_text: str,
    ) -> None:
        facts = RunnerFacts(
            nonce_observed=True,
            nonce_id=nonce_id,
            nonce_sha256=nonce_sha,
            null_actor_observed_nonce=null_observed,
            version_match=True,
            precondition_ok=True,
            vm_ids=[vm for vm in (target_vm, attacker_vm) if vm],
            network_id=network_id,
            probe_evidence_sha256=target_probe_sha,
            host_evidence_sha256=host_evidence_sha or None,
        )
        narrative = NarrativeBundle(
            poc_artifact=poc_text,
            setup_script=setup_text,
            attacker_transcript=attacker_transcript,
            target_response_excerpt=target_response,
            host_evidence_excerpt=host_evidence_text,
        )
        try:
            verdict, model, prompt_hash = self.validate_fn(facts, narrative)
        except ValidatorError:
            record_outcome(
                conn,
                job_id=job_id,
                attempt_id=attempt_id,
                outcome="completed",
                verdict="inconclusive",
                authority="runner_observed",
                reason_code="validator_error",
            )
            conn.execute(
                "UPDATE attempts SET finished_at=? WHERE id=?",
                (now(), attempt_id),
            )
            conn.commit()
            return
        record_validation(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            target_id=target_id,
            authority=authority,
            validator_model=model,
            prompt_hash=prompt_hash,
            verdict=verdict.verdict,
            reason_code=verdict.reason_code,
            nonce_id=nonce_id,
            runner_nonce_observed=True,
            null_actor_observed_nonce=null_observed,
            evidence={
                "probe_evidence_sha256": target_probe_sha,
                "host_evidence_sha256": host_evidence_sha or None,
                "nonce_sha256": nonce_sha,
                "vm_ids": facts.vm_ids,
                "network_id": network_id,
            },
        )
        set_final_attempt(conn, job_id, attempt_id)
        record_outcome(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            outcome="completed",
            verdict=verdict.verdict,
            authority=authority,
            reason_code=verdict.reason_code,
        )
        conn.execute("UPDATE attempts SET finished_at=? WHERE id=?", (now(), attempt_id))
        conn.commit()

    def _hold(
        self,
        conn: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        attempt_dir: Path,
        details: dict[str, Any],
    ) -> None:
        """Keep the VMs up until a person releases them, or the TTL expires.

        hold_s < 0 holds with no deadline: the VMs stay up until someone
        releases or cancels the job. hold_s > 0 adds a deadline as a backstop.
        The order stays hold -> destroy -> validate either way, so the verdict
        is still produced from recorded evidence after teardown.

        This blocks the single runner thread, so no other job starts while a
        job is held. With no deadline that is indefinite, which is the point:
        nothing reclaims the host but a person.
        """
        started = time.monotonic()
        forever = self.hold_s < 0
        deadline = started + (0.0 if forever else self.hold_s)
        # held_at plus hold_s is the expiry; the page counts it down so the
        # runner needs no clock beyond the one jobstore already provides.
        payload = {**details, "hold_s": self.hold_s, "held_at": now()}
        path = attempt_dir / "held-vms.json"
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        path.write_bytes(body)
        record_artifact(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            kind="held_vms",
            path=path,
            sha256=hashlib.sha256(body).hexdigest(),
            size=len(body),
        )
        while forever or time.monotonic() < deadline:
            if is_release_requested(conn, job_id):
                break
            # Cancelling is the second way out, so a held job is never stuck.
            if is_cancel_requested(conn, job_id):
                break
            time.sleep(2.0 if forever else min(2.0, max(0.05, deadline - time.monotonic())))
        # Waiting on a person is not the job's compute budget.
        waited = time.monotonic() - started
        if self._job.deadline_at is not None:
            self._job.deadline_at += waited

    @staticmethod
    def _destroy(
        client: BrokerClient,
        attacker_vm: str | None,
        target_vm: str | None,
        network_id: str | None,
    ) -> None:
        errors: list[Exception] = []
        for vm in (attacker_vm, target_vm):
            if not vm:
                continue
            try:
                client.call("destroy_vm", {"vm_id": vm})
            except Exception as exc:  # noqa: BLE001 - continue the teardown sweep
                errors.append(exc)
        if network_id:
            try:
                client.call("destroy_network", {"network_id": network_id})
            except Exception as exc:  # noqa: BLE001 - continue the teardown sweep
                errors.append(exc)
        if errors:
            raise errors[0]

    def _collect_step_trace(self, client: Any, vm_id: str, step_id: str, sink: Path) -> None:
        # Fetched through the attributed client, so this read is sequenced and
        # recorded like every other broker call. Best effort: a missing trace
        # must never turn a passing step into a failure, nor mask the step's
        # own error on the way out.
        try:
            result = client.call(
                "copy_out",
                {"vm_id": vm_id, "guest_path": f"{GUEST_TRACE_REL}/{step_id}.trace"},
            )
            raw = Path(str(result["path"])).read_text(encoding="utf-8", errors="replace")
            sink.write_text(redact(raw, self._job.secrets), encoding="utf-8")
        except Exception:  # noqa: BLE001 - never fatal
            return

    def _step(
        self,
        conn: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        seq: int,
        name: str,
        step_id: str | None,
        fn: Callable[[], Any],
    ) -> Any:
        if self._job.deadline_at is not None and time.monotonic() > self._job.deadline_at:
            raise RunnerFailure("deadline_exceeded", "job deadline exceeded")
        if is_cancel_requested(conn, job_id):
            raise RunnerFailure("cancelled", "job cancelled")
        row = begin_step(
            conn,
            job_id=job_id,
            attempt_id=attempt_id,
            seq=seq,
            name=name,
            step_id=step_id,
        )
        try:
            result = fn()
            finish_step(conn, row, state="passed")
            return result
        except RunnerFailure as exc:
            finish_step(conn, row, state="failed", reason_code=exc.code, detail=self._detail(exc))
            raise
        except BrokerError as exc:
            finish_step(conn, row, state="failed", reason_code=exc.code, detail=self._detail(exc))
            raise RunnerFailure(exc.code, str(exc)) from exc
        except (FetchError, ExtractorError, ValidatorError, PocGenError) as exc:
            code = getattr(exc, "code", "harness_error")
            finish_step(conn, row, state="failed", reason_code=code, detail=self._detail(exc))
            raise RunnerFailure(code, str(exc)) from exc
        except Exception as exc:
            finish_step(
                conn, row, state="failed", reason_code="harness_error", detail=self._detail(exc)
            )
            raise RunnerFailure("harness_error", str(exc)) from exc

    @staticmethod
    def _output(result: dict[str, Any]) -> str:
        """The tail of stdout AND stderr, because either alone has lost a cause.

        `stderr or stdout` picked the wrong half: apt puts the diagnosis on
        stdout - "dpkg: error processing package ..." - and only the summary on
        stderr - "E: Sub-process /usr/bin/dpkg returned an error code (1)". A
        wordpress provision failed with a 56-character detail that named
        neither the package nor the reason. The step scripts write their own
        messages to stderr, so that half has to stay too.
        """
        # The tail is also the wrong shape for apt. The wordpress provision
        # named its package only because the error happened to be last;
        # dpkg's REASON - "trying to overwrite ..., which is also in package
        # ..." - sat above 95 lines of "Unpacking ..." and fell off the end.
        # Dropping apt's own progress chatter keeps the error AND the
        # continuation line under it, which a grep for "error" would have cut
        # in half.
        tail = []
        for stream in ("stdout", "stderr"):
            kept = [
                line
                for line in (result.get(stream) or "").splitlines()
                if not PROGRESS.match(line)
            ]
            tail.append("\n".join(kept)[-1500:])
        return "\n".join(part for part in tail if part.strip())

    def _detail(self, exc: BaseException) -> str:
        # Capped: a step's stderr can be a whole build log, and this is read in
        # a table row, not downloaded.
        return redact(str(exc), self._job.secrets)[-4000:]

def _artifact_sha(artifact_id: str) -> str:
    from xentry.targets import artifact_hash

    return artifact_hash(artifact_id)


def _guest_artifact(artifact_id: str) -> str:
    """Where copy_in puts an artifact inside the guest."""
    return f"{GUEST_ARTIFACT_DIR}/{artifact_id}.tar.gz"


def _approved_names(approved: list[Any]) -> list[tuple[Any, str]]:
    """Each approved file with the name it takes inside the guest.

    Derived from the URL it came from rather than stored, because the name is
    not evidence - the digest is - and deriving it keeps one rule for what a
    guest-side filename may be.
    """
    return [
        (item, generic.artifact_name(Path(urlsplit(item.final_url).path).name))
        for item in approved
    ]


def _guest_artifact_file(name: str) -> str:
    """The same, for a file whose own name carries its type."""
    return f"{GUEST_ARTIFACT_DIR}/{name}"


def _nonce_sha(conn: sqlite3.Connection, attempt_id: str, phase: str) -> str:
    row = conn.execute(
        "SELECT sha256 FROM nonces WHERE attempt_id=? AND phase=?", (attempt_id, phase)
    ).fetchone()
    return str(row["sha256"]) if row is not None else ""
