"""Ordered job runner for V1 remote targets."""

from __future__ import annotations

import base64
import hashlib
import queue
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from xentry.broker import BrokerClient, BrokerError
from xentry.db import connect
from xentry.extract import ArtifactText, ExtractorError, extract
from xentry.fetch import FetchError, bundle_sha256, fetch
from xentry.jobstore import (
    begin_step,
    create_job,
    finish_step,
    is_cancel_requested,
    now,
    record_artifact,
    record_broker_call,
    record_nonce,
    record_outcome,
    record_validation,
    set_cleanup_state,
    set_final_attempt,
    set_plan,
)
from xentry.security import new_nonce, redact
from xentry.targets import TargetInstance, by_cve, by_poc_url, setup_script_path
from xentry.validator import (
    NarrativeBundle,
    RunnerFacts,
    ValidatorError,
    assess,
)


class RunnerFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


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


class JobRunner:
    def __init__(
        self,
        *,
        db_path: Path,
        data_dir: Path,
        broker_socket: Path,
        extract_fn: Callable[[list[ArtifactText]], Any] = extract,
        validate_fn: Callable[[RunnerFacts, NarrativeBundle], Any] = assess,
        fetch_fn: Callable[[str], Any] = fetch,
        broker_factory: Callable[[], BrokerClient] | None = None,
        keep_on_failure: bool = False,
        job_deadline_s: float | None = 7200.0,
        target_deadlines: dict[str, float] | None = None,
    ) -> None:
        self.db_path = db_path
        self.data_dir = data_dir
        self.broker_socket = broker_socket
        self.extract_fn = extract_fn
        self.validate_fn = validate_fn
        self.fetch_fn = fetch_fn
        self.keep_on_failure = keep_on_failure
        self.job_deadline_s = job_deadline_s
        self.target_deadlines = target_deadlines or {}
        self._deadline_at: float | None = None
        self._job_started_at = 0.0
        self.broker_factory = broker_factory or (
            lambda: BrokerClient(self.broker_socket, timeout=2400)
        )
        self._queue: queue.Queue[tuple[str, str, str, str, str | None] | None] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._stopped = threading.Event()

    def start(self) -> None:
        if self._worker is None:
            self.recover_interrupted()
            self._worker = threading.Thread(target=self._work, name="xentry-runner", daemon=True)
            self._worker.start()

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
            )
        finally:
            conn.close()
        self._queue.put((job_id, cve_url, poc_url, attempt_id, bundle_sha256))
        return job_id

    def _work(self) -> None:
        while not self._stopped.is_set():
            item = self._queue.get()
            if item is None:
                return
            job_id, cve_url, poc_url, attempt_id, expected_bundle = item
            try:
                self.run_job(job_id, cve_url, poc_url, attempt_id, expected_bundle)
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
    ) -> None:
        conn = connect(self.db_path)
        attempt_dir = self.data_dir / "jobs" / job_id / "attempt-0"
        self._job_started_at = time.monotonic()
        self._deadline_at = (
            self._job_started_at + self.job_deadline_s
            if self.job_deadline_s is not None
            else None
        )
        target: TargetInstance | None = None
        target_vm: str | None = None
        attacker_vm: str | None = None
        network_id: str | None = None
        client: Any = None
        cleanup_ok = True
        destroyed = False
        failure: RunnerFailure | None = None
        cve_id: str | None = None
        null_nonce = ""
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
                fetched_cve = self.fetch_fn(cve_url)
                target_hint = by_poc_url(poc_url)
                if target_hint is not None:
                    repo = target_hint.poc.repository.removeprefix("https://github.com/")
                    raw_url = (
                        f"https://raw.githubusercontent.com/{repo}/"
                        f"{target_hint.poc.commit}/README.md"
                    )
                    fetched_poc = self.fetch_fn(raw_url)
                else:
                    fetched_poc = self.fetch_fn(poc_url)
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
                return (
                    ArtifactText("cve", fetched_cve.sha256, fetched_cve.text),
                    ArtifactText("poc", fetched_poc.sha256, fetched_poc.text),
                    bundle,
                )

            cve_artifact, poc_artifact, bundle = self._step(
                conn, job_id, attempt_id, 1, "fetch", None, fetch_step
            )
            if expected_bundle and bundle != expected_bundle:
                raise RunnerFailure("source_unavailable", "source bundle changed since check")

            def extract_step() -> tuple[TargetInstance, str]:
                nonlocal target, cve_id
                facts = self.extract_fn([cve_artifact, poc_artifact])
                target = by_cve(facts.cve_id)
                if target is None:
                    raise RunnerFailure("unsupported_target", f"unsupported CVE: {facts.cve_id}")
                cve_id = facts.cve_id
                return target, facts.cve_id

            def plan_step() -> TargetInstance:
                assert target is not None and cve_id is not None
                normalized = poc_url.rstrip("/").removesuffix(".git")
                expected = target.poc.repository.rstrip("/").removesuffix(".git")
                if normalized != expected:
                    raise RunnerFailure("unsupported_poc", "PoC URL does not match the target pin")
                set_plan(
                    conn,
                    job_id,
                    cve_id=cve_id,
                    target_id=target.target_id,
                    bundle_sha256=bundle,
                )
                return target

            # Extract and plan are separate steps so failures are attributable.
            target, cve_id = self._step(conn, job_id, attempt_id, 2, "extract", None, extract_step)
            plan_target = self._step(conn, job_id, attempt_id, 3, "plan", None, plan_step)
            target = plan_target
            target_deadline = self.target_deadlines.get(target.target_id)
            if target_deadline is not None:
                self._deadline_at = self._job_started_at + target_deadline

            def create_network() -> dict[str, Any]:
                nonlocal network_id
                assert client is not None
                result = client.call(
                    "create_network",
                    {"job_id": job_id, "profile_id": target.network_profile_id},
                )
                network_id = str(result["network_id"])
                return result

            network = self._step(conn, job_id, attempt_id, 4, "create_network", None, create_network)

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

            def setup_params() -> dict[str, str]:
                assert target is not None
                mirror_url = str(network["mirror_url"])
                if target.target_id == "php2shell":
                    return {
                        "mirror_url": mirror_url,
                        "php_artifact_id": "php-8.4.26-src",
                        "php_sha256": _artifact_sha("php-8.4.26-src"),
                    }
                if target.target_id == "gitlab":
                    return {
                        "mirror_url": mirror_url,
                        "gitlab_artifact_id": "gitlab-19.2.5-deb",
                        "gitlab_sha256": _artifact_sha("gitlab-19.2.5-deb"),
                    }
                return {
                    "mirror_url": mirror_url,
                    "kernel_artifact_id": "kernel-6.17.0-23",
                    "kernel_sha256": _artifact_sha("kernel-6.17.0-23"),
                    "kernel_modules_artifact_id": "kernel-modules-6.17.0-23",
                    "kernel_modules_sha256": _artifact_sha("kernel-modules-6.17.0-23"),
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
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure(
                        "provision_failed",
                        (result.get("stderr") or result.get("stdout") or "setup failed")[-2000:],
                    )
                return result

            self._step(conn, job_id, attempt_id, 6, "provision", target.setup_step_id, setup_step)

            rebooted = False
            if target.target_id == "dirtyfrag":
                def reboot_step() -> dict[str, Any]:
                    assert client is not None and target_vm is not None
                    return client.call("reboot", {"vm_id": target_vm, "timeout_s": 300})

                self._step(conn, job_id, attempt_id, 7, "reboot", "reboot-dirtyfrag", reboot_step)
                rebooted = True

            def readiness_step() -> dict[str, Any]:
                assert client is not None and target is not None and target_vm is not None
                result = client.call(
                    "exec",
                    {
                        "vm_id": target_vm,
                        "step_id": target.readiness_step_id,
                        "params": {},
                        "tty": False,
                        "timeout_s": target.timeouts.readiness_s,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure(
                        "target_unhealthy",
                        (result.get("stderr") or result.get("stdout") or "readiness failed")[-2000:],
                    )
                return result

            self._step(
                conn,
                job_id,
                attempt_id,
                8 if rebooted else 7,
                "readiness",
                target.readiness_step_id,
                readiness_step,
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
                            "image_id": "ubuntu-24.04-attacker",
                        },
                    )
                    attacker_vm = str(result["vm_id"])
                    return result

                self._step(
                    conn, job_id, attempt_id, 8, "create_attacker", None, create_attacker
                )

            assert target is not None and target_vm is not None
            guest_ip = str(target_info["guest_ip"])

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
                conn, job_id, attempt_id, 9, "copy_poc", None, copy_poc
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
                            "poc_sha256": target.poc.sha256,
                            "poc_dir": target.poc_dir,
                        },
                        "tty": False,
                        "timeout_s": 600,
                    },
                )
                if result["exit_code"] != 0:
                    raise RunnerFailure("poc_build_failed", result.get("stderr", "")[-2000:])
                return result

            self._step(
                conn,
                job_id,
                attempt_id,
                10,
                "build_poc",
                target.build_step_id,
                build_step,
            )

            next_seq = 11
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
                )
                return nonce, nonce_id

            def null_actor() -> dict[str, Any]:
                nonlocal null_nonce, null_output
                assert client is not None
                null_nonce, _ = place_phase("null")
                params = {"target_ip": guest_ip} if target.attacker_profile_id else {}
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

            def probe_null() -> None:
                assert client is not None
                if null_nonce in null_output:
                    raise RunnerFailure(
                        "null_actor_observed_nonce",
                        "null actor transcript contained the nonce",
                    )
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
                            (prefix.get("stderr") or prefix.get("stdout") or "prefix failed")[-2000:],
                        )
                params: dict[str, str] = {"nonce_path": target.nonce.path}
                if target.attacker_profile_id:
                    params["target_ip"] = guest_ip
                params["poc_dir"] = target.poc_dir
                if target.target_id == "php2shell":
                    params["zif_offset"] = target.zif_offset
                    params["dtor_offset"] = target.dtor_offset
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
                        },
                    )
                finally:
                    if capture_thread is not None:
                        capture_thread.join(timeout=150)
                raw_output = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
                real_observed = real_nonce in raw_output
                attacker_transcript = redact(raw_output, [real_nonce])
                if result["exit_code"] != 0:
                    raise RunnerFailure("exploit_failed", attacker_transcript[-2000:])
                return result

            self._step(
                conn,
                job_id,
                attempt_id,
                next_seq,
                "real_actor",
                target.invocation_step_id,
                real_actor,
            )
            next_seq += 1

            def target_probe() -> None:
                nonlocal target_response, target_probe_sha, host_evidence_sha, host_evidence_text
                assert client is not None
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

            # Destroy before validation, as required by the contract.
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
                    "guest_attested+llm_assessed"
                    if target.target_id == "dirtyfrag"
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
        except (FetchError, ExtractorError, ValidatorError) as exc:
            failure = RunnerFailure(getattr(exc, "code", "harness_error"), str(exc))
        except Exception as exc:  # noqa: BLE001 - last-resort runner failure
            failure = RunnerFailure("harness_error", str(exc))
        finally:
            if client is not None and not destroyed and (attacker_vm or target_vm or network_id):
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
                and not (self.keep_on_failure and (attacker_vm or target_vm or network_id))
            ):
                set_cleanup_state(conn, job_id, "done")
            if failure is not None:
                reason = failure.code
                if not cleanup_ok:
                    reason = "security_cleanup_failed"
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
            self._deadline_at = None
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
        if self._deadline_at is not None and time.monotonic() > self._deadline_at:
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
            finish_step(conn, row, state="failed", reason_code=exc.code)
            raise
        except BrokerError as exc:
            finish_step(conn, row, state="failed", reason_code=exc.code)
            raise RunnerFailure(exc.code, str(exc)) from exc
        except (FetchError, ExtractorError, ValidatorError) as exc:
            code = getattr(exc, "code", "harness_error")
            finish_step(conn, row, state="failed", reason_code=code)
            raise RunnerFailure(code, str(exc)) from exc
        except Exception as exc:
            finish_step(conn, row, state="failed", reason_code="harness_error")
            raise RunnerFailure("harness_error", str(exc)) from exc

def _artifact_sha(artifact_id: str) -> str:
    from xentry.targets import artifact_hash

    return artifact_hash(artifact_id)


def _nonce_sha(conn: sqlite3.Connection, attempt_id: str, phase: str) -> str:
    row = conn.execute(
        "SELECT sha256 FROM nonces WHERE attempt_id=? AND phase=?", (attempt_id, phase)
    ).fetchone()
    return str(row["sha256"]) if row is not None else ""
