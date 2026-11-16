"""Typed V1 target instances."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from xentry.models import (
    EvidenceChannel,
    NonceSpec,
    NullActor,
    PocPin,
    ProbeStep,
    Resources,
    RetryPolicy,
    Timeouts,
)

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "config" / "artifacts.yaml"
STEPS = ROOT / "targets" / "steps.yaml"


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _artifact_sha(artifact_id: str) -> str:
    artifacts = _load_yaml(CATALOG).get("artifacts") or {}
    artifact = artifacts.get(artifact_id)
    if not isinstance(artifact, dict) or not artifact.get("sha256"):
        raise RuntimeError(f"artifact is not pinned: {artifact_id}")
    return str(artifact["sha256"])


def resolved_artifacts() -> set[str]:
    """Artifact ids the catalog pins with a real digest."""
    artifacts = _load_yaml(CATALOG).get("artifacts") or {}
    return {
        name
        for name, entry in artifacts.items()
        if isinstance(entry, dict) and entry.get("status") == "resolved"
    }


def _step_sha(step_id: str) -> str:
    steps = _load_yaml(STEPS).get("steps") or {}
    step = steps.get(step_id)
    if not isinstance(step, dict) or not step.get("sha256"):
        raise RuntimeError(f"step is not pinned: {step_id}")
    return str(step["sha256"])


@dataclass(frozen=True)
class TargetInstance:
    target_id: str
    cve_ids: tuple[str, ...]
    poc_context: str
    base_image_id: str
    kernel_artifact_id: str | None
    resources: Resources
    attacker_profile_id: str | None
    network_profile_id: str
    actor_user: str
    setup_step_id: str
    setup_script: str
    readiness_step_id: str
    build_step_id: str
    invocation_step_id: str
    null_step_id: str
    probe_step_id: str
    setup_sha256: str
    expected_version: str
    poc: PocPin
    probes: tuple[ProbeStep, ...]
    nonce: NonceSpec
    null_actor: NullActor
    evidence_channel: EvidenceChannel
    target_ports: tuple[int, ...]
    poc_archive_guest_path: str
    poc_dir: str
    what_proves: tuple[str, ...]
    what_does_not_prove: tuple[str, ...]
    # Set only by an ecosystem target: the one package whose version the
    # fixed-version control run moves. Empty when the advisory's product is not
    # a dependency this lab declares, and the job then claims less.
    subject_package: str = ""
    # Set with subject_package: the version the advisory says fixes the flaw. A
    # second build of the same app, with that one dependency overridden, is
    # installed beside the first and served on control_port. The control run
    # points the same PoC at that port and requires it to fail, which is what
    # separates "the exploit works here" from "the vulnerability is why".
    fixed_version: str = ""
    control_port: int = 0
    zif_offset: str = "0x466220"
    dtor_offset: str = "0x645870"
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    timeouts: Timeouts = field(
        default_factory=lambda: Timeouts(
            boot_s=120,
            provision_s=1800,
            readiness_s=300,
            poc_s=900,
            validate_s=120,
        )
    )

    def decisive_probe(self) -> ProbeStep:
        decisive = [probe for probe in self.probes if probe.decisive]
        if len(decisive) != 1:
            raise RuntimeError(f"{self.target_id} has {len(decisive)} decisive probes")
        return decisive[0]


def _build_targets() -> dict[str, TargetInstance]:
    php = TargetInstance(
        target_id="php2shell",
        cve_ids=("CVE-2026-109618",),
        poc_context="remote",
        base_image_id="ubuntu-24.04-target",
        kernel_artifact_id=None,
        resources=Resources(vcpu=2, memory_mb=4096, disk_gb=25),
        attacker_profile_id="attacker-remote",
        network_profile_id="isolated",
        actor_user="xentry-guest",
        setup_step_id="setup-php",
        setup_script="php2shell/setup.sh",
        readiness_step_id="readiness-php",
        build_step_id="build-poc-php",
        invocation_step_id="run-poc-php",
        null_step_id="null-php",
        probe_step_id="probe-php-http",
        setup_sha256=_step_sha("setup-php"),
        expected_version="8.4.26",
        poc=PocPin(
            artifact_id="poc-php2shell",
            repository="https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit",
            commit="167085410a9342fafbd1bd64f5006920dbc83b8e",
            files=["exploit.py"],
            sha256=_artifact_sha("poc-php2shell"),
            build_step_id="build-poc-php",
            invocation_step_id="run-poc-php",
        ),
        probes=(
            ProbeStep(
                step_id="probe-php-http",
                kind="http_get",
                decisive=True,
                params={"port": 8088, "path": "/xentry-leak.txt"},
                timeout_s=10,
            ),
        ),
        nonce=NonceSpec(path="/var/lib/xentry/nonce", owner="www-data", mode=0o640),
        null_actor=NullActor(location="attacker", step_id="null-php"),
        evidence_channel=EvidenceChannel(kind="target_probe", channel="http"),
        target_ports=(8088,),
        poc_archive_guest_path="/var/lib/xentry/artifacts/poc-php2shell.tar.gz",
        poc_dir="/home/xentry-guest/xentry-poc",
        what_proves=(
            "A target-side nonce is readable by the PHP web user after the attacker runs the pinned PoC.",
        ),
        what_does_not_prove=(
            "Other PHP builds or SAPIs are unaffected; this is a lab reproduction, not a risk assessment.",
        ),
    )
    gitlab = TargetInstance(
        target_id="gitlab",
        cve_ids=("CVE-2026-85706",),
        poc_context="remote",
        base_image_id="ubuntu-24.04-target",
        kernel_artifact_id=None,
        resources=Resources(vcpu=4, memory_mb=8192, disk_gb=50),
        attacker_profile_id="attacker-remote",
        network_profile_id="isolated",
        actor_user="xentry-guest",
        setup_step_id="setup-gitlab",
        setup_script="gitlab/setup.sh",
        readiness_step_id="readiness-gitlab",
        build_step_id="build-poc-gitlab",
        invocation_step_id="run-poc-gitlab",
        null_step_id="null-gitlab",
        probe_step_id="probe-gitlab-response",
        setup_sha256=_step_sha("setup-gitlab"),
        expected_version="19.2.5",
        poc=PocPin(
            artifact_id="poc-gitlab",
            repository="https://github.com/gagaltotal/CVE-2026-85706-gitlab-poc",
            commit="e275edcdd00dfd921c4b646f4a568a3a092a29a1",
            files=["CVE-2026-85706.go"],
            sha256=_artifact_sha("poc-gitlab"),
            build_step_id="build-poc-gitlab",
            invocation_step_id="run-poc-gitlab",
        ),
        probes=(
            ProbeStep(
                step_id="probe-gitlab-response",
                kind="proxy_capture",
                decisive=True,
                params={"ports": [80, 443]},
                timeout_s=30,
            ),
        ),
        nonce=NonceSpec(path="/var/opt/gitlab/xentry-nonce", owner="git", mode=0o640),
        null_actor=NullActor(location="attacker", step_id="null-gitlab"),
        evidence_channel=EvidenceChannel(kind="proxy_capture", channel="tcp"),
        target_ports=(80, 443),
        poc_archive_guest_path="/var/lib/xentry/artifacts/poc-gitlab.tar.gz",
        poc_dir="/home/xentry-guest/xentry-poc",
        what_proves=(
            "The target-side proxy capture contains the nonce after the attacker runs the pinned GitLab PoC.",
        ),
        what_does_not_prove=(
            "Other GitLab versions or paths are unaffected; the attacker transcript is not decisive.",
        ),
    )
    dirtyfrag = TargetInstance(
        target_id="dirtyfrag",
        cve_ids=("CVE-2026-43500", "CVE-2026-43284"),
        poc_context="local",
        base_image_id="ubuntu-24.04-dirtyfrag",
        kernel_artifact_id="kernel-6.17.0-23",
        resources=Resources(vcpu=2, memory_mb=2048, disk_gb=25),
        attacker_profile_id=None,
        network_profile_id="isolated",
        actor_user="xentry-guest",
        setup_step_id="setup-dirtyfrag",
        setup_script="dirtyfrag/setup.sh",
        readiness_step_id="readiness-dirtyfrag",
        build_step_id="build-poc-dirtyfrag",
        invocation_step_id="run-poc-dirtyfrag",
        null_step_id="null-dirtyfrag",
        probe_step_id="probe-dirtyfrag-pty",
        setup_sha256=_step_sha("setup-dirtyfrag"),
        expected_version="6.17.0-23-generic",
        poc=PocPin(
            artifact_id="poc-dirtyfrag",
            repository="https://github.com/V4bel/dirtyfrag",
            commit="aab16fcada27142dd8ce8704906cf6736cf213b8",
            files=["exp.c"],
            sha256=_artifact_sha("poc-dirtyfrag"),
            build_step_id="build-poc-dirtyfrag",
            invocation_step_id="run-poc-dirtyfrag",
        ),
        probes=(
            ProbeStep(
                step_id="probe-dirtyfrag-pty",
                kind="pty_session",
                decisive=True,
                params={"channel": "org.xentry.evidence.0"},
                timeout_s=60,
            ),
        ),
        nonce=NonceSpec(path="/root/xentry-nonce", owner="root", mode=0o600),
        null_actor=NullActor(location="target", step_id="null-dirtyfrag"),
        evidence_channel=EvidenceChannel(
            kind="host_serial",
            channel="org.xentry.evidence.0",
        ),
        target_ports=(),
        poc_archive_guest_path="/var/lib/xentry/artifacts/poc-dirtyfrag.tar.gz",
        poc_dir="/home/xentry-guest/xentry-poc",
        what_proves=(
            "The host serial channel shows the root-only nonce after the local PoC runs.",
        ),
        what_does_not_prove=(
            "The guest kernel is compromised; authority is guest_attested+llm_assessed, not forge-proof.",
        ),
    )
    return {target.target_id: target for target in (php, gitlab, dirtyfrag)}


TARGETS = _build_targets()
# The mtimes TARGETS was built from. It carries the step hashes and artifact
# digests of the three checked-in targets, read once at import - so re-pinning
# one of them, or editing its script, left a running app serving the old digest
# and a job failing with "artifact hash mismatch" until someone restarted it.
# The broker had the same shape and the same symptom (entry 49b).
_STAMPS: dict[str, int] = {}


def _fresh() -> dict[str, TargetInstance]:
    """TARGETS, rebuilt if either file it is derived from has changed.

    The dict object is mutated rather than replaced, because callers do
    `from xentry.targets import TARGETS` and would otherwise keep the old one.
    """
    changed = False
    for path in (STEPS, CATALOG):
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            continue
        if _STAMPS.get(str(path)) != stamp:
            _STAMPS[str(path)] = stamp
            changed = True
    if changed and _STAMPS:
        TARGETS.clear()
        TARGETS.update(_build_targets())
    return TARGETS


def by_id(target_id: str) -> TargetInstance | None:
    return _fresh().get(target_id)


def by_cve(cve_id: str) -> TargetInstance | None:
    for target in _fresh().values():
        if cve_id in target.cve_ids:
            return target
    return None


def by_poc_url(url: str) -> TargetInstance | None:
    cleaned = url.rstrip("/").removesuffix(".git")
    for target in _fresh().values():
        if cleaned == target.poc.repository.rstrip("/").removesuffix(".git"):
            return target
    return None


def artifact_hash(artifact_id: str) -> str:
    return _artifact_sha(artifact_id)


def setup_script_path(target: TargetInstance) -> Path:
    return ROOT / "targets" / target.setup_script
