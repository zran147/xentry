"""Typed models from the xentry V1 contracts.

This is a Phase 0 skeleton. The authoritative field list is
docs/designs/xentry-v1-contracts.md (revision 5 corrections).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    artifact_id: str
    sha256: str
    quote: str
    line_start: int | None = None
    line_end: int | None = None


class Facts(BaseModel):
    cve_id: str
    product: str
    affected_range: str
    version_evidence: list[EvidenceRef]
    protocol: Literal["http", "https", "tcp", "local"] | None = None
    ports: list[int] = Field(default_factory=list)
    auth_required: bool
    build_strategy: str
    poc_context: Literal["remote", "local"]
    marker_candidate: str | None = None
    artifact_candidates: list[EvidenceRef] = Field(default_factory=list)
    citations: list[EvidenceRef]


class Resources(BaseModel):
    vcpu: int
    memory_mb: int
    disk_gb: int


class PocPin(BaseModel):
    artifact_id: str
    repository: str
    commit: str
    files: list[str]
    sha256: str
    build_step_id: str
    invocation_step_id: str


class ProbeStep(BaseModel):
    step_id: str
    kind: Literal["http_get", "response_parse", "pty_session", "host_serial", "qmp", "proxy_capture"]
    decisive: bool
    params: dict[str, object] = Field(default_factory=dict)
    timeout_s: int


class NonceSpec(BaseModel):
    path: str
    owner: str
    mode: int
    value_source: Literal["runner"] = "runner"


class NullActor(BaseModel):
    location: Literal["attacker", "target"]
    step_id: str
    expected: Literal["no_nonce"] = "no_nonce"


class EvidenceChannel(BaseModel):
    kind: Literal["target_probe", "proxy_capture", "host_serial", "qmp"]
    channel: str


class RetryPolicy(BaseModel):
    transient_fetch_retries: int = 1
    poc_reruns: int = 1


class Timeouts(BaseModel):
    boot_s: int
    provision_s: int
    readiness_s: int
    poc_s: int
    validate_s: int


class Target(BaseModel):
    target_id: Literal["php2shell", "gitlab", "dirtyfrag"]
    cve_ids: list[str]
    poc_context: Literal["remote", "local"]
    script_source: Literal["checked_in"] = "checked_in"
    base_image_artifact_id: str
    kernel_artifact_id: str | None = None
    resources: Resources
    attacker_profile_id: str | None = None
    network_profile_id: str = "isolated"
    actor_user: Literal["xentry-guest"] = "xentry-guest"
    setup_script_path: str
    setup_sha256: str
    expected_version: str
    version_probe_step_id: str
    poc: PocPin
    probes: list[ProbeStep]
    nonce: NonceSpec
    null_actor: NullActor
    evidence_channel: EvidenceChannel
    retry_policy: RetryPolicy
    timeouts: Timeouts
    target_ports: list[int] = Field(default_factory=list)
    what_proves: list[str]
    what_does_not_prove: list[str]


class RunLimits(BaseModel):
    max_tokens: int
    per_call_tokens: int
    max_vm_minutes: int
    max_disk_gb: int


class ProbeOutcome(BaseModel):
    step_id: str
    kind: str
    nonce_observed: bool
    decisive_evidence_sha256: str
    parser: str
    raw_path: str
    ts: str


class JobOutcome(BaseModel):
    id: str
    job_id: str
    attempt_id: str
    outcome: Literal["completed", "failed", "cancelled", "interrupted"]
    verdict: Literal["reproduced", "not_reproduced", "inconclusive", "not_run"]
    authority: Literal[
        "runner_observed+llm_assessed",
        "guest_attested+llm_assessed",
        "runner_observed",
    ]
    reason_code: str
    ts: str


class LlmVerdict(BaseModel):
    verdict: Literal["reproduced", "not_reproduced", "inconclusive"]
    reason_code: str
    evidence_refs: list[str]
    explanation: str
