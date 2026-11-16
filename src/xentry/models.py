"""Typed models from the xentry V1 contracts.

This is a Phase 0 skeleton. The authoritative field list is
docs/designs/xentry-v1-contracts.md (revision 5 corrections).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    artifact_id: str
    # Optional, and filled in by verify_facts from the artifact the id names.
    # Requiring the model to echo 64 hex characters added a failure mode and no
    # guarantee: the harness supplied the artifact and already knows its
    # digest. One wrong character used to discard a whole extraction.
    sha256: str = ""
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
    # Provisioning instructions, not claims about the vulnerability: what the
    # PoC's own README says to install and run. They carry no citation
    # requirement because they assert nothing a reader could be misled by - a
    # wrong package or entrypoint fails the provision loudly, and the closed
    # vocabulary means neither can become an arbitrary command. Used only by a
    # derived target; the three checked-in ones ignore them.
    setup_packages: list[str] = Field(default_factory=list)
    setup_units: list[str] = Field(default_factory=list)
    # What the PoC needs on the ATTACKER to run at all - a JDK for a JNDI
    # exploit, a compiler for a kernel PoC. Installed from the attacker's own
    # archive before the network locks, because after that it has no network
    # and a missing dependency is a failed run with a misleading reason.
    attacker_packages: list[str] = Field(default_factory=list)
    attacker_pip: list[str] = Field(default_factory=list)
    poc_argv: list[str] = Field(default_factory=list)
    # Where in the PoC repository the vulnerable application is built from. Read
    # as evidence about the environment, never executed: an ecosystem target
    # takes the dependency pins and the start command out of the manifest in
    # this directory and installs them itself. "" is the repository root.
    app_dir: str | None = None
    # Every version the advisory names as fixing the flaw. A list, because a
    # maintained library fixes each supported branch separately: CVE-2026-126187
    # names 19.0.9, 19.1.10, 19.2.9 and 19.3.1, and which one a job wants
    # depends on the branch its lab is on. Asking for "the fixed version" got
    # 19.0.9 - a two-minor downgrade from the lab's 19.3.0, which would have
    # made the control build a different stack rather than the same one one
    # version on. Uncited: it only decides whether a control run is possible,
    # and that run either fails - proving the point - or fails the job.
    fixed_versions: list[str] = Field(default_factory=list)
    poc_entrypoint: str | None = None
    # How a LOCAL PoC hands over root, which the harness must never guess: the
    # relay that carries the proof out has to be given to the exploit the way
    # that exploit accepts it. One checked-in script per shape, so this chooses
    # a step id and nothing else. null means neither shape fits, and the job is
    # refused saying so rather than running a relay the PoC will ignore.
    privesc_shape: (
        Literal[
            "stdin-shell", "argv-command", "fixed-command", "pty-shell",
            "setuid-drop", "two-stage",
        ]
        | None
    ) = None
    # A PoC that is a command rather than a file - blasty's CVE-2021-41773 is a
    # curl line in its README. An EvidenceRef, so the quote is verified against
    # the artifact exactly like version_evidence: the model points at a
    # command, it cannot write one. The two spans say which part of that quote
    # is the host:port and which is the file being read, and the harness
    # substitutes its own at those spans and nowhere else.
    poc_command: EvidenceRef | None = None
    poc_command_target: str | None = None
    poc_command_read: str | None = None
    # The span naming the command the TARGET executes, for an advisory whose
    # claim is code execution. Exactly one of read or exec: which one is the
    # claim the run proves, and a disclosure does not prove execution.
    poc_command_exec: str | None = None
    # The name of the script that starts an unpacked product - Confluence's
    # start-confluence.sh - for the last-resort download path, where there is no
    # package and so no systemd unit. A name, not a path and not a command: the
    # checked-in setup step resolves it under the unpacked tree and decides how
    # it runs. Uncited for the same reason setup_units is: a wrong name fails
    # the provision with the directory listing in the step output.
    launch: str | None = None
    # When the affected software is only vulnerable once a file is in place -
    # Apache needs `Require all granted`, a Tomcat app needs its .war in
    # webapps - the KIND of placement, from a closed set the setup step owns.
    # Not a path: the kind decides the path, in checked-in code.
    place: str | None = None
    # Which file in the PoC repository IS that placement, as a path relative to
    # its root - blasty's is "000-default.conf". The file listing makes it
    # visible, and naming it lets the approval card offer it instead of asking
    # the operator to go and find it.
    place_file: str | None = None
    # The directory in the PoC repository holding a Dockerfile that builds the
    # vulnerable environment, relative to its root; "" for the root itself.
    # Set only when that is the ONLY description the author gave - it trades
    # our pinned provenance for theirs, which ADR 34 records.
    dockerfile: str | None = None
    artifact_candidates: list[EvidenceRef] = Field(default_factory=list)
    citations: list[EvidenceRef]
    # Filled in by verify_facts, not by the model: why a narrative citation was
    # dropped. Defaulted so an extractor reply never has to supply it.
    dropped_citations: list[str] = Field(default_factory=list)


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
    kind: Literal[
        "target_probe", "proxy_capture", "host_serial", "qmp", "attacker_transcript"
    ]
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
