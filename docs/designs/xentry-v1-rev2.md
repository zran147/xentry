# xentry V1 — Two-VM CVE Reproduction with a Runner-Owned Evidence Spine

* **Author:** zran147
* **Status:** Proposed (Revision 2)
* **Date:** 2026-11-06

## Overview

xentry V1 is a local web application for one or two users. A user submits a CVE link and a PoC link. The backend fetches a bounded evidence bundle, a DeepSeek-backed Google ADK agent extracts facts and authors a setup script plus PoC wrapper, and a runner-owned pipeline provisions one target VM and, for remote PoCs, one lightweight attacker VM. The target VM hosts the vulnerable software. The attacker VM builds and runs the pinned remote PoC from a separate kernel. Dirty Frag runs inside the target VM and its decisive evidence is captured through a host-side channel.

The runner owns the sequence, the nonce, the null-actor check, the evidence capture, the validator invocation, and the destroy. The model never calls validate or destroy. A separate context-isolated DeepSeek session labels the verdict `llm_assessed`. The runner's target-side nonce observation is a hard precondition: the LLM cannot return `reproduced` when the runner did not observe the nonce.

V1 uses system libvirt through a root-owned broker with a fixed verb set, a dedicated isolated libvirt network, and nftables default-deny. It uses no container runtime in execution or deployment. The three acceptance targets are CVE-2026-109618 (PHP2Shell), CVE-2026-85706 (GitLab), and CVE-2026-43500 (Dirty Frag). Their setup scripts are checked in and hand-reviewed once for malicious content; the generated-provisioning path is a V1.1 feature, not a V1 acceptance claim.

## The Problem

The prior v2 design tried to build a general evidence-first CVE pipeline and knowledge bank. It grew to roughly 12,000 lines across about 20 subsystems, produced three recipes it called verified, and could not be audited by its owner. Its verification path was self-reported: the generated PoC printed its own success marker, and the harness never checked it independently.

V1 is a reset. It narrows the product to a local web UI, three known Linux targets, one job at a time, and a runner-owned evidence path. The hard problem is not whether an agent can write a setup script. It is whether the system can show that a reported reproduction was caused by the vulnerability and not by the agent, the setup script, the PoC, a leftover file, or a misconfigured target.

V1 does not solve that problem deterministically. It uses a separate attacker VM for remote PoCs, a runner-owned nonce and null actor, a host-side evidence channel for Dirty Frag, and a context-isolated LLM validator. The verdict is honest about its authority: it is `llm_assessed`, and the runner-side nonce observation is recorded separately. The full harness-owned verification contract is deferred.

## Goals

* **G1. Local operation.** The app binds to `127.0.0.1` by default and supports one or two users without accounts. Every mutation requires a startup-generated request-integrity token, with CSRF, Origin, and Host checks. A second remote user is supported through an SSH local port forward, not LAN exposure.
* **G2. Bounded input.** The app accepts a CVE link and a PoC link, detects the source shape, fetches a bounded evidence bundle, stores the raw bytes and hashes, and rejects unsupported sources, CVEs, and PoCs before spending a VM.
* **G3. Runner-owned pipeline.** The runner owns fetch, extract, plan, network creation, target VM creation, provisioning, attacker VM creation for remote PoCs, nonce injection, null actor, real actor, evidence capture, destroy, and validator invocation. The model is invoked only for extraction, setup authoring, and bounded repair. It has no fetch, execute, validate, or destroy tools.
* **G4. Two-VM harness.** System libvirt through a root-owned broker runs one target VM and, for remote PoCs, one lightweight attacker VM. The broker exposes a fixed verb set and a fixed domain template. The two VMs share a dedicated isolated libvirt network with no host LAN or internet route after provisioning. No container runtime is used.
* **G5. Target packs.** Each target has a checked-in pack with a typed manifest: base image, kernel, resources, actor user, setup script and hash, pinned PoC, probe spec, null-actor spec, attacker profile for remote PoCs, network profile, evidence channel, retry policy, destroy policy, and claim limits. V1 uses `script_source: checked_in` for all three targets. A fourth real target is needed before the generated path becomes a product claim.
* **G6. Causal evidence.** The runner generates a fresh 128-bit nonce after provisioning and places it where the actor cannot read it directly. A null actor runs the same wrapper without the exploit and must not produce the nonce. For remote PoCs, the attacker VM runs the PoC and the runner observes the target-side nonce. For Dirty Frag, the runner captures evidence through a host-side channel. The runner records `nonce_observed`; the LLM validator cannot return `reproduced` without it.
* **G7. Execution isolation.** No PoC code is built or executed on the host. Remote PoCs are built and run in the attacker VM as a non-root user. Dirty Frag runs in the target VM as a non-root actor. No host mounts, devices, shared folders, or containers are used. The broker is root-owned and fixed-verb; its risk acceptance is recorded.
* **G8. Job lifecycle.** Jobs are asynchronous, queued, cancellable, and recoverable. The state machine covers both VMs, cancellation, interruption, teardown failure, and a startup orphan sweep. One job runs at a time; a job may use two VMs.
* **G9. Storage and audit.** The per-job attempt directory and append-only JSONL logs are authoritative. SQLite is a rebuildable index with a defined schema and forward-only migrations. Failed jobs are retained; secrets are redacted; a downloadable bundle reconstructs the job.
* **G10. Honest UI.** Job state, verdict, and verdict authority are separate fields. "Succeeded" and "verified" are banned from the UI. The agent summary is labeled non-authoritative. The pre-run plan shows both VM profiles, the network, the probe, the evidence channel, and the caps before Start.
* **G11. Budgets and failure codes.** Per-target time, memory, disk, token, and VM-cycle caps are enforced by the runner. Every failure has a closed reason code and a next action. Retries cover transient and infrastructure failures, not a failed exploit.
* **G12. Testability.** A fake two-VM driver and a fake broker cover the lifecycle without KVM. Validator fixtures, a scripted model client, a prompt-injection corpus, a null-actor test, a broker-contract test, and a kill-and-restart test are part of V1.
* **G13. Operational readiness.** The app runs from a local virtual environment and a systemd user unit. The broker runs as a separate root-owned systemd unit. The database has a schema version, forward-only migrations, a backup before migration, and a documented rollback.
* **G14. Scope discipline.** V1 is all three targets with an explicit budget, not an open-ended product rebuild. The generated-provisioning path and the second attacker VM for Dirty Frag are deferred. The budget and acceptance gates below are binding.

## Non-Goals

* User accounts, roles, multi-tenancy, or LAN exposure without an explicit SSH tunnel.
* General CVE coverage. V1 supports the three named CVEs and rejects others before provisioning.
* Arbitrary PoC adaptation. V1 runs the pinned PoC or an alternate that matches the same invocation contract.
* Windows, macOS, browser, GPU, hardware, cloud-only, or network-callback targets.
* Docker or any container runtime in xentry or in target or attacker provisioning.
* Concurrent jobs, more than two VMs per job, multi-VM topologies beyond target plus attacker, high availability, or cloud deployment.
* The full v2 contract: deterministic human-authored validators, harness-owned version-range probes, fixed-build negative controls, immutable bank versions, scoring, multiple advisory and PoC sources, and the five CLI bank verbs. V1 uses a context-isolated LLM validator with a runner-owned nonce precondition and accepts the false-positive risk.
* Automatic publication or export of results, and the license gate that would come with it.
* A general agent platform: ADK sub-agents, long-term memory, the ADK web UI, or model-driven tool selection.
* Proving real-world exploitability or safety. V1 records a lab reproduction, not a production risk assessment.
* A polished single-page app, mobile support, a frontend build chain, a dashboard, or a settings editor for every environment variable.
* Unlimited retries, indefinite artifact retention, or a disk budget beyond the stated ceiling.
* Automatic re-authoring of the exploit for V1.
* A human approval gate for generated setup scripts in the normal flow. Only the first three bootstrap scripts receive a one-time malicious-content review; the generated path is V1.1.
* Dynamic target packs or a plugin loader.
* Currency display without a versioned and dated pricing table.

## V1 Scope and Budget

The budget is binding. If a measured component exceeds it, the owner chooses what to cut or raises the budget explicitly; the design does not silently grow.

| Dimension | V1 budget |
| --- | --- |
| Handwritten Python | At most 5,500 lines across at most 26 modules |
| Templates and static files | At most 1,200 lines |
| Tests | At most 3,500 lines |
| Runtime dependencies | At most 14 direct dependencies |
| Target packs | Three checked-in packs plus shared attacker and network profiles |
| VM profiles | One target profile per target; one lightweight attacker profile |
| Concurrency | One job at a time; at most two VMs per job |
| Peak host memory | GitLab 10 GB (8 GB target + 2 GB attacker); PHP2Shell 6 GB (4 + 2); Dirty Frag 3 GB (2 + host evidence) |
| Disk ceiling | 100 GB total; per-job cap in the pack |
| Per-job time caps | PHP2Shell 45 min; GitLab 75 min; Dirty Frag 45 min |
| Token cap | 150,000 tokens per job; per-call cap enforced |
| Setup repair | One bounded repair per attempt |
| PoC rerun | One rerun for transient infrastructure failure; never for a failed exploit |
| Effort | Phase 0 one week; Phase 1 three weeks; Phase 2 two weeks; Phase 3 two weeks; Phase 4 two weeks |

Acceptance numbers:

* Two consecutive clean runs per target: both must have `nonce_observed = true`, the null actor must fail, and the verdict must be `reproduced` with authority `runner_observed+llm_assessed`.
* No completed job may lack a validation row tied to its nonce.
* Validator fixture gate: at least 18 of 20 labeled fixtures classified correctly, and all five known-fail fixtures classified as `not_reproduced` or `inconclusive`.
* ADK gate: at least 19 of 20 structured-output fixtures valid, with citation validation passing for every accepted fact. If the gate fails, the direct LiteLLM runtime is used.
* Prompt-injection gate: every hostile fixture produces a failed job and no host effect.
* Kill-and-restart gate: no running domain and no stale overlay or ISO after restart; the job is `interrupted`.
* Broker gate: the app cannot open a libvirt connection directly; every VM operation goes through the broker's fixed verbs.

## Open Questions and Phase 0 Gates

* **Broker and network.** Does the root-owned broker create a dedicated isolated libvirt network, start two VMs, enforce nftables default-deny, and return host-side evidence without exposing arbitrary libvirt control? Exit criteria: a two-VM PHP2Shell smoke run, an egress test that fails closed, and a broker-contract test.
* **Host capacity.** Does the host have enough free memory for GitLab 8 GB plus attacker 2 GB plus the app? Exit criteria: a preflight check with a hard admission refusal.
* **GitLab package.** Is GitLab CE 19.2.5 Omnibus retrievable with a stable URL and SHA-256, and does it install in the target VM? Exit criteria: a pinned artifact and a successful readiness run.
* **Dirty Frag kernel.** Is the pinned `6.17.0-23-generic` kernel package available and installable? Exit criteria: `uname -r` matches after reboot.
* **Dirty Frag host evidence.** Does the host-side serial or QMP channel capture a root-only nonce without the guest kernel being able to forge the entire channel? Exit criteria: a documented channel, a tamper analysis, and a known-limits statement.
* **PHP2Shell web root.** Can the target web user read the nonce path while the attacker user cannot? Exit criteria: ownership and mode test.
* **ADK structured output.** Does ADK plus LiteLLM plus `deepseek/deepseek-chat` meet the structured-output gate? Exit criteria: the 20-fixture gate above.
* **Image and package hashes.** What exact SHA-256 values will the operator record for the Ubuntu base images, the attacker image, the GitLab `.deb`, and the Dirty Frag kernel package? Exit criteria: tracked catalog with hashes.

## Critical User Journeys (CUJs)

### CUJ 1: Submit a remote target and get a verdict

* **Given**: the app, broker, and target pack are configured; host memory and disk pass preflight; no job is running.
* **When**: the user pastes the CVE link and the PoC link, runs Check links, reviews the two-VM plan, and presses Start.
* **Then**: the runner creates an isolated network, a target VM, and an attacker VM; provisions the target; builds the pinned PoC in the attacker; runs the null actor and the real actor; observes the target-side nonce; destroys both VMs; invokes the validator; and shows the verdict, the `runner_observed+llm_assessed` authority, and the evidence.

### CUJ 2: Submit Dirty Frag and get a verdict

* **Given**: the target pack, the pinned kernel package, and the host-side evidence channel are configured.
* **When**: the user starts the job.
* **Then**: the runner creates one target VM, provisions the kernel, reboots, verifies `uname -r`, runs the null actor and the real actor, captures the root-only nonce through the host-side channel, destroys the VM before validation, and shows the verdict with the guest-attested limit stated.

### CUJ 3: Review a verdict and its evidence

* **Given**: a completed job.
* **When**: the user opens Job Detail.
* **Then**: the runner facts (`nonce_observed`, null-actor result, version/precondition, VM and network IDs), the validator verdict, the evidence references, the nonce id, and the agent summary appear in that order; the summary is labeled non-authoritative; the user can download the audit bundle.

### CUJ 4: Cancel a long GitLab run

* **Given**: a GitLab job is provisioning or running.
* **When**: the user presses Cancel.
* **Then**: the runner interrupts the current guest command, destroys the attacker VM and the target VM in that order, removes the network, overlays, and ISOs, writes `cancelled`, and shows the cleanup result. A failed destroy is visible as `security_cleanup_failed`.

### CUJ 5: Recover after a crash

* **Given**: the worker is killed mid-job.
* **When**: the app starts again.
* **Then**: the job is marked `interrupted`; the broker lists xentry-managed domains and networks without an active job and destroys them; stale overlays and ISOs are removed; the UI shows an orphan banner if cleanup cannot finish.

### CUJ 6: Reject an unsupported CVE

* **Given**: the user submits a CVE outside the three supported packs.
* **When**: the user runs Check links.
* **Then**: the app names the unsupported target, shows the supported set, and does not create a VM, network, or model spend.

## Technical Plan (Architecture)

### System shape

```text
Browser
  |  HTTP + request-integrity token
  v
Web/API process (unprivileged) ── SQLite index ── attempt dir + JSONL
  |
  v
Job runner (one job, one or two VMs)
  |-- fetch and pin evidence (SSRF guard) -> evidence store
  |-- extractor (ADK + DeepSeek, no tools) -> typed facts
  |-- setup author/repair (ADK + DeepSeek, no tools) -> scripts
  |-- broker client over Unix socket
  |     |-- isolated libvirt network + nftables
  |     |-- target VM: create, provision, freeze, nonce, null actor, real actor
  |     |-- attacker VM (remote only): create, copy PoC, build, run
  |     |-- host-side evidence channel (Dirty Frag)
  |     `-- destroy both VMs before validation
  |-- validator session (direct LiteLLM, no tools, fresh context)
  `-- projection into jobs/validations/verdict/authority
  v
SSE or polling -> UI (state, verdict, authority, evidence, logs)
```

### Components

| Component | Responsibility |
| --- | --- |
| Web/API | Server-rendered pages, JSON endpoints, SSE, token, CSRF/Origin/Host, UI state and verdict. |
| Job runner | Queue claim, state machine, two-VM orchestration, timeouts, cancellation, retries, cleanup, validator invocation. |
| Broker client | Unix-socket client for the root-owned broker; fixed verbs only. |
| Root broker | System-libvirt domains, isolated networks, nftables, snapshots, guest exec, host evidence, destroy. |
| Fetcher and evidence store | Source-aware fetch, SSRF guard, byte caps, content-addressed storage, manifests, bounded bundle. |
| Target pack registry | Typed manifests for images, resources, scripts, PoCs, probes, null actors, attacker profiles, evidence channels. |
| Agent runtime | ADK plus LiteLLM/DeepSeek for extract, author, and repair. No fetch or execute tools. |
| Validator client | Direct LiteLLM call with a fixed prompt, no tools, runner facts plus untrusted narrative. |
| Storage | SQLite index plus per-job attempt directories and append-only JSONL. |
| UI | Four screens and one help modal; state, verdict, authority, plan, evidence, logs. |

### Broker and privilege model

The app runs as an unprivileged user and never joins the `libvirt` group. A root-owned broker listens on a Unix socket with peer-credential checks. The broker exposes only:

```text
ensure_network(job_id, profile) -> network_id
start_target(job_id, profile_id, image_id) -> vm_id
start_attacker(job_id, profile_id, image_id) -> vm_id
exec(vm_id, user, argv, tty, timeout) -> command_result
copy_in(vm_id, host_path, guest_path, user) -> sha256
copy_out(vm_id, guest_path, host_path) -> sha256
snapshot(vm_id, name) -> snapshot_id
restore(vm_id, snapshot_id)
read_host_evidence(vm_id, channel) -> bytes
destroy_vm(vm_id)
destroy_network(network_id)
list_managed() -> domains, networks
```

The broker rejects arbitrary XML, arbitrary host paths, and arbitrary commands outside the fixed domain templates. It validates the job id, the profile id, and the host path under the xentry data directory. It is a root-owned systemd unit with a restricted filesystem view and a documented capability set. The risk acceptance is recorded: the broker is root-equivalent for VM and network operations; the app is not.

### Isolated network

The broker creates one libvirt network per job:

```text
name: xentry-<job_id>
forward mode: none
subnet: 10.<job-slot>.0.0/24
target: 10.<job-slot>.0.10
attacker: 10.<job-slot>.0.20
dhcp: static leases only
host route: none
```

During provisioning, the target VM may reach only a host-local artifact mirror on the private network. The runner fetches the pinned artifacts on the host through the SSRF guard, stores them, and serves them read-only on the mirror. The target setup script uses that mirror; it does not reach the internet. The attacker VM receives the pinned PoC by `copy_in`; it does not need egress. After provisioning, nftables rules default-deny all egress from the network except the target service port used by the attacker and the runner's probe path. The broker runs an egress test before the real actor and fails closed.

The network is destroyed with the VMs. The broker lists and destroys orphan networks at startup.

### Two-VM lifecycle

Remote target (GitLab or PHP2Shell):

```text
create network -> create target -> provision target -> readiness
-> create attacker -> copy pinned PoC -> build in attacker
-> freeze target -> nonce -> null actor (attacker no-op) -> target probe
-> restore target -> fresh nonce -> real actor in attacker -> target probe
-> collect attacker transcript + target evidence -> destroy attacker
-> destroy target -> destroy network -> validate
```

Dirty Frag:

```text
create network -> create target -> provision pinned kernel -> reboot
-> verify uname -r -> freeze -> nonce -> null actor -> host evidence
-> restore or fresh boot -> fresh nonce -> real actor -> host evidence
-> destroy target -> destroy network -> validate
```

Destroy happens before the validator on every path. The validator receives an immutable bundle; it does not need a running VM.

### Runner state machine

| State | Trigger | Guard | Next | Cleanup |
| --- | --- | --- | --- | --- |
| `queued` | Job accepted | Supported target, preflight pass | `fetching` | None |
| `fetching` | Worker claim | Fetch budget | `extracting` | None |
| `extracting` | Evidence bundle stored | Typed facts valid | `planning` | None |
| `planning` | Setup author/repair | Script under cap | `creating_network` | None |
| `creating_network` | Broker network | Network profile valid | `creating_target` | `destroy_network` |
| `creating_target` | Broker start | Image hash valid | `provisioning` | `destroy_vm` |
| `provisioning` | Setup script | Readiness pass | `ready_target` | `destroy_vm` |
| `ready_target` | Version/precondition | Version accepted | `creating_attacker` or `freezing` | `destroy_vm` |
| `creating_attacker` | Broker start | Remote PoC only | `ready_attacker` | `destroy_vm` |
| `ready_attacker` | PoC copied/built | Build pass | `freezing` | `destroy_vm` |
| `freezing` | Snapshot | Target healthy | `running_null` | `destroy_vm` |
| `running_null` | Null actor | No nonce observed | `restoring` | `destroy_vm` |
| `restoring` | Snapshot restore | Restore pass | `running_poc` | `destroy_vm` |
| `running_poc` | Real actor | Nonce injected | `collecting_evidence` | `destroy_vm` |
| `collecting_evidence` | Probe/host channel | Evidence hashes | `destroying` | None |
| `destroying` | Broker destroy | Idempotent | `validating` or `failed` | Record result |
| `validating` | Validator call | Runner facts present | `completed` or `failed` | None |
| `completed` | Validation stored | Verdict projection | `done` | None |
| `failed` | Closed reason | Any phase | `destroying` | Destroy both VMs |
| `cancelled` | User cancel | Any phase | `destroying` | Destroy both VMs |
| `interrupted` | Startup recovery | Crash | `destroying` | Destroy both VMs |

`completed`, `failed`, `cancelled`, and `interrupted` are terminal outcomes; `done` records cleanup completion. Verdict (`reproduced`, `not_reproduced`, `inconclusive`, `not_run`) and authority (`runner_observed+llm_assessed`) are separate columns written by the runner. A null-actor failure is `failed` with `null_actor_failed`; it does not reach the validator.

Cancellation interrupts the current guest command, then destroys the attacker VM, the target VM, and the network in that order. Dirty Frag has no attacker VM. A destroy failure is `security_cleanup_failed` and remains visible.

### Closed reason codes

| Code | Trigger | Retry | Next action |
| --- | --- | --- | --- |
| `source_unavailable` | A required CVE or PoC fetch failed | One fetch retry | Check links |
| `evidence_insufficient` | The extractor cannot cite the facts it needs | No | Supply a better link or text |
| `unsupported_target` | The CVE is not in the three packs | No | Choose a supported CVE |
| `unsupported_poc` | The PoC link does not match the pack pin | No | Use the pinned PoC |
| `version_unidentified` | The advisory range or installed version is missing | No | Supply version evidence |
| `broker_unavailable` | Socket, peer credential, or broker auth failure | One retry | Check the broker unit |
| `network_create_failed` | libvirt network or nftables failure | One retry | Inspect broker and network logs |
| `target_create_failed` | Target domain start failure | One retry | Check memory, disk, image |
| `attacker_create_failed` | Attacker domain start failure | One retry | Check memory, disk, image |
| `provision_failed` | Setup script non-zero or readiness failure | One repair | Inspect the setup log |
| `target_unhealthy` | Service, port, or version check failed | One repair | Inspect readiness evidence |
| `null_actor_failed` | The null actor observed the nonce | No | Fix the probe or nonce placement |
| `nonce_not_observed` | The real run did not observe the nonce | One rerun only for transient infrastructure | Inspect runner facts |
| `exploit_failed` | The PoC ran without the nonce | No | Do not auto-retry |
| `host_evidence_missing` | Dirty Frag host channel returned no evidence | One retry | Inspect broker evidence log |
| `validator_error` | Provider, JSON, or schema failure | One retry | Park or record `inconclusive` |
| `validator_disagreed` | LLM verdict contradicts runner facts | No | Clamp and record |
| `timeout` | Phase or job timeout | No | Inspect the in-flight operation |
| `budget_exhausted` | Token, disk, time, or memory cap | No | Raise the cap or reduce the target |
| `cancelled` | User cancellation | No | Cleanup both VMs and the network |
| `interrupted` | Crash or restart recovery | No | Cleanup and do not resume |
| `teardown_failed` | Generic destroy or network cleanup failure | No | Manual cleanup |
| `security_cleanup_failed` | Dirty Frag or security-critical destroy failure | No | Block new jobs and clean manually |
| `policy_blocked` | Prompt injection, SSRF, or forbidden operation | No | Review the evidence |
| `harness_error` | Unexpected internal error | No | Inspect logs |

### Target packs

The manifest is a typed schema:

```yaml
target_id: php2shell
cve_ids: [CVE-2026-109618]
poc_context: remote            # remote | local
script_source: checked_in      # checked_in | generated
base_image: {name, url, sha256}
kernel: {package_url, sha256, release}   # optional
resources: {vcpu, memory_mb, disk_gb}
attacker_profile: {name, image_sha256, vcpu, memory_mb, disk_gb, toolchain}
network: {profile: isolated, target_port: 8088}
actor_user: xentry
setup_script: {path, sha256}
poc: {repository, commit, files, sha256, build, invocation_template}
probe: {kind: http_get|response_parse|pty_session|host_serial, nonce_placement, request, expected}
null_actor: {user, command_template, expected: no_nonce}
evidence_channel: {kind: target_probe|host_serial|qmp, path}
retry_policy: {setup_repairs: 1, poc_reruns: 1, fresh_vm_on_retry: bool}
destroy_policy: {mandatory_before_validate: true, failure_code}
timeouts: {boot_s, provision_s, poc_s, validate_s}
pack_version: 1
what_proves: [...]
what_does_not_prove: [...]
```

The three packs:

* **PHP2Shell, CVE-2026-109618:** target VM Ubuntu 24.04 with native PHP 8.4.26 and Apache mod_php; attacker VM with Python 3.12 and `requests`. Target port 8088. Actor `xentry`. The runner writes a nonce readable by the web user, the attacker runs the PoC `--cmd` to write it to the web root, and the runner fetches it from the target side. The attacker transcript is not the pass condition.
* **GitLab, CVE-2026-85706:** target VM Ubuntu 24.04 with pinned GitLab CE 19.2.5 Omnibus; attacker VM with Go. Target port 80/443. Actor `xentry`. The nonce is owned by the GitLab service user (`git`) and placed outside the document root; the attacker runs the Go PoC with the nonce path; the runner parses the target-side response.
* **Dirty Frag, CVE-2026-43500:** target VM Ubuntu 24.04.4 with pinned kernel `6.17.0-23-generic`; no attacker VM. Actor `xentry`. The runner drives the PTY root shell through the broker and reads the root-only nonce from the host-side channel. The VM is destroyed before validation.

### Probe and evidence contract

The probe is one typed runner-owned primitive per kind. No per-pack Python is imported into the app process.

```text
http_get:        runner GETs a target URL and records status, headers, body, hash
response_parse:  runner parses a target response for the nonce and records the match
pty_session:     runner opens a PTY as the actor, runs the PoC command, records the transcript
host_serial:     broker reads the host-side serial/virtio-serial channel and records bytes
qmp:             broker reads a QMP query result from the host side
```

`ProbeContext` contains `job_id`, `target_id`, `vm_id`, `user`, `nonce`, `nonce_path`, `target_port`, and `timeouts`. `ProbeEvidence` contains `kind`, `command`, `stdout_sha256`, `stderr_sha256`, `exit_code`, `http_status`, `body_excerpt`, `nonce_observed`, `timestamp`, and `raw_path`. The runner resolves every evidence reference against the transcript or artifact hashes.

### Nonce, actor, and null actor

* **Actor** is the non-root account that runs the PoC, distinct from the service account the vulnerability compromises. The target pack names it; the attacker VM always runs the PoC as `xentry`.
* **Nonce** is 128 bits from `secrets.token_hex(16)`, generated after the freeze and placed by the runner. The target pack declares the path, owner, and mode. The nonce path is kept out of the setup-author prompt and out of the generator's context. The validator may see the nonce value only as a runner fact; the bundle prefers `nonce_observed` and a hash.
* **Null actor** runs the same wrapper with the exploit parameter removed or invalidated. It runs as the same user and exercises the same probe read path. The expected result is `nonce_observed = false`. The null-actor transcript is stored in the attempt directory.
* **Deterministic precondition:** the runner writes `nonce_observed` to the validation input. If false, the job is `failed` or `inconclusive` before or regardless of the LLM verdict. The LLM cannot return `reproduced`.
* **Reactive setup:** the setup scripts are checked in and hash-pinned for V1. The runner records the executed hash. A generated setup script is a V1.1 feature and is not used for the three V1 targets.

### Validator

The validator is a direct LiteLLM call to `deepseek/deepseek-chat`, not an ADK agent. It has a fixed, versioned prompt, temperature 0, no tools, no generator history, no plan, no repair history, and no shared state. It receives:

* **Runner facts:** `nonce_observed`, null-actor result, version/precondition, target and attacker VM ids, probe outputs, evidence hashes.
* **Untrusted narrative:** pinned PoC, setup script and wrapper, attacker transcript, target response excerpts.

The validator returns:

```json
{
  "verdict": "reproduced | not_reproduced | inconclusive",
  "reason_code": "closed code",
  "evidence_refs": ["transcript line or artifact hash"],
  "explanation": "short text"
}
```

The runner validates the schema, resolves every `evidence_ref`, clamps `reproduced` to false when `nonce_observed` is false, stamps `model` and `prompt_hash` itself, and stores the validation row with `authority = runner_observed+llm_assessed`. The validator prompt labels the bundle sections as data, not instructions. The bundle minimizes DeepSeek egress: prefer the nonce observation and hashes over the nonce value and raw attacker text.

### Agent runtime

ADK is used behind `AgentRuntime` with `LiteLlm(model="deepseek/deepseek-chat")`. The agent has three calls and no tools:

* `extract(excerpts) -> Facts`
* `author_setup(facts, pack) -> SetupBundle`
* `repair_setup(facts, classified_log, pack) -> SetupBundle`

The typed `Facts` model includes product, affected range, version evidence, protocol/port, auth, build strategy, PoC context, candidate marker, and artifact candidates. Each fact carries an `evidence_ref` and a quote. Prompt files are versioned and hashed. The runner logs every model request and response, token counts, model id, and prompt hash.

The ADK gate measures structured-output validity, citation validity, and repair success on 20 fixtures. If the gate fails, a direct LiteLLM function-calling loop of roughly 150–250 lines replaces ADK behind the same interface. The validator is always a direct LiteLLM call.

### Storage and audit

SQLite is a rebuildable index. The attempt directory and JSONL are authoritative.

```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY, cve_id TEXT NOT NULL, target_id TEXT NOT NULL,
  poc_url TEXT NOT NULL, state TEXT NOT NULL, verdict TEXT,
  authority TEXT, reason_code TEXT, created_at TEXT NOT NULL,
  started_at TEXT, finished_at TEXT, attempt_dir TEXT NOT NULL,
  agent_summary TEXT
);
CREATE TABLE attempts (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_no INTEGER NOT NULL,
  attempt_dir TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT,
  finished_at TEXT, failure_code TEXT, previous_attempt_id TEXT,
  FOREIGN KEY(job_id) REFERENCES jobs(id)
);
CREATE TABLE vms (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, role TEXT NOT NULL,
  domain_name TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT,
  destroyed_at TEXT, FOREIGN KEY(job_id) REFERENCES jobs(id)
);
CREATE TABLE tool_calls (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL, tool TEXT NOT NULL, params_json TEXT NOT NULL,
  params_sha256 TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  status TEXT NOT NULL, result_path TEXT, result_sha256 TEXT,
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE validations (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  target_pack_id TEXT NOT NULL, pack_version INTEGER NOT NULL,
  authority TEXT NOT NULL, validator_model TEXT NOT NULL,
  validator_prompt_hash TEXT NOT NULL, verdict TEXT NOT NULL,
  reason_code TEXT, runner_nonce_observed INTEGER NOT NULL,
  null_actor_passed INTEGER NOT NULL, evidence_json TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL, ts TEXT NOT NULL,
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE artifacts (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  kind TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE worker_lock (
  id INTEGER PRIMARY KEY CHECK (id = 1), owner TEXT NOT NULL,
  heartbeat TEXT NOT NULL
);
CREATE TABLE schema_version (version INTEGER NOT NULL);
```

`jobs.state` is the lifecycle state; `jobs.verdict` and `jobs.authority` are the latest projection from the final attempt's validation. A null-actor failure writes `verdict = not_run`, `authority = runner_observed`, and `reason_code = null_actor_failed`. The attempt directory contains `attempt.json`, raw evidence, scripts, VM logs, transcript JSONL, validator input/output, and `outcome.json` written last and atomically. Redaction runs before any write.

### Web UI and API

```text
POST /api/jobs                  {cve_url, poc_url, check_id?} + token -> job id
POST /api/links/check          fetch and summarize both links -> check_id, bundle_sha256, target_id, plan
GET  /api/jobs                 list
GET  /api/jobs/{id}            job row, state, verdict, authority
GET  /api/jobs/{id}/validations validation row and evidence refs
GET  /api/jobs/{id}/evidence/{artifact_id} evidence bytes or excerpt
GET  /api/jobs/{id}/events     SSE stream with Last-Event-ID backfill
GET  /api/jobs/{id}/events?since= polling fallback
POST /api/jobs/{id}/cancel     request cancellation
GET  /api/jobs/{id}/bundle     downloadable audit bundle
POST /api/preflight            broker, KVM, memory, disk, images, DeepSeek, DB, bind mode
GET  /api/system               preflight status and orphan list
GET  /help                     help page
```

The UI has four screens and one help modal: New Job, Jobs, Job Detail, System. New Job shows Check links, the resolved CVE/target, the target and attacker VM profiles, the isolated network, the probe, the evidence channel, the caps, and the PoC revision being used. Job Detail shows the stage timeline, the runner facts first, the validator verdict and authority, the evidence, and the agent summary labeled non-authoritative. The UI never uses "succeeded" or "verified." The token is delivered via an HttpOnly, SameSite cookie or a per-page endpoint; all model, PoC, and transcript text is autoescaped and rendered as inert text; a strict CSP is on.

### Security and threat model

* **Broker risk:** the broker is root-owned and can start/destroy VMs and change network rules. It is not a general libvirt proxy; it exposes fixed verbs and validates job/profile/path. The app never joins `libvirt`. The risk acceptance is recorded.
* **Network:** isolated libvirt network, no host LAN or internet route after provisioning, nftables default-deny, host-local artifact mirror, egress test fails closed, all attempts logged.
* **VM boundary:** no host mounts, devices, shared folders, display, USB, 9p, or virtiofs. Virtio disk/net and serial only. Transient domains, no autostart.
* **PoC handling:** the host stores the PoC archive as opaque bytes and hashes it; extraction/build happens in the attacker VM. No host execution.
* **Dirty Frag:** host-side serial/QMP evidence, mandatory destroy before validation, guest-attested limit stated in the UI and bundle.
* **Prompt injection:** the extractor receives excerpts, not raw HTML; the generator receives typed facts and the pack, no fetch/execute tools; the validator sees labeled data and has no tools; hostile fixtures must fail.
* **SSRF:** http/https only, resolve and connect to the validated IP, reject loopback/private/link-local/multicast/metadata on every redirect, `trust_env=False`, byte and time caps.
* **UI:** token not in the DOM where possible, autoescaping, inert logs, CSP, Host/Origin checks, JSON content type.
* **Secrets and egress:** `.env` at 0600; no key or guest password in logs or guest; DeepSeek egress disclosed in the UI/help; bundle minimizes raw attacker text and nonce exposure.
* **No containers:** no Docker or Podman in execution, target provisioning, or attacker provisioning.

### Interfaces

```text
VmDriver:        create(profile, role), start, exec(user, argv, tty, timeout),
                 copy_in, copy_out, snapshot, restore, host_evidence,
                 destroy, private_ip
BrokerClient:    ensure_network, start_target, start_attacker, exec, copy_in,
                 copy_out, snapshot, restore, read_host_evidence,
                 destroy_vm, destroy_network, list_managed
GuestExec:       run(user, argv, tty, timeout) -> CommandResult
HttpProbe:       get(url, timeout) -> HttpResult
Fetcher:         fetch(url) -> Artifact + Manifest
EvidenceStore:   put(bytes, manifest) -> hash; get(hash)
AgentRuntime:    extract(excerpts) -> Facts; author_setup(facts, pack) -> SetupBundle;
                 repair_setup(facts, classified_log, pack) -> SetupBundle
ValidatorClient: assess(runner_facts, narrative) -> LlmVerdict
NetworkManager:  create_isolated(job), allow_artifact_mirror, default_deny,
                 egress_test, destroy
JobRunner:       submit, cancel, recover, sweep_orphans
```

### What each target proves and does not prove

* **PHP2Shell:** proves RCE in the pinned PHP 8.4.26/Apache build through a target-side nonce observed after an attacker-VM request. Does not prove other builds, other SAPIs, or real-world exploitability.
* **GitLab:** proves an unauthenticated file read of the runner's nonce file through an attacker-VM request. Does not prove other versions, other paths, or broader data access.
* **Dirty Frag:** proves that a root-only nonce was observed through the host-side channel after the local exploit. The guest kernel is compromised during the exploit, so the transcript is guest-attested; the host-side channel and the known limits are recorded. Does not prove persistence, other kernels, or reliability on patched builds.
* **Overall:** V1 records a lab reproduction with a runner-observed nonce and an `llm_assessed` verdict. It is not a deterministic proof and not a production risk assessment.

## Alternatives Considered

### 1. Runner-owned sequence instead of an agent-owned tool trajectory

* **Pros:** The job state is not model output; validate and destroy cannot be skipped.
* **Cons:** The runner has more states and the agent has less flexibility.
* **Reason for Rejection:** Agent-owned was rejected because it makes the job state a model output and hands the model a success verb. A fully deterministic pipeline was also rejected because it removes the requested LLM capability. Revisit if the agent adds no value over fixed steps.

### 2. Target VM plus attacker VM for remote PoCs, Dirty Frag local with host evidence

* **Pros:** The remote PoC runs in a separate kernel; the target-side nonce observation is independent of the attacker transcript; Dirty Frag needs no second VM.
* **Cons:** Two VMs per remote job break the one-VM assumption and increase memory and time; Dirty Frag's evidence remains guest-attested.
* **Reason for Rejection:** Host execution (rejected: untrusted code on the workstation), a single VM for remote PoCs (rejected: same-kernel causality), and Docker as the attacker boundary (rejected: host kernel and daemon risk, and the user's no-container rule) were not chosen. The chosen path is target plus attacker VM with a runner-owned nonce; Dirty Frag uses a host-side channel and states its limit.

### 3. Independent LLM validator with a runner-owned nonce precondition

* **Pros:** The validator is context-isolated and the runner's nonce observation constrains it.
* **Cons:** The LLM can still be fooled; the validator adds a model call and egress.
* **Reason for Rejection:** Human-authored deterministic validators were deferred because the owner chose the independent-session approach; the full v2 oracle was rejected for scope and schedule. The chosen path is a runner-owned nonce/null actor plus an independent LLM session that cannot return `reproduced` without `nonce_observed`. Revisit when the harness contract lands.

### 4. System libvirt through a root-owned broker

* **Pros:** The only path that provides an isolated network, nftables control, host-side evidence, and two VMs with a fixed interface while keeping the app unprivileged.
* **Cons:** The broker is root-owned; it is a privileged component and must be reviewed and restricted.
* **Reason for Rejection:** Session libvirt was rejected because it does not provide the same network and host-evidence control for two VMs; direct QEMU was rejected for V1 because it re-buys the harness and still needs host root for nftables. The broker risk is accepted and recorded.

### 5. Checked-in setup scripts for V1, generated path in V1.1

* **Pros:** The reviewed hash describes what runs; the three acceptance targets are reproducible; the generated path is not claimed without a real target.
* **Cons:** The autonomous normal flow is not exercised in V1; a fourth real target is needed.
* **Reason for Rejection:** Per-run generation for the first three targets was rejected because a reactive setup can manufacture evidence and the reviewed hash would not describe the executed script. The generated path is deferred to V1.1 with a real fourth target.

### 6. ADK behind an interface with a structured-output gate

* **Pros:** Keeps the requested ADK path; the interface allows a direct LiteLLM fallback.
* **Cons:** ADK adds a framework layer and a gate; it is not load-bearing.
* **Reason for Rejection:** Direct LiteLLM without a spike was rejected for now because the owner asked for ADK; ADK without a gate was rejected because its structured-output behavior is unproven. The chosen path is ADK with a 20-fixture gate and a direct fallback.

### 7. Filesystem attempt directories plus a SQLite index

* **Pros:** JSONL and attempt directories are authoritative and readable; SQLite is rebuildable.
* **Cons:** Two stores require projection rules and rebuild code.
* **Reason for Rejection:** SQLite for command output and transcripts was rejected because it bloats the database and couples retention to migrations; a no-database option was rejected because job and evidence queries are harder. The chosen path is files plus a minimal index with a defined DDL.

### 8. Asynchronous job queue with one worker

* **Pros:** Long jobs survive browser refreshes; cancellation and recovery are explicit.
* **Cons:** A background worker and state machine are more code than a blocking request.
* **Reason for Rejection:** Blocking requests were rejected because GitLab runs for tens of minutes. One process with a background worker was chosen over a separate worker because a broker or supervisor adds operational surface for one or two users.

### 9. Minimal four-screen UI with SSE and polling fallback

* **Pros:** The UI can show the two-VM plan, the runner facts, the verdict, and the evidence.
* **Cons:** The UI is more than a thin adapter; it is a browser trust boundary.
* **Reason for Rejection:** A CLI-only product was rejected because the requirement is a web UI; a polished SPA was rejected as scope. The chosen path is four server-rendered screens, SSE, polling fallback, autoescaping, and a strict CSP.

### 10. Docker as the remote-PoC boundary

* **Pros:** A container is lighter than a VM and easier to start.
* **Cons:** A Docker container shares the host kernel and requires the daemon/socket; it is weaker than a VM and contradicts the no-container rule.
* **Reason for Rejection:** Rejected by the owner and the review. The second attacker VM provides a separate kernel and keeps the VM as the isolation boundary.

## Non-Functional Requirements

* **Security and privacy:** loopback binding, request-integrity token, CSRF/Origin/Host, SSRF guard with connect-to-validated-IP, two-VM isolation, nftables default-deny, broker fixed verbs and risk acceptance, no host mounts or devices, no secrets in guests or logs, DeepSeek egress disclosure and minimization.
* **Performance and latency:** one job at a time; two VMs for remote targets; GitLab target 8 GB plus attacker 2 GB; PHP2Shell 4 + 2 GB; Dirty Frag 2 GB plus host evidence. SSE with polling fallback; per-phase timeouts; token caps.
* **Reliability and recovery:** state table, per-phase timeouts, cancellation, idempotent destroy, orphan sweep for domains and networks, interrupted-job marking, broker idempotency.
* **Storage and retention:** attempt directories and JSONL authoritative; SQLite rebuildable; failed jobs retained; overlays and archives pruned by policy; 100 GB ceiling.
* **Rollout and rollback:** app as a user systemd unit; broker as a root systemd unit; forward-only migrations with backup; a newer schema refuses to start; an upgrade marks in-flight jobs interrupted and destroys their VMs.

## Additional Resources

* `concepts_brief.md` — the approved V1 brainstorm brief.
* `consolidated_review_report.md` and the five stage reports — the review that produced this revision.
* `docs/adr/0001-v1-reset.md` — the decision record for the two-VM architecture, the broker, the checked-in scripts, and the independent LLM validator.
* The three pinned PoC repositories and the CVE records for CVE-2026-109618, CVE-2026-85706, and CVE-2026-43500.

## Future Improvements

* Replace the LLM-assessed verdict with the full harness-owned contract: deterministic validators, version-range probes, fixed-build controls, and an immutable bank.
* Add the generated-provisioning path with a fourth real target and no human review, and remove the checked-in-script limitation.
* Add more target packs without changing the pipeline; add Windows or client-side targets only with their own isolation design.
* Add cached base images with a corrected key, more than one concurrent job, and a proper LAN auth story if the user count grows.
* Add model-free revalidation and a cost dashboard once the pricing table is versioned.

## Detailed Implementation Plan

### Fixed defaults

* Python 3.12; `uv` with `uv.lock`; FastAPI, Jinja2, `sse-starlette`, `httpx`, Pydantic, PyYAML, `google-adk`, `litellm`, `libvirt-python`, `asyncssh`.
* App as an unprivileged user; system libvirt through the root-owned broker over a Unix socket.
* Two VM profiles: target and attacker. The attacker is a lightweight Ubuntu 24.04 image with Go and Python; no compiler needed for the remote PoCs.
* SQLite index; attempt directories and JSONL authoritative.
* One job at a time; at most two VMs.
* GitLab CE 19.2.5; Dirty Frag `6.17.0-23-generic`; PHP 8.4.26.
* V1 `script_source: checked_in` for all three targets; the generated path is V1.1.

### Host prerequisites

* Linux with KVM (`/dev/kvm`); nested virtualization on WSL2; system libvirt 12 or newer; QEMU 10 or newer.
* `nftables`, `cloud-image-utils` (`cloud-localds`), `qemu-img`, `ssh-keygen`, libvirt development headers for `libvirt-python`, Python 3.12, `uv`, and systemd.
* A dedicated unprivileged `xentry` user for the app. The app is not in the `libvirt` group. The broker runs as a separate root-owned systemd unit.
* Preflight checks free memory, free disk, `/dev/kvm`, broker reachability, artifact hashes, DeepSeek reachability, DB writability, and bind mode. GitLab peaks at 10 GB of guest memory and 40 GB of disk; the total ceiling is 100 GB.
* WSL2 checks: `/dev/kvm` after restart, libvirtd enabled, systemd user lingering, and monotonic durations.

### Target files to create or modify

| File | Type | Required contents |
| --- | --- | --- |
| `pyproject.toml` | Create | Project metadata, dependencies, tool config, `uv` lock workflow. |
| `uv.lock` | Create | Pinned dependency graph. |
| `README.md` | Create | Install, broker setup, base images, `.env`, run, systemd, security, limits. |
| `.env.example` | Modify | Session-to-broker settings, broker socket, network profile, attacker image, caps, paths; remove stale system-libvirt and attempt defaults. |
| `.gitignore` | Modify | `.env`, `var/`, `*.qcow2`, `*.iso`, keys, test artifacts. |
| `deploy/xentry.service` | Create | User unit for the unprivileged app. |
| `deploy/xentry-broker.service` | Create | Root-owned broker unit with a restricted filesystem and capability set. |
| `scripts/fetch-artifacts.sh` | Create | Fetch and hash the base images, attacker image, GitLab `.deb`, and Dirty Frag kernel package into the tracked catalog. |
| `scripts/migrate.py` | Create | Forward-only migrations, backup, newer-schema refusal. |
| `scripts/run-dev.sh` | Create | `uv sync`, load `.env`, run uvicorn. |
| `scripts/preflight.py` | Create | CLI wrapper around `src/xentry/preflight.py`. |
| `scripts/run_target_e2e.py` | Create | Real-VM acceptance runner for one target. |
| `config/artifacts.yaml` | Create | Tracked artifact catalog: image, package, kernel, PoC URLs and SHA-256. |
| `profiles/attacker.yaml` | Create | Lightweight attacker image, resources, toolchain, no egress. |
| `profiles/network.yaml` | Create | Isolated network name pattern, subnet, target/attacker addresses, artifact mirror, nftables policy. |
| `prompts/extract.md` | Create | Tool-less extractor contract and `Facts` schema. |
| `prompts/setup.md` | Create | Setup author contract and line cap. |
| `prompts/repair.md` | Create | Bounded repair contract and classified-log schema. |
| `prompts/validator.md` | Create | Runner facts vs. untrusted narrative; JSON verdict; no tools. |
| `prompts/README.md` | Create | Prompt versioning and fixture policy. |
| `targets/README.md` | Create | Pack schema, hash rules, `poc_context`, `script_source`, probe kinds, budget. |
| `targets/php2shell/pack.yaml` | Create | Typed pack for CVE-2026-109618. |
| `targets/php2shell/setup.sh` | Create | Hand-reviewed PHP 8.4.26/Apache build, hash-pinned. |
| `targets/php2shell/probe.yaml` | Create | `http_get` target-side nonce probe and null-actor spec. |
| `targets/php2shell/poc.pin.yaml` | Create | Repository, commit, files, SHA-256, build, invocation. |
| `targets/gitlab/pack.yaml` | Create | Typed pack for CVE-2026-85706. |
| `targets/gitlab/setup.sh` | Create | Pinned GitLab 19.2.5 Omnibus install. |
| `targets/gitlab/probe.yaml` | Create | `response_parse` target-side nonce probe and null-actor spec. |
| `targets/gitlab/poc.pin.yaml` | Create | Go PoC repository, commit, build, invocation. |
| `targets/dirtyfrag/pack.yaml` | Create | Typed pack for CVE-2026-43500; `poc_context: local`, host evidence. |
| `targets/dirtyfrag/setup.sh` | Create | Pinned kernel install, reboot, `uname -r` gate. |
| `targets/dirtyfrag/probe.yaml` | Create | `pty_session` + `host_serial` evidence and null-actor spec. |
| `targets/dirtyfrag/poc.pin.yaml` | Create | C PoC repository, commit, build. |
| `targets/_dummy/pack.yaml` | Create | Test-only generated pack; not a V1 acceptance proof. |
| `migrations/001_initial.sql` | Create | The DDL above, indexes, constraints. |
| `migrations/README.md` | Create | Forward-only policy and backup rule. |
| `src/xentry/__init__.py` | Create | Package marker and version. |
| `src/xentry/config.py` | Create | Settings, absolute paths, file modes, caps, broker socket. |
| `src/xentry/models.py` | Create | Pydantic models: `TargetPack`, `PocPin`, `Facts`, `ProbeContext`, `ProbeEvidence`, `ValidationRecord`, `LlmVerdict`, `RunLimits`. |
| `src/xentry/db.py` | Create | SQLite factory, WAL, migrations, repositories, claim/projection queries. |
| `src/xentry/security.py` | Create | Token generation/storage, Origin/Host, CSRF, CSP, redaction. |
| `src/xentry/events.py` | Create | JSONL event schema, writer, SSE formatting, backfill. |
| `src/xentry/queue.py` | Create | Claim, worker lock, cancel flag, recovery. |
| `src/xentry/runner.py` | Create | State machine, two-VM orchestration, timeouts, cleanup, validator invocation. |
| `src/xentry/broker.py` | Create | Broker client with fixed verbs. |
| `src/xentry/cleanup.py` | Create | Orphan domains/networks, overlays, ISOs, interrupted jobs. |
| `src/xentry/fetch.py` | Create | SSRF-safe fetch with connect-to-validated-IP. |
| `src/xentry/sources.py` | Create | NVD, cve.org, GitHub, generic HTML; bounded bundle. |
| `src/xentry/evidence.py` | Create | Content-addressed store and quote checks. |
| `src/xentry/packs.py` | Create | Typed pack loader, hash checks, probe kind validation. |
| `src/xentry/agent.py` | Create | `AgentRuntime`, ADK runtime, direct LiteLLM fallback, prompts, repair. |
| `src/xentry/validator.py` | Create | Runner facts bundle, direct LiteLLM call, schema validation, clamping. |
| `src/xentry/bundle.py` | Create | Audit bundle and hash manifest. |
| `src/xentry/preflight.py` | Create | Broker, KVM, memory, disk, artifacts, DeepSeek, DB, bind mode, orphans. |
| `src/xentry/web/__init__.py` | Create | Package marker. |
| `src/xentry/web/app.py` | Create | FastAPI app, lifespan, middleware, templates, static. |
| `src/xentry/web/routes.py` | Create | UI and API routes. |
| `src/xentry/web/sse.py` | Create | SSE with backfill and heartbeat. |
| `src/xentry/web/schemas.py` | Create | Request/response models. |
| `src/xentry/web/deps.py` | Create | Settings, DB, token, job, template context. |
| `src/xentry/vm/__init__.py` | Create | Package marker. |
| `src/xentry/vm/driver.py` | Create | `VmDriver`, `VmProfile`, `CommandResult`, `SnapshotRef`. |
| `src/xentry/vm/broker_driver.py` | Create | Driver backed by the broker client. |
| `src/xentry/vm/fake_driver.py` | Create | In-memory two-VM fake for tests. |
| `src/xentry/vm/network.py` | Create | Network profile, artifact mirror, nftables policy, egress test. |
| `src/xentry/vm/host_evidence.py` | Create | Host serial/QMP evidence capture and tamper notes. |
| `src/xentry/vm/images.py` | Create | Catalog, hash checks, cloud-init seed, overlays, SSH keys. |
| `src/xentry/vm/probes.py` | Create | Runner-owned `http_get`, `response_parse`, `pty_session`, `host_serial` primitives. |
| `broker/xentry_broker.py` | Create | Root-owned broker service: fixed verbs, libvirt, nftables, host evidence. |
| `templates/base.html` | Create | Layout, CSP, token delivery, navigation. |
| `templates/new_job.html` | Create | Links, Check links, two-VM plan, Start. |
| `templates/jobs.html` | Create | Job list with state, verdict, authority. |
| `templates/job_detail.html` | Create | Timeline, runner facts, verdict, evidence, agent summary. |
| `templates/system.html` | Create | Preflight, orphans, caps. |
| `templates/help.html` | Create | Usage, security, SSH tunnel, limits. |
| `static/app.css` | Create | Minimal accessible layout. |
| `static/app.js` | Create | Token-aware fetch, SSE, polling, filters, cancel, bundle. |
| `tests/conftest.py` | Create | Temp dirs, DB, settings, fake broker/driver, scripted model. |
| `tests/test_state_machine.py` | Create | Transition table, guards, terminal states, projection. |
| `tests/test_broker_contract.py` | Create | Fixed verbs, no XML/paths/commands, peer checks, idempotent destroy. |
| `tests/test_network_policy.py` | Create | Isolated network, artifact mirror, default-deny, egress failure. |
| `tests/test_two_vm_runner.py` | Create | Remote and local paths, null actor, nonce, destroy before validate. |
| `tests/test_queue_recovery.py` | Create | Claim, kill/restart, interrupted, orphan sweep. |
| `tests/test_fetch_ssrf.py` | Create | Private/metadata rejection, connect-to-IP, redirect, caps. |
| `tests/test_sources.py` | Create | Source detection, citations, PoC pinning. |
| `tests/test_evidence.py` | Create | Content-addressed store, quote checks, bundle limit. |
| `tests/test_packs.py` | Create | Schema, hashes, probe kinds, no target-id branches. |
| `tests/test_agent_contract.py` | Create | Extract/author/repair, no tools, citations, gate fixtures. |
| `tests/test_validator.py` | Create | Runner facts, nonce clamp, evidence refs, schema, egress minimization. |
| `tests/test_security.py` | Create | Token, CSRF/Origin/Host, CSP, redaction, no secrets. |
| `tests/test_ui_vocabulary.py` | Create | No "succeeded"/"verified"; state/verdict/authority; agent summary label. |
| `tests/test_prompt_injection.py` | Create | Hostile CVE/PoC/setup/transcript fixtures fail safely. |
| `tests/test_vm_libvirt.py` | Create | Gated real two-VM smoke: broker, network, boot, exec, snapshot, destroy, egress. |
| `tests/test_bundle.py` | Create | Bundle reconstruction, hashes, no secrets. |
| `tests/fixtures/` | Create | NVD/GitHub/transcript/prompt-injection fixtures for the gates. |
| `docs/adr/0001-v1-reset.md` | Create | Two-VM, broker, checked-in scripts, independent validator, no-container decision. |
| `docs/security/threat-model.md` | Create | Broker, network, VM, Dirty Frag, SSRF, XSS, DeepSeek egress, host archive. |
| `docs/designs/xentry-v1.md` | Modify | This revision. |
| `docs/designs/SITEMAP.md` | Modify | Keep the design registered. |

### Verification plan

* **Build:** `uv sync --extra dev`, `python -m compileall src broker`.
* **Unit:** `pytest -q`; fake broker/driver covers the two-VM lifecycle.
* **Static:** `ruff check src broker tests`, `ruff format --check`, `mypy src broker`.
* **Coverage:** `pytest --cov=src/xentry --cov=broker --cov-fail-under=80`; exclude templates, static, and scripts.
* **Broker:** fixed-verb tests, invalid job/profile/path rejection, peer-credential check, idempotent destroy, orphan network cleanup.
* **Network:** two-VM smoke, artifact mirror, default-deny, egress test fails closed, no host LAN route, attacker cannot reach the host.
* **Two-VM path:** remote job with PHP2Shell and GitLab; null actor fails; runner observes the target-side nonce; destroy before validate; no host effect.
* **Dirty Frag:** host-side evidence, guest-attested limit, mandatory destroy, `uname -r` gate.
* **Security:** SSRF connect-to-IP, DNS rebinding, XSS/CSP, token, prompt-injection corpus, DeepSeek bundle minimization.
* **Recovery:** kill and restart; no domain or network remains; job `interrupted`.
* **Acceptance:** two consecutive clean runs per target; validator fixture gate; ADK gate; broker gate; budget gate.
* **UI:** rendered-page test for state/verdict/authority and banned words.

### Phases

* **Phase 0: one week.** Broker, isolated network, two-VM smoke, PHP2Shell build, Dirty Frag kernel, GitLab package, ADK structured-output gate, artifact hashes. Exit criteria are the Open Questions gates.
* **Phase 1: three weeks.** Engine, storage, fake broker/driver, web UI, token/SSRF, PHP2Shell end to end with two VMs. Acceptance: two clean runs, null actor fails, nonce observed, no orphan.
* **Phase 2: two weeks.** GitLab pack, heavy provisioning, long-job UX, attacker VM, cancel. Acceptance: two clean runs, correct nonce, no orphan.
* **Phase 3: two weeks.** Dirty Frag pack, pinned kernel, reboot, host-side evidence, mandatory destroy. Acceptance: two clean runs with the guest-attested limit recorded.
* **Phase 4: two weeks.** Prompt-injection corpus, broker/network security, budget tests, bundle, upgrade/rollback, full acceptance.

The phases are sequential. Phase 0 failures change the plan before Phase 1; they do not become acceptance surprises.
