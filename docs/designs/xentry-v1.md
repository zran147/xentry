# xentry V1 — Target and Attacker VM CVE Reproduction

* **Author:** zran147
* **Status:** Proposed (Revision 5)
* **Date:** 2026-11-06

## Overview

xentry V1 is a local web application for one or two users. A user submits a CVE link and a PoC link. The backend fetches a bounded evidence bundle, a DeepSeek-backed Google ADK extractor returns typed facts, and a runner-owned pipeline provisions a target VM and, for remote PoCs, a lightweight attacker VM. The target VM hosts the vulnerable software. The attacker VM builds and runs the pinned remote PoC from a separate kernel. Dirty Frag runs inside the target VM and its evidence is captured through a host-side channel.

The runner owns every stateful operation: network creation, VM creation, provisioning, nonce placement, null actor, real actor, evidence capture, destroy, and validator invocation. The model has no fetch, execute, validate, or destroy tools. A separate context-isolated DeepSeek session labels the verdict `llm_assessed`. The runner's nonce observation is a hard precondition for `reproduced`; the LLM cannot create a pass. The authority is `runner_observed+llm_assessed` for remote targets and `guest_attested+llm_assessed` for Dirty Frag.

V1 uses system libvirt through a root-owned broker with a fixed verb set, a dedicated isolated libvirt network, an artifact mirror, and nftables default-deny. It uses no container runtime. The three acceptance targets are CVE-2026-109618 (PHP2Shell), CVE-2026-85706 (GitLab), and CVE-2026-43500 (Dirty Frag). Their setup scripts are checked in and hand-reviewed once. The generated-provisioning path is V1.1.

The owner has chosen all three targets, the attacker VM for remote PoCs, the system-libvirt broker, and the checked-in-script path. Revision 5 raises the budget to match that choice and adds the field-level contracts, broker registry, target values, runner step table, reason-code/DDL/API definitions, corrections, and test cases in the companion file `docs/designs/xentry-v1-contracts.md`, which is normative.

## The Problem

The prior v2 design tried to build a general evidence-first CVE pipeline and knowledge bank. It grew to roughly 12,000 lines across about 20 subsystems, produced three recipes it called verified, and could not be audited by its owner. Its verification path was self-reported: the generated PoC printed its own success marker, and the harness never checked it independently.

V1 is a reset. It narrows the product to a local web UI, three known Linux targets, one job at a time, and a runner-owned evidence path. The hard problem is not whether an agent can write a setup script. It is whether the system can show that a reported reproduction was caused by the vulnerability and not by the agent, the setup script, the PoC, a leftover file, or a misconfigured target.

V1 does not solve that problem deterministically. It uses an attacker VM for remote PoCs, a runner-owned nonce and null actor, a host-side evidence channel for Dirty Frag, and a context-isolated LLM validator. The verdict is honest about its authority. The full harness-owned verification contract is deferred.

## Goals

* **G1. Local operation.** Bind `127.0.0.1`. One or two users, no accounts. Every non-GET request requires a request-integrity token, with CSRF, Origin, and Host checks. A second remote user connects through an SSH local port forward.
* **G2. Bounded input.** Accept a CVE link and a PoC link, detect the source shape, fetch a bounded evidence bundle, store raw bytes and hashes, and reject unsupported sources, CVEs, and PoCs before creating a VM or network.
* **G3. Runner-owned pipeline.** The runner owns the ordered steps: fetch, extract, plan, create network, create target, provision, readiness, create attacker for remote PoCs, build PoC, freeze, place nonce, null actor, probe, restore or reboot, fresh nonce, real actor, target probe, host evidence, destroy attacker, destroy target, destroy network, validate, project. The model is invoked only for extraction.
* **G4. Two-VM harness.** System libvirt through a root-owned broker runs one target VM and, for remote PoCs, one lightweight attacker VM. The broker exposes fixed verbs and fixed domain templates. The two VMs share one isolated libvirt network with no host LAN or internet route after provisioning. No container runtime is used.
* **G5. Typed targets.** V1 uses three checked-in `Target` instances in `src/xentry/targets.py`, not a generic YAML pack layer. Each instance declares its image, kernel, resources, actor, setup script and hash, pinned PoC, ordered probe steps, nonce, null actor, evidence channel, retry policy, timeouts, and claim limits. `script_source` is `checked_in` for all three; `generated` is V1.1.
* **G6. Causal evidence.** The runner generates a fresh 128-bit nonce after the freeze, places it through a broker verb that sets owner and mode, and keeps the value runner-only. A null actor runs the same wrapper without the exploit and must not observe the nonce. For remote PoCs, the attacker runs the PoC and the runner observes the target-side nonce. For Dirty Frag, the runner captures host-side evidence and records the guest-attested limit. The LLM cannot return `reproduced` without `nonce_observed`.
* **G7. Execution isolation.** No PoC code is built or executed on the host. Remote PoCs run in the attacker VM as `xentry-guest`. Dirty Frag runs in the target VM as `xentry-guest`; its root shell is spawned by the PoC, not by the broker. All three setup scripts run as `root`, allowlisted by step id. `xentry-guest` has no sudo, setuid, pkexec, shared SSH key, or writable root-owned path. No host mounts, devices, shared folders, or containers.
* **G8. Job lifecycle.** Jobs are asynchronous, cancellable, recoverable, and recorded as an ordered step list plus `outcome` and `cleanup_state`. One job runs at a time; a job may use two VMs. Every path destroys both VMs and the network before validation.
* **G9. Storage and audit.** The per-job attempt directory and append-only JSONL are authoritative. SQLite is a rebuildable index with the DDL below. Failed jobs are retained; secrets are redacted; the audit bundle reconstructs the job.
* **G10. Honest UI.** Job state, verdict, and authority are separate fields. "Succeeded" and "verified" are banned. The agent summary is labeled non-authoritative. The pre-run plan shows the target, attacker (if any), network, nonce path, probe, evidence channel, and caps.
* **G11. Budgets and failure codes.** Per-target time, memory, disk, token, and VM-cycle caps are enforced. Every failure has a closed code and a next action. Retries cover transient infrastructure only.
* **G12. Testability.** A fake broker/driver covers the lifecycle without KVM. Validator fixtures, scripted model clients, a prompt-injection corpus, a null-actor test, a broker-contract test, a budget test, and a kill-and-restart test are part of V1.
* **G13. Operational readiness.** The app runs from a local virtual environment and a systemd user unit. The broker runs as a separate root-owned systemd unit. The database has a schema version, forward-only migrations, a backup before migration, and a documented backup-restore rollback.
* **G14. Scope discipline.** The budget below is binding. Revision 5 raises it to match the owner's choice of all three targets and the attacker VM. Any further growth requires an explicit budget change and an ADR entry.

## Non-Goals

* User accounts, roles, multi-tenancy, or LAN exposure without an SSH tunnel.
* General CVE coverage; V1 supports the three named CVEs.
* Arbitrary PoC adaptation beyond the pinned repository and commit.
* Windows, macOS, browser, GPU, hardware, cloud-only, or network-callback targets.
* Docker or any container runtime in xentry or in target or attacker provisioning.
* Concurrent jobs, more than two VMs per job, more than one target plus one attacker, high availability, or cloud deployment.
* The full v2 contract: deterministic human-authored validators, version-range probes, fixed-build controls, immutable bank versions, scoring, multiple advisory/PoC sources, and the five CLI bank verbs.
* Publication or export, and the license gate.
* ADK sub-agents, long-term memory, the ADK web UI, or model-driven tool selection.
* Generated setup authoring or repair in V1. The setup scripts are checked in; the generated path is V1.1.
* A polished SPA, mobile support, a frontend build chain, a dashboard, or a settings editor.
* Unlimited retries, indefinite retention, or a disk budget beyond the ceiling.
* Automatic exploit re-authoring, dynamic target packs, or a plugin loader.
* Currency display without a versioned pricing table.

## V1 Scope and Budget

The budget is binding and raised for the two-VM/broker decision. The counting rule: "module" means every `.py` file under `src/`, `broker/`, and `scripts/`, including `__init__.py`; tests are counted separately. "Handwritten lines" excludes blank lines, comments, and generated lockfiles.

| Dimension | V1 budget |
| --- | --- |
| Handwritten Python | At most 8,000 lines across at most 44 modules (the headroom covers the broker registry, actor-separation tests, and image-build script) |
| Per-component allocation | Web/API/UI 1,000; runner/queue/cleanup 1,100; broker client and broker 1,500; VM/network/mirror/host evidence 1,300; ingestion/evidence 650; extractor/validator 650; storage/security/events/bundle 800; scripts 650; target/profile instances 350 |
| Templates and static | At most 1,500 lines |
| Tests | At most 4,500 lines |
| Runtime dependencies | At most 18 direct dependencies across the app and broker environments |
| Target definitions | Three checked-in `Target` instances and one shared attacker/network profile |
| Concurrency | One job at a time; at most two VMs per job |
| Peak host memory | GitLab 10 GB (8 target + 2 attacker); PHP2Shell 6 GB (4 + 2); Dirty Frag 3 GB (2 + host evidence) |
| Per-job disk caps | PHP2Shell 25 GB; GitLab 50 GB; Dirty Frag 25 GB; total ceiling 100 GB |
| Per-job time caps | PHP2Shell 90 min; GitLab 120 min; Dirty Frag 90 min; per-step maxima are bounded by the job deadline |
| Token cap | 150,000 tokens per job; per-call cap enforced |
| Setup repair | None in V1; checked-in scripts execute byte-for-byte |
| PoC rerun | One rerun for transient infrastructure failure; never for a failed exploit |
| Effort | Phase 0 two weeks; Phase 1 four weeks; Phase 2 three weeks; Phase 3 two weeks; Phase 4 three weeks |

Budget gates:

* `tests/test_budget.py` counts modules and lines and fails above the cap.
* Each component's allocation is recorded in the file table; a component over its line budget requires an explicit budget change.
* The two-VM and broker lines are inside the broker/VM allocations. There is no unbudgeted privileged unit.

Acceptance numbers:

* Two consecutive clean runs per target: `nonce_observed = true`, the null actor does not observe the nonce, the verdict is `reproduced`, and the authority is `runner_observed+llm_assessed` (remote) or `guest_attested+llm_assessed` (Dirty Frag).
* No completed job lacks a validation row tied to its nonce id.
* Validator fixture gate: at least 18 of 20 labeled fixtures classified correctly; all five known-fail fixtures are `not_reproduced` or `inconclusive`.
* Extractor gate: at least 19 of 20 facts fixtures valid, and 100% of accepted facts cite a resolvable evidence hash.
* Prompt-injection gate: every hostile fixture produces a failed job and no host effect.
* Kill-and-restart gate: no running domain, network, overlay, or ISO after restart; the job is `interrupted`.
* Broker gate: the app has no libvirt connection; every VM/network operation goes through the broker; guest root is allowed only for `setup-*` steps; `collect-host-evidence` is broker-side; the actor is `xentry-guest`.

## Decision Record and Phase 0 Gates

**Owner decisions (2026-11-06):**

* All three targets remain in V1.
* GitLab and PHP2Shell run their PoCs from a lightweight attacker VM.
* Dirty Frag stays in the target VM with host-side evidence.
* System libvirt through a root-owned, fixed-verb broker; no containers.
* Checked-in setup scripts for V1; generated provisioning is V1.1.
* The broker's root-equivalent risk and the LLM validator's false-positive risk are accepted.

These decisions are recorded in `docs/adr/0001-v1-reset.md`. The ADR is a V1 deliverable, not an external resource.

**Phase 0 gates and consequences:**

| Gate | Exit criterion | If it fails |
| --- | --- | --- |
| A. One-VM causality | PHP2Shell and GitLab pass the nonce/null-actor test on one target VM | The attacker VM remains an isolation choice; record the weaker causal claim, or re-scope |
| B. Broker and network | Two VMs boot through the broker on an isolated network; domain UID is not root; AppArmor/seccomp active; nftables default-deny; egress test fails closed; mirror serves the pinned artifacts | Fix the broker or withdraw the VM-boundary claim; do not start Phase 1 |
| C. Dirty Frag host evidence | Host-side channel captures the root-only nonce; tamper analysis states whether the guest can forge it | Use `guest_attested+llm_assessed` or make Dirty Frag `inconclusive` |
| D. Target builds | PHP 8.4.26, GitLab 19.2.5, and the pinned Dirty Frag kernel install and pass readiness | Re-scope the target or raise the budget explicitly |
| E. Host capacity | GitLab 10 GB peak and 100 GB disk fit with the app and broker | Reduce concurrency (already one), raise the host, or drop GitLab |
| F. Extractor | ADK extraction/citation gate passes 20 fixtures | Use the direct LiteLLM runtime |
| G. Artifact provenance | Image, package, kernel, and PoC hashes come from vendor checksums or out-of-band values | Do not pin by first fetch; block Phase 1 |

A failed gate revises the plan before the next phase. It does not become an acceptance surprise.

## Critical User Journeys (CUJs)

### CUJ 1: Submit a remote target

* **Given**: the app, broker, and target instance are configured; preflight passes; no job is running.
* **When**: the user pastes the links, runs Check links, reviews the two-VM plan, and starts.
* **Then**: the runner creates the network, target, and attacker; provisions; builds the PoC in the attacker; runs the null actor and real actor; observes the target-side nonce; destroys both VMs and the network; validates; shows the verdict, authority, nonce id, and evidence.

### CUJ 2: Submit Dirty Frag

* **Given**: the target definition, pinned kernel, and host-evidence channel are configured.
* **When**: the user starts the job.
* **Then**: the runner creates one target VM, installs the kernel, reboots, verifies `uname -r`, builds the PoC, runs the null actor and real actor, captures the root-only nonce through the host channel, destroys the VM, and shows `guest_attested+llm_assessed` with the stated limit.

### CUJ 3: Review a verdict

* **Given**: a completed job.
* **When**: the user opens Job Detail.
* **Then**: runner facts (`nonce_observed`, null-actor result, version/precondition, VM/network ids, nonce id), validator verdict, evidence refs, and the agent summary appear in order; the summary is non-authoritative; the audit bundle is downloadable.

### CUJ 4: Cancel a long GitLab run

* **Given**: GitLab is provisioning or running.
* **When**: the user cancels.
* **Then**: the runner interrupts the current guest command, destroys the attacker, target, and network, writes `cancelled`, and shows the cleanup result. A failed security destroy is `security_cleanup_failed`.

### CUJ 5: Recover after a crash

* **Given**: the worker is killed mid-job.
* **When**: the app starts.
* **Then**: the job is `interrupted`; the broker lists and destroys xentry-managed domains and networks without an active job; stale overlays/ISOs are removed; an orphan banner appears if cleanup cannot finish.

### CUJ 6: Reject an unsupported CVE

* **Given**: a CVE outside the three targets.
* **When**: Check links runs.
* **Then**: the app names the unsupported target, shows the supported set, and creates no VM, network, or model spend.

## Technical Plan (Architecture)

### System shape

```text
Browser
  | HTTP + request-integrity token
  v
Web/API (unprivileged) ── SQLite index ── attempt dir + JSONL
  |
  v
Job runner (one job, one or two VMs)
  |-- fetch/pin evidence (SSRF guard) -> evidence store
  |-- ADK extractor (DeepSeek, no tools) -> Facts
  |-- broker client over Unix socket
  |     |-- isolated network + nftables + artifact mirror
  |     |-- target VM: provision, freeze, nonce, null actor, real actor
  |     |-- attacker VM (remote): build and run the pinned PoC
  |     `-- host-side evidence channel (Dirty Frag)
  |-- destroy attacker, target, network
  |-- validator (direct LiteLLM, no tools, fresh context)
  `-- project outcome/verdict/authority
  v
SSE or polling -> UI
```

### Components and ownership

| Component | Owner | Responsibility |
| --- | --- | --- |
| Web/API | app | Pages, JSON API, SSE, token, CSRF/Origin/Host, UI |
| Job runner | app | Step list, attempts, timeouts, cancellation, retries, cleanup, validator call |
| Broker client | app | Fixed-verb Unix-socket client |
| Broker service | root | libvirt domains/networks, nftables, artifact mirror, SSH exec/copy, snapshots, reboot, host evidence, destroy |
| Fetcher/evidence | app | Source-aware fetch, SSRF guard, content-addressed store |
| Target definitions | app | Three checked-in `Target` instances |
| Extractor | app | ADK + LiteLLM/DeepSeek, no tools |
| Validator | app | Direct LiteLLM, no tools |
| Storage | app | SQLite index, attempt dirs, JSONL |
| UI | app | Four screens, one help modal |

### Broker contract

The broker listens on `/run/xentry/broker.sock`, owned `root:xentry`, mode `0660`, and checks the peer UID. The app never joins `libvirt`.

```text
ensure_network(job_id, network_profile_id) -> network_id
apply_egress_policy(network_id, phase) -> applied
run_egress_test(network_id) -> pass_fail
start_artifact_mirror(job_id, manifest_id) -> mirror_url
stop_artifact_mirror(job_id)
start_target(job_id, target_id, image_id) -> vm_id, guest_ip, domain
start_attacker(job_id, attacker_profile_id, image_id) -> vm_id, guest_ip, domain
exec(vm_id, step_id, params, tty, timeout) -> CommandResult
cancel_exec(vm_id, request_id)
http_probe(vm_id, network_id, port, method, path, timeout, max_bytes) -> HttpResult
proxy_capture(vm_id, network_id, target_port, timeout) -> Artifact
copy_in(vm_id, artifact_id, guest_path) -> sha256
copy_out(vm_id, guest_path) -> artifact_id, sha256
place_nonce(vm_id, nonce_id, path, owner, mode, value) -> sha256
snapshot(vm_id, kind) -> snapshot_id
restore(vm_id, snapshot_id)
reboot(vm_id) -> boot_id
read_host_evidence(vm_id, channel) -> bytes
destroy_vm(vm_id)
destroy_network(network_id)
list_managed() -> domains, networks
```

`exec` takes `step_id`, not arbitrary argv. The broker-owned registry `broker/registry.py` maps each `step_id` to a command template, typed parameters, an allowed user, timeout, retry, evidence, and failure code. The app never sends a template, image path, guest path, or user; unknown ids are rejected with `broker_registry_rejected`. The registry also resolves target, profile, image, and artifact ids. `copy_in`/`copy_out` take artifact ids or guest paths under the job directory. `place_nonce` is the only nonce writer. `http_probe` is the trusted target-side HTTP observation path; the app-side `vm/probes.py` is a plan builder only. `destroy_vm`/`destroy_network` are idempotent. Every verb writes a `broker_calls` row.

The broker creates domains from a fixed template. QEMU runs as a dedicated `xentry-vm` user, not root. The domain has virtio disk/net, serial, no host mounts/devices/display/USB/9p/virtiofs. AppArmor/seccomp is active. If the host cannot run QEMU unprivileged, Gate B fails and the design is revised.

Guest transport is SSH with a per-job key injected by cloud-init. The broker owns `asyncssh`; the app does not. `reboot` waits for SSH and a new boot id.

### Isolated network and artifact mirror

```text
network: xentry-<job_id>, forward mode none, subnet 10.<slot>.0.0/24
target: 10.<slot>.0.10; attacker: 10.<slot>.0.20
mirror: 10.<slot>.0.1:8081 (host bridge gateway, broker-managed)
```

There is no host LAN or internet route. Host access is limited to the broker, the mirror on the bridge gateway, and the loopback port forward.

Provisioning phase: nftables allows target→mirror only; the mirror serves the job's pinned PHP source, GitLab `.deb`, kernel image and modules `.deb`s, and PoC artifacts from `config/artifacts.yaml`. The mirror is a static broker-managed service on the fixed `10.42.0.1:8081`; it serves no apt index. Apt dependencies are baked into the target and attacker images by `scripts/build-images.sh`. After provisioning: default-deny; allow attacker→target on `target_ports` and broker→target SSH/probe; deny all other egress. `run_egress_test` fails closed and logs attempts.

The artifact catalog is the single source of truth for image, package, kernel, and PoC pins. `scripts/fetch-artifacts.sh` seeds it from vendor checksums/signatures and refuses to write a new pin without an out-of-band value. `config/image-manifests.yaml` records the packages baked into each target image; `scripts/build-images.sh` builds the images. The attacker image preinstalls Go and Python `requests`; the PoC fetches nothing at run time.

### Ordered runner steps

The runner is an ordered step list, not a 22-state machine.

```text
1  fetch
2  extract
3  plan
4  create_network
5  create_target
6  provision
7  readiness + version/precondition
8  create_attacker + build_poc        (remote only)
9  freeze
10 place_nonce
11 null_actor
12 probe_null
13 restore or reboot                 (remote: memory restore; Dirty Frag: fresh boot)
14 place_fresh_nonce
15 real_actor
16 target_probe
17 host_evidence                     (Dirty Frag only)
18 destroy_attacker                  (remote only)
19 destroy_target
20 destroy_network
21 validate                          (only after successful evidence)
22 project
```

The contracts' 23-step table and its applicability, probe-dispatch, and post-boot corrections are normative; this list is the high-level order. Each step has a timeout, a guard, and a cleanup action. `jobs.outcome` is `completed`, `failed`, `cancelled`, or `interrupted`. `jobs.cleanup_state` is `pending`, `running`, `done`, or `failed`. A failed, cancelled, or interrupted job goes from the current step to cleanup; it never enters `validate`. `cancel_requested` is persisted; `cancel_exec` interrupts the in-flight guest command. `job_steps` records every step with start/end, state, and reason. Destroy happens before validate on every path.

Retries: one attempt may have one setup repair? No. V1 has no setup repair. A transient fetch failure may retry once; a PoC rerun is allowed only for a classified infrastructure failure; a failed exploit is not retried. Dirty Frag retries use a fresh VM. Every retry starts a new attempt.

### Target definitions

V1 uses typed Python instances, not YAML packs. The field-level model, exact target values, artifact pins, setup-script outlines, and broker registry are in `docs/designs/xentry-v1-contracts.md`; that file is normative.

```text
Target(
  target_id, cve_ids, poc_context: remote|local,
  script_source: checked_in,
  base_image_artifact_id, kernel_artifact_id?,
  resources {vcpu, memory_mb, disk_gb},
  attacker_profile_id?, network_profile_id,
  actor_user: xentry-guest, setup_script_path, setup_sha256,
  expected_version, version_probe_command,
  poc: PocPin{repository, commit, files, sha256, build_step, invocation_step},
  probes: list[ProbeStep{kind, decisive, params, timeout}],
  nonce: NonceSpec{path, owner, mode, value_source: runner},
  null_actor: NullActor{location: attacker|target, step_id, expected: no_nonce},
  evidence_channel: EvidenceChannel{kind, channel},
  retry_policy: {transient_fetch_retries: 1, poc_reruns: 1},
  timeouts: {...}, what_proves, what_does_not_prove
)
```

`ProbeStep.kind` is one of `http_get`, `response_parse`, `pty_session`, `host_serial`, `qmp`. Exactly one step is `decisive`. `target_ports` is a list. `attacker_profile_id` is null for Dirty Frag. `kernel_artifact_id` is null for remote targets. The setup script is hash-checked before execution; there is no author/repair path.

Three instances:

* **PHP2Shell**: target port 8088; attacker with Python; nonce readable by the web user; probe fetches the written nonce; authority `runner_observed+llm_assessed`.
* **GitLab**: target ports 80/443; attacker with Go; nonce owned by `git` outside the document root; probe parses the leaked response; authority `runner_observed+llm_assessed`.
* **Dirty Frag**: no attacker; actor `xentry-guest`; setup installs the pinned kernel, reboots, verifies `uname -r`, installs `gcc`/`make`/libc headers; PoC built and run as `xentry-guest`; the PoC spawns the root shell; the runner attaches as `xentry-guest`; root-only nonce `/root/xentry-nonce` mode 0600; host serial evidence; fresh boot for the real run; authority `guest_attested+llm_assessed`.

### Probe evidence contract

`RunnerContext` fields: `job_id`, `target_id`, `attempt_id`, `vm_id`, `user`, `nonce`, `nonce_path`, `target_ports`, `timeouts`.
`AttackerContext` fields: `job_id`, `target_id`, `attempt_id`, `vm_id`, `user`, `nonce_path`, `target_ip`, `target_ports`, `timeouts`. It never contains the nonce value.
`ProbeEvidence` fields: `kind`, `step_id`, `decisive`, `command`, `stdout_sha256`, `stderr_sha256`, `exit_code`, `http_status`, `body_excerpt`, `nonce_observed`, `nonce_sha256`, `host_channel`, `timestamp`, `raw_path`.

Exactly one probe step is decisive. The runner resolves every evidence reference against the transcript or artifact hash.

### Interfaces

```text
VmDriver (runner-facing):
  create_target, create_attacker, exec(step_id, params, tty, timeout),
  copy_in, copy_out, place_nonce, snapshot, restore, reboot,
  read_host_evidence, destroy_vm, destroy_network, list_managed

BrokerClient: the only VmDriver implementation; same fixed verbs over the Unix socket
GuestExec (broker-internal): SSH exec/copy/PTY, timeout, boot-id wait
HttpProbe (broker-internal): GET/parse against the target private IP
AgentRuntime: extract(excerpts) -> Facts
ValidatorClient: assess(runner_facts, narrative) -> LlmVerdict
```

`VmDriver` is the runner-facing port. `BrokerClient` is its only production adapter; `FakeDriver` is the test adapter. The broker-internal `GuestExec` and `HttpProbe` do not appear in the app.

### Nonce and null actor

* The nonce is 128 bits from `secrets.token_hex(16)`, generated after the freeze, placed by `place_nonce`, and referenced by `nonce_id`/`nonce_sha256`. The `nonces` table records the null and real phases separately; `validations.nonce_id` references the real-phase nonce. The value is never stored in SQLite, the audit bundle, the attacker VM, or the validator prompt.
* The attacker context receives `nonce_path` only. `ProbeContext` is split into `RunnerContext` (secret) and `AttackerContext` (path only).
* The null actor runs the same wrapper without the exploit. It records its location, step id, transcript, and target-side observation. Expected: `nonce_observed = false`.
* The validator receives `nonce_observed` and `nonce_sha256`, never the value. The LLM cannot return `reproduced` when `nonce_observed` is false. The runner stamps `model`/`prompt_hash`.
* For Dirty Frag, the authority is `guest_attested+llm_assessed`; the UI and bundle state that the guest kernel is compromised during the exploit.

### Validator

Direct LiteLLM `deepseek/deepseek-chat`, fixed versioned prompt, temperature 0, no tools, no generator history, no shared state. It receives runner facts (`nonce_observed`, null-actor result, version/precondition, VM/network ids, probe and host-evidence hashes) and labeled untrusted narrative (PoC, setup script, transcripts). It returns `{verdict, reason_code, evidence_refs, explanation}`. The runner validates the schema, resolves every ref, clamps `reproduced` to false when the nonce is false, stamps the model/prompt hash, and stores the validation row with authority and nonce id. The validator may only downgrade a runner-observed positive with a recorded reason and evidence ref (`validator_disagreed`).

### Extractor

ADK + LiteLLM `deepseek/deepseek-chat`, no tools. One call: `extract(excerpts) -> Facts`. The extractor is load-bearing for target admission and the pre-run plan: it identifies the CVE, product, affected range, version evidence, and PoC identity; the runner maps the result to one of the three `Target` instances and rejects a mismatch with `unsupported_target` or `version_unidentified`. `Facts` includes product, affected range, version evidence, protocol/ports, auth, build strategy, PoC context, candidate marker, and artifact candidates, each with an evidence ref and quote. The extractor gate is 19/20 valid facts and 100% citation validity; failure switches to the direct LiteLLM runtime via `XENTRY_AGENT_RUNTIME`. There is no setup author/repair in V1. ADR 0001 records the reversal of ADR 0007: the model is used for extraction, not tool execution.

### Storage and audit

SQLite is a rebuildable index. Attempt directory and JSONL are authoritative.

```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY, cve_id TEXT, target_id TEXT NOT NULL,
  poc_url TEXT NOT NULL, check_id TEXT, bundle_sha256 TEXT,
  outcome TEXT, cleanup_state TEXT NOT NULL DEFAULT 'pending',
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  reason_code TEXT, created_at TEXT NOT NULL, started_at TEXT,
  finished_at TEXT, attempt_dir TEXT NOT NULL, final_attempt_id TEXT,
  agent_summary TEXT,
  CHECK (outcome IN ('completed','failed','cancelled','interrupted') OR outcome IS NULL),
  CHECK (cleanup_state IN ('pending','running','done','failed'))
);
CREATE TABLE attempts (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_no INTEGER NOT NULL,
  attempt_dir TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  failure_code TEXT, previous_attempt_id TEXT,
  nonce_id TEXT, nonce_sha256 TEXT, nonce_path TEXT, nonce_owner TEXT,
  nonce_mode TEXT, nonce_created_at TEXT,
  UNIQUE(job_id, attempt_no),
  FOREIGN KEY(job_id) REFERENCES jobs(id)
);
CREATE TABLE job_steps (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL,
  started_at TEXT, finished_at TEXT, reason_code TEXT,
  UNIQUE(job_id, attempt_id, seq),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE vms (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  role TEXT NOT NULL, domain_name TEXT NOT NULL, state TEXT NOT NULL,
  started_at TEXT, destroyed_at TEXT,
  CHECK (role IN ('target','attacker')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE broker_calls (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL, verb TEXT NOT NULL, params_sha256 TEXT NOT NULL,
  started_at TEXT, finished_at TEXT, status TEXT, result_path TEXT,
  result_sha256 TEXT,
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);
CREATE TABLE validations (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  target_id TEXT NOT NULL, authority TEXT NOT NULL,
  validator_model TEXT NOT NULL, validator_prompt_hash TEXT NOT NULL,
  verdict TEXT NOT NULL, reason_code TEXT,
  nonce_id TEXT NOT NULL, runner_nonce_observed INTEGER NOT NULL,
  null_actor_observed_nonce INTEGER NOT NULL,
  evidence_json TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, ts TEXT NOT NULL,
  CHECK (verdict IN ('reproduced','not_reproduced','inconclusive','not_run')),
  CHECK (authority IN ('runner_observed+llm_assessed','guest_attested+llm_assessed','runner_observed')),
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

The complete DDL, including `job_outcomes`, `nonces`, `link_checks`, indexes, CHECKs, and `PRAGMA foreign_keys`, is in `xentry-v1-contracts.md` section 8. `jobs.final_attempt_id` points to the attempt that produced the validation. A null-actor failure writes `outcome = failed`, `verdict = not_run`, `authority = runner_observed`, `reason_code = null_actor_failed`, and no validation row; the runner-owned outcome is the authoritative source. Raw evidence is written and hashed first; redaction applies to derived copies (validator input, bundle, UI); both hashes are stored. Append-only is enforced by one writer and a per-job lock.

### Web UI and API

```text
POST /api/jobs                  {cve_url, poc_url, check_id} + token
POST /api/links/check          fetch, target match, plan; returns check_id, bundle_sha256
GET  /api/jobs                 list
GET  /api/jobs/{id}            job, outcome, verdict, authority
GET  /api/jobs/{id}/steps      job steps
GET  /api/jobs/{id}/validations validation and evidence refs
GET  /api/jobs/{id}/evidence/{artifact_id}
GET  /api/jobs/{id}/events     SSE with Last-Event-ID
GET  /api/jobs/{id}/events?since= polling
POST /api/jobs/{id}/cancel     + token
GET  /api/jobs/{id}/bundle
POST /api/preflight            + token
GET  /api/system
```

Every non-GET route requires the token and a JSON content type. Token delivery: a 32-byte `xentry_token` in an HttpOnly, SameSite=Strict cookie, plus a double-submit CSRF token in a meta tag and the `X-Xentry-CSRF` header. `check_id` is stored in `link_checks` with a 30-minute TTL and single-use rule; the job stores `bundle_sha256` and fails if the refetched bundle differs. `jobs.cve_id` is filled at plan time; the submit row may be null until extraction. The error envelope and status map are in `xentry-v1-contracts.md`.

The UI has four screens and one help modal. It shows the target and attacker (if any), network, nonce path (not value), probe, evidence channel, caps, runner facts, verdict, authority, and agent summary labeled non-authoritative. It never uses "succeeded" or "verified." All model/PoC/transcript text is autoescaped and inert; a strict CSP is on. The banned-word test scans rendered HTML, JSON, static assets, and bundle text.

### Security and threat model

* **Broker:** root-owned, fixed verbs, peer-UID check, broker-owned registry, typed step commands; guest root only for `setup-*` and `collect-host-evidence`; actor `xentry-guest` has no sudo/setuid/pkexec; domain QEMU as `xentry-vm`; AppArmor profile `deploy/apparmor/xentry-vm` and seccomp; socket 0660. Broker code/venv/config are root-owned; job dirs are `xentry`-owned. The broker risk acceptance is recorded in the ADR and risk table.
* **Network:** isolated libvirt network, no host LAN/internet, artifact mirror only during provisioning, default-deny after, egress test fails closed, attempts logged.
* **VMs:** no host mounts/devices/display/USB/9p/virtiofs; transient; no autostart.
* **PoC:** host stores the archive as opaque bytes; extraction/build only in the attacker or target VM; no host execution.
* **Dirty Frag:** PoC-spawned root shell, runner attaches as `xentry-guest`, host serial evidence, mandatory destroy, guest-attested authority.
* **Prompt injection:** extractor sees excerpts; no fetch/execute tools; validator sees labeled data with no tools; hostile fixtures must fail safely.
* **SSRF:** http/https only; connect to the validated IP; reject loopback/private/link-local/multicast/metadata on every redirect; `trust_env=False`; byte/time caps.
* **UI:** autoescaping, inert logs, CSP, Host/Origin, token, JSON only. A local process/WSL2 limitation is documented.
* **Egress:** DeepSeek data egress disclosed in UI/help; validator bundle sends nonce observation and hash, not value; raw attacker text minimized.
* **No containers.**

**Risks and mitigations:**

| Risk | Impact | Mitigation | Residual | Owner |
| --- | --- | --- | --- | --- |
| Broker root compromise | Host compromise | Fixed verbs, peer UID, typed steps, AppArmor, root-only Dirty Frag | Root-equivalent broker accepted | owner |
| Guest escape | Host compromise | QEMU as `xentry-vm`, minimal devices, AppArmor/seccomp | KVM escape remains | owner |
| Dirty Frag guest attestation | False root evidence | Host serial, fresh boot, null actor, distinct authority | Guest kernel can forge; accepted | owner |
| LLM validator fooled | False verdict | Runner nonce precondition, clamp, fixtures | False positive remains | owner |
| Prompt injection | Bad script/probe | No tools, facts only, VM/egress | Text-level injection remains | owner |
| SSRF | Internal access | Validated-IP connect, redirect checks | DNS rebinding residual | owner |
| Supply chain | Wrong image/package | Vendor hashes, catalog, mirror | Upstream compromise | owner |
| Disk exhaustion | Job failure | 100 GB ceiling, per-job caps, retention | None if enforced | owner |

### What each target proves and does not prove

* **PHP2Shell:** RCE in the pinned PHP 8.4.26/Apache build through a target-side nonce observed after an attacker-VM request. Does not prove other builds/SAPIs or real-world exploitability.
* **GitLab:** unauthenticated file read of the runner's nonce through an attacker-VM request. Does not prove other versions, other paths, or broader data access.
* **Dirty Frag:** a root-only nonce observed through the host channel after the local exploit, with authority `guest_attested+llm_assessed` because the guest kernel is compromised. Does not prove persistence, other kernels, or forge-proof evidence.
* **Overall:** a lab reproduction with a runner-observed nonce and an LLM-assessed verdict; not a deterministic proof and not a production risk assessment.

## Alternatives Considered

Each heading names the rejected option; the chosen path is in the Reason for Rejection.

### 1. Rejected: agent-owned tool trajectory (chosen: runner-owned sequence)

* **Pros:** flexible tool choice.
* **Cons:** job state becomes model output; validate/destroy can be skipped.
* **Reason for Rejection:** the runner owns the ordered steps; the model extracts only. A fully deterministic pipeline was also rejected because it removes the requested LLM capability.

### 2. Rejected: host execution or one VM for remote PoCs (chosen: target + attacker VM)

* **Pros:** host execution is simple; one VM is cheaper.
* **Cons:** host execution risks the workstation and key; one VM shares the target kernel.
* **Reason for Rejection:** attacker VM for remote PoCs; Dirty Frag is local with host evidence. Docker was rejected (host kernel, daemon).

### 3. Rejected: human-authored deterministic validators (chosen: LLM validator with runner precondition)

* **Pros:** deterministic, repeatable.
* **Cons:** validator registry and human burden; the owner chose the LLM session.
* **Reason for Rejection:** runner-owned nonce + null actor + independent LLM; the LLM cannot pass without `nonce_observed`. Full v2 oracle deferred.

### 4. Rejected: session libvirt or direct QEMU (chosen: system libvirt broker)

* **Pros:** session/direct QEMU avoid a root daemon.
* **Cons:** they do not provide the two-VM network, nftables, and host-evidence control in one place.
* **Reason for Rejection:** system libvirt through a fixed-verb broker; the broker risk is accepted and budgeted. Direct QEMU remains a reuse candidate if the broker gate fails.

### 5. Rejected: per-run generated setup scripts (chosen: checked-in scripts for V1)

* **Pros:** generated scripts exercise the autonomous flow.
* **Cons:** a reactive or malicious setup can manufacture evidence; the reviewed hash would not describe the run.
* **Reason for Rejection:** first three scripts are checked in and hash-verified; generated provisioning is V1.1 with a real fourth target.

### 6. Rejected: ADK setup author/repair (chosen: ADK extractor only)

* **Pros:** ADK for the requested agent path.
* **Cons:** author/repair has no V1 consumer and conflicts with checked-in scripts.
* **Reason for Rejection:** ADK is load-bearing only for extraction; setup author/repair moves to V1.1.

### 7. Rejected: YAML target packs (chosen: three typed Python instances)

* **Pros:** packs are data-driven for future targets.
* **Cons:** a four-source schema for three fixed targets; the schema could not express the packs.
* **Reason for Rejection:** `src/xentry/targets.py` with typed instances; the YAML pack schema is a V1.1 input.

### 8. Rejected: SQLite for everything (chosen: attempt dirs/JSONL + index)

* **Pros:** one store.
* **Cons:** large logs and transcripts bloat SQLite; migrations couple retention.
* **Reason for Rejection:** files authoritative, SQLite rebuildable.

### 9. Rejected: blocking request or separate worker (chosen: one process + background worker)

* **Pros:** simple/blocking; separate worker isolates restarts.
* **Cons:** blocking loses long jobs; separate worker adds a broker/supervisor.
* **Reason for Rejection:** one process with a durable claim; split later if needed.

### 10. Rejected: Docker as the remote-PoC boundary (chosen: attacker VM)

* **Pros:** lightweight.
* **Cons:** shares the host kernel and requires the daemon/socket; contradicts the no-container rule.
* **Reason for Rejection:** attacker VM provides a separate kernel; no containers.

## Non-Functional Requirements

* **Security and privacy:** loopback, token, CSRF/Origin/Host, SSRF validated-IP connect, isolated network, broker fixed verbs, no host secrets, DeepSeek egress disclosure/minimization, no containers.
* **Performance:** one job; two VMs for remote; GitLab 10 GB peak; PHP 6 GB; Dirty Frag 3 GB; SSE plus polling; per-step timeouts.
* **Reliability:** ordered steps, persisted cancel, idempotent destroy, orphan sweep for domains/networks, interrupted marking, broker idempotency.
* **Storage:** attempt dirs/JSONL authoritative; SQLite rebuildable; 100 GB ceiling; per-job caps; retention window.
* **Rollout:** app user unit; broker root unit; forward-only migrations with backup; backup-restore rollback; newer schema refuses to start; upgrade marks in-flight jobs interrupted.

## Additional Resources

* `concepts_brief.md` — the V1 brief.
* `consolidated_review_report.md` and `consolidated_review_report_rev2.md` with the stage reports — the review trail.
* `docs/adr/0001-v1-reset.md` — the decision record (V1 deliverable).
* `docs/designs/xentry-v1-contracts.md` — the normative field-level contracts, registry, step table, target values, reason codes, DDL/API, tests, and phase map.
* The pinned PoC repositories and the CVE records for CVE-2026-109618, CVE-2026-85706, and CVE-2026-43500.

## Future Improvements

* Full harness-owned deterministic verification: version probes, fixed-build controls, immutable bank.
* Generated provisioning with a fourth real target and no human review.
* More targets without pipeline changes; Windows/client-side only with a new isolation design.
* Cached images, multiple concurrent jobs, LAN auth, model-free revalidation, cost dashboard.

## Detailed Implementation Plan

### Fixed defaults

* Python 3.12; `uv` with `uv.lock`; FastAPI, Jinja2, `sse-starlette`, `httpx`, Pydantic, PyYAML, `google-adk`, `litellm` in the app; `virsh`/libvirt-clients, `asyncssh`, PyYAML in the broker.
* Host: Ubuntu 24.04.4; libvirt 10+ (tested on 12), QEMU 8.2+ (tested on 10.2.1); nftables; cloud-image-utils; qemu-img; ssh-keygen; systemd.
* App user `xentry`; broker root; guest actor `xentry-guest`; QEMU user `xentry-vm`.
* One job at a time; target + attacker for remote; target only for Dirty Frag.
* GitLab CE 19.2.5; Dirty Frag `6.17.0-23-generic`; PHP 8.4.26.
* Checked-in scripts; extractor-only ADK; validator direct LiteLLM.

### Repository files to create or modify

| File | Type | Required contents | Budget |
| --- | --- | --- | --- |
| `pyproject.toml` | Create | Metadata, app/broker extras, tool config, uv. | 40 |
| `uv.lock` | Create | Pinned dependency graph. | generated |
| `README.md` | Create | Install, broker, images, `.env`, run, systemd, security, limits. | 200 |
| `.env.example` | Modify | Broker socket, artifact catalog, caps, absolute paths. | 40 |
| `.gitignore` | Modify | `.env`, `var/`, images, ISOs, keys. | 20 |
| `deploy/xentry.service` | Create | App user unit. | 30 |
| `deploy/xentry-broker.service` | Create | Root broker unit, restricted filesystem/caps. | 40 |
| `deploy/apparmor/xentry-vm` | Create | QEMU AppArmor profile. | 80 |
| `scripts/fetch-artifacts.sh` | Create | Vendor-seeded catalog, image/package/kernel/PoC download, hashes. | 120 |
| `scripts/migrate.py` | Create | Forward-only migrations, backup, newer-schema refusal. | 60 |
| `scripts/run-dev.sh` | Create | `uv sync`, load `.env`, uvicorn. | 30 |
| `scripts/preflight.py` | Create | CLI preflight wrapper. | 40 |
| `scripts/run_target_e2e.py` | Create | Real-VM acceptance runner. | 120 |
| `scripts/build-images.sh` | Create | Build target/attacker images with apt deps; hash pins. | 150 |
| `scripts/install-apparmor.sh` | Create | Install QEMU AppArmor profile. | 40 |
| `scripts/rebuild_index.py` | Create | Rebuild SQLite from journal/job dirs. | 80 |
| `config/artifacts.yaml` | Create | Single source: image, package, kernel, PoC URLs + SHA-256 + provenance. | 120 |
| `config/image-manifests.yaml` | Create | Packages baked into each target/attacker image; build manifest. | 120 |
| `prompts/extract.md` | Create | `Facts` schema, citations, no tools. | 100 |
| `prompts/validator.md` | Create | Runner facts vs narrative, JSON verdict, no tools. | 100 |
| `prompts/README.md` | Create | Versioning/hash/fixtures. | 30 |
| `targets/php2shell/setup.sh` | Create | Hand-reviewed PHP 8.4.26/Apache build, hash-pinned. | 150 |
| `targets/gitlab/setup.sh` | Create | Pinned GitLab 19.2.5 Omnibus install. | 120 |
| `targets/dirtyfrag/setup.sh` | Create | Pinned kernel, reboot, `uname -r`, gcc/make. | 120 |
| `targets/README.md` | Create | Checked-in script rules, hash verification, no author/repair. | 40 |
| `migrations/001_initial.sql` | Create | DDL above, indexes, constraints. | 150 |
| `migrations/README.md` | Create | Forward-only, backup, rollback by restore. | 30 |
| `src/xentry/__init__.py` | Create | Version. | 5 |
| `src/xentry/cli.py` | Create | Console entry point; `xentry cleanup --force`/`--status`. | 80 |
| `src/xentry/config.py` | Create | Settings, absolute paths, modes, caps, broker socket. | 120 |
| `src/xentry/models.py` | Create | Field-complete `Facts`, `Target`, `ProbeStep`, `PocPin`, `NonceSpec`, `NullActor`, `EvidenceChannel`, `RunLimits`, `VmProfile`, `CommandResult`, `SnapshotRef`, `HttpResult`, `Artifact`, `Manifest`, `ClassifiedLog`, `LlmVerdict`. | 250 |
| `src/xentry/targets.py` | Create | Three `Target` instances. | 250 |
| `src/xentry/profiles.py` | Create | Attacker and network profile instances. | 80 |
| `src/xentry/db.py` | Create | SQLite factory, WAL, migrations, repositories, projections. | 200 |
| `src/xentry/security.py` | Create | Token, CSRF/Origin/Host, CSP, redaction. | 120 |
| `src/xentry/events.py` | Create | JSONL schema, writer, SSE formatting, backfill. | 120 |
| `src/xentry/queue.py` | Create | Claim, worker lock, cancel flag, recovery. | 100 |
| `src/xentry/runner.py` | Create | Ordered steps, attempts, timeouts, cleanup, validator call. | 450 |
| `src/xentry/broker.py` | Create | Fixed-verb broker client. | 150 |
| `src/xentry/cleanup.py` | Create | Orphan domains/networks, overlays, ISOs, interrupted jobs. | 120 |
| `src/xentry/fetch.py` | Create | SSRF-safe fetch, connect-to-validated-IP. | 120 |
| `src/xentry/sources.py` | Create | Three fixed CVE inputs, pinned PoC resolution, generic fallback. | 150 |
| `src/xentry/evidence.py` | Create | Content-addressed store, quote checks, bundle cap. | 100 |
| `src/xentry/agent.py` | Create | `AgentRuntime.extract`, ADK, direct LiteLLM fallback. | 120 |
| `src/xentry/validator.py` | Create | Runner facts bundle, direct LiteLLM, schema, clamp. | 150 |
| `src/xentry/bundle.py` | Create | Audit bundle and hash manifest. | 100 |
| `src/xentry/preflight.py` | Create | Broker, KVM, memory, disk, artifacts, DeepSeek, DB, bind, orphans. | 120 |
| `src/xentry/web/__init__.py` | Create | Package marker. | 5 |
| `src/xentry/web/app.py` | Create | FastAPI app, lifespan, middleware, templates/static. | 150 |
| `src/xentry/web/routes.py` | Create | UI/API routes, check store, error envelope. | 200 |
| `src/xentry/web/sse.py` | Create | SSE backfill/heartbeat. | 80 |
| `src/xentry/web/schemas.py` | Create | Request/response models. | 100 |
| `src/xentry/web/deps.py` | Create | Settings, DB, token, job context. | 60 |
| `src/xentry/vm/__init__.py` | Create | Package marker. | 5 |
| `src/xentry/vm/driver.py` | Create | `VmDriver` protocol, value objects. | 100 |
| `src/xentry/vm/broker_driver.py` | Create | Broker-backed driver. | 120 |
| `src/xentry/vm/fake_driver.py` | Create | Fake two-VM driver. | 150 |
| `src/xentry/vm/probes.py` | Create | Runner-owned probe primitives. | 150 |
| `broker/__init__.py` | Create | Package marker. | 5 |
| `broker/main.py` | Create | Socket server, peer UID, verb dispatch. | 150 |
| `broker/libvirt_ops.py` | Create | Domains, snapshots, reboot, destroy. | 300 |
| `broker/network_ops.py` | Create | Isolated network, nftables, egress test, mirror lifecycle. | 250 |
| `broker/exec_ops.py` | Create | SSH exec/copy/PTY, place_nonce, cancel. | 250 |
| `broker/host_evidence.py` | Create | Serial/QMP evidence. | 120 |
| `broker/profiles.py` | Create | Domain XML, image resolution, guest IP. | 150 |
| `broker/registry.py` | Create | Broker-owned target/step/image/artifact registry and validation. | 200 |
| `broker/proxy.py` | Create | Per-job TCP proxy and captured target-side response evidence. | 150 |
| `templates/base.html` | Create | Layout, CSP, token, nav. | 80 |
| `templates/new_job.html` | Create | Links, check, plan, start. | 100 |
| `templates/jobs.html` | Create | List state/verdict/authority. | 60 |
| `templates/job_detail.html` | Create | Steps, facts, verdict, evidence, summary. | 120 |
| `templates/system.html` | Create | Preflight, orphans, caps. | 60 |
| `templates/help_modal.html` | Create | Help modal. | 40 |
| `static/app.css` | Create | Accessible layout. | 100 |
| `static/app.js` | Create | Token-aware fetch, SSE, polling, filters, cancel, bundle. | 150 |
| `tests/conftest.py` | Create | Temp dirs, DB, fake broker/driver, scripted model. | 120 |
| `tests/test_budget.py` | Create | Module/line/dependency count gate. | 60 |
| `tests/test_migrations.py` | Create | Forward migration, backup/restore, newer-schema refusal. | 80 |
| `tests/test_actor_separation.py` | Create | Actor cannot sudo/read root nonce/write service binary; Dirty Frag null actor. | 100 |
| `tests/test_steps.py` | Create | Step order, guards, outcomes, cleanup, no validate on failure. | 120 |
| `tests/test_broker_contract.py` | Create | Fixed verbs, step ids, user/root allowlist, peer UID, idempotent destroy. | 150 |
| `tests/test_network_mirror.py` | Create | Isolated network, mirror, default-deny, egress failure, offline packages. | 150 |
| `tests/test_two_vm_runner.py` | Create | Remote/local paths, nonce, null actor, destroy before validate. | 180 |
| `tests/test_nonce_secret.py` | Create | Nonce value absent from attacker/validator/bundle/DB. | 80 |
| `tests/test_queue_recovery.py` | Create | Kill/restart, interrupted, orphan sweep. | 100 |
| `tests/test_fetch_ssrf.py` | Create | Private/metadata rejection, validated-IP connect, redirect, caps. | 100 |
| `tests/test_sources.py` | Create | Three fixed inputs, PoC pin, generic fallback. | 80 |
| `tests/test_evidence.py` | Create | Store, quote checks, bundle cap. | 80 |
| `tests/test_targets.py` | Create | Typed instances, hash checks, probe/decisive, no target-id branches. | 100 |
| `tests/test_agent_contract.py` | Create | Extractor only, no tools, citations, gate fixture. | 80 |
| `tests/test_validator.py` | Create | Runner facts, nonce clamp, authority, evidence refs, egress minimization. | 100 |
| `tests/test_security.py` | Create | Token all mutations, CSRF/Origin/Host, CSP, redaction, no secrets. | 100 |
| `tests/test_ui_vocabulary.py` | Create | Rendered HTML/JSON/static/bundle banned words; state/verdict/authority. | 80 |
| `tests/test_prompt_injection.py` | Create | Hostile fixtures fail safely with no host effect. | 80 |
| `tests/test_vm_libvirt.py` | Create | Gated real two-VM smoke: broker, network, boot, exec, snapshot, reboot, destroy. | 150 |
| `tests/test_bundle.py` | Create | Reconstruction, hashes, no nonce value/secrets. | 80 |
| `tests/fixtures/` | Create | NVD/GitHub/transcript/injection fixtures and labels. | 300 |
| `docs/adr/0001-v1-reset.md` | Create | Two-VM, broker, checked-in scripts, validator, no-container, budget. | 120 |
| `docs/designs/xentry-v1-contracts.md` | Create | Field-level models, registry, step table, target values, reason codes, DDL/API, tests, phase map. | docs |
| `docs/security/threat-model.md` | Create | Broker, network, VM, Dirty Frag, SSRF, XSS, DeepSeek, host archive, supply chain. | 150 |
| `docs/security/dirtyfrag-evidence.md` | Create | Host-channel mechanism, capture timing, tamper analysis. | 100 |
| `docs/designs/xentry-v1.md` | Modify | This revision. | — |
| `docs/designs/SITEMAP.md` | Modify | Register revision 3. | 20 |

Per-file budgets are planning estimates; the component allocations and the 8,000-line cap are the binding gates. The companion contracts file `docs/designs/xentry-v1-contracts.md` is normative and supplies the field-level models, registry, step table, target values, reason codes, DDL additions, API, test cases, and phase map.

### Host prerequisites

* Ubuntu 24.04.4 host; `libvirt-daemon-system`, `libvirt-clients`, QEMU 8.2+, `nftables`, `cloud-image-utils`, `qemu-img`, `openssh-client`, Python 3.12, `uv`, `systemd`.
* App user `xentry`; broker root unit; guest actor `xentry-guest`; QEMU user `xentry-vm`; broker socket `root:xentry 0660`; app not in `libvirt`.
* App env: FastAPI, Jinja2, sse-starlette, httpx, Pydantic, PyYAML, google-adk, litellm, uvicorn. Broker env: libvirt-clients/`virsh`, asyncssh, PyYAML. Dev: pytest, pytest-asyncio, pytest-cov, ruff, mypy, uvicorn.
* Memory admission: GitLab 10 GB, PHP 6 GB, Dirty Frag 3 GB; disk 100 GB; per-job caps above.
* WSL2: `/dev/kvm`, libvirtd, systemd lingering, monotonic clock.

### Verification plan

The per-file test cases, fixture schemas, and skip markers are in `xentry-v1-contracts.md` section 13.

* **Build:** `uv sync --extra app --extra broker --extra dev`; `python -m compileall src broker scripts`.
* **Budget:** `pytest -q tests/test_budget.py`; module/line/dependency caps.
* **Unit:** `pytest -q`; fake broker/driver covers remote and local paths.
* **Static:** `ruff check src broker scripts tests`, `ruff format --check`, `mypy src broker`.
* **Coverage:** `pytest --cov=src/xentry --cov=broker --cov-fail-under=80`.
* **Broker:** fixed verbs, step-id allowlist, root-only Dirty Frag, peer UID, idempotent destroy, domain UID, AppArmor/seccomp.
* **Network/mirror:** two-VM isolated network, mirror reachability during provisioning, default-deny after, egress test fail-closed, offline package set, no host LAN.
* **Nonce:** value absent from DB/attacker/validator/bundle; nonce id/hash recorded; fresh nonce after restore; null actor no nonce.
* **Two-VM:** PHP2Shell and GitLab two clean runs each; destroy before validate; attacker transcript not the pass condition.
* **Dirty Frag:** fresh boot, `uname -r`, PoC-spawned root shell, host serial evidence, `guest_attested` authority, mandatory destroy.
* **Security:** token all mutations, CSRF/Origin/Host, CSP, SSRF validated-IP, prompt injection, DeepSeek egress minimization.
* **Recovery:** kill/restart; no domain/network/overlay/ISO remains; job interrupted.
* **Acceptance:** two clean runs per target; validator/extractor gates; broker/network/nonce/budget gates; UI vocabulary.

### Phases

* **Phase 0 (2 weeks):** broker registry/libvirt/network/mirror/exec/host evidence, image build, AppArmor, artifact provenance, ADK extractor gate, prior-tree reuse spike. Gates B, C, D, E, F, G pass; Gate A is measured in Phase 1.
* **Phase 1 (4 weeks):** app/API/storage, step runner, fake driver, UI, token/SSRF, nonce, PHP2Shell target + attacker. Acceptance: Gate A recorded; two clean runs; null actor no nonce; no orphan.
* **Phase 2 (3 weeks):** GitLab target + attacker, long-job UX, cancel/recovery. Acceptance: two clean runs; nonce; teardown.
* **Phase 3 (2 weeks):** Dirty Frag target, kernel, reboot, host evidence, actor separation. Acceptance: two clean runs; guest-attested authority; post-boot `uname -r`; no orphan.
* **Phase 4 (3 weeks):** prompt-injection corpus, broker/network security, budget gates, bundle, upgrade/restore, full acceptance.

Phase 0 failures revise the plan before the next phase. The 14-week effort includes the two-VM and broker work; any further growth requires a budget change and an ADR entry.
