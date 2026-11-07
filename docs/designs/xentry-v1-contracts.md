# xentry V1 — Revision 5 Contracts

**Companion to:** `docs/designs/xentry-v1.md`
**Status:** Proposed (Revision 5 contracts)
**Date:** 2026-11-06

This file is normative. Where the main design and this file differ, this file wins. It supplies the field-level models, broker registry, runner step table, target values, setup-script outlines, reason codes, API contracts, DDL additions, test cases, and phase mapping that the revision-3 focused review found missing.

## Revision 5 corrections (normative)

This section supersedes any conflicting text in the sections below or in the main design.

### A. Registry completion

```text
profiles: isolated, target-php2shell, target-gitlab, target-dirtyfrag, attacker-remote
images:   ubuntu-24.04-target, ubuntu-24.04-dirtyfrag, ubuntu-24.04-attacker

image_artifacts:
  ubuntu-24.04-target     -> ubuntu-target-image
  ubuntu-24.04-dirtyfrag  -> ubuntu-dirtyfrag-image
  ubuntu-24.04-attacker   -> ubuntu-attacker-image

build input (not broker-served): ubuntu-base-image -> vendor Ubuntu 24.04 cloud image

steps added: build-poc-php
broker-side (not a guest step): collect-host-evidence
```

* `http_probe(vm_id, network_id, port, method, path, timeout_s, max_bytes) -> HttpResult`. The broker resolves the target IP from `vm_id` and verifies the VM belongs to `network_id`; the caller does not supply `target_ip`.
* `proxy_capture(vm_id, network_id, target_port, timeout_s) -> Artifact`. The broker runs a per-job TCP proxy between the attacker and the target, records both directions, and returns the capture artifact. GitLab's decisive target-side evidence is parsed from this capture, not the attacker transcript.
* `copy_in(vm_id, artifact_id, guest_rel_path) -> sha256`. The broker owns the absolute destination under the job directory; the app supplies only a relative path. Absolute paths and `..` are rejected with `broker_registry_rejected`.
* `Target.base_image_artifact_id` accepts an image id that the registry maps to an artifact id; `create_target`/`create_attacker` accept image ids only.
* Registry-completeness tests: every `Target` id, image id, profile id, step id, and artifact id resolves; unknown ids are rejected; off-network `http_probe` and traversal `copy_in` are rejected.

### B. Privilege and root transport

* Cloud-init creates two guest accounts: `root` (key-only) and `xentry-guest`. The broker holds a per-job root key and a per-job actor key; the app holds neither. `root` gets the root key in `authorized_keys`; `xentry-guest` gets the actor key. `PermitRootLogin prohibit-password`, `PasswordAuthentication no`.
* `setup-*` steps run as `root` via the broker's root key. `run-poc-*`, `null-*`, and `readiness-*` steps run as `xentry-guest` via the actor key. `collect-host-evidence` is broker-side over the host serial/QMP channel, not a guest root step.
* `xentry-guest` has no sudo, setuid, pkexec, shared SSH key, or writable root-owned path. `place_nonce` runs as broker root and writes the nonce at the target's declared path/owner/mode.
* The host app user `xentry` and the guest actor `xentry-guest` are distinct. Any remaining `xentry` guest-actor reference in the main document is superseded by `xentry-guest`.
* `tests/test_actor_separation.py` asserts the actor restrictions, the root-key-only login, and that `collect-host-evidence` is not a guest command.

### C. Target values

| Field | PHP2Shell | GitLab | Dirty Frag |
| --- | --- | --- | --- |
| image id | `ubuntu-24.04-target` | `ubuntu-24.04-target` | `ubuntu-24.04-dirtyfrag` |
| kernel | distro | distro | `6.17.0-23-generic` |
| resources | 2 vCPU, 4 GB, 25 GB | 4 vCPU, 8 GB, 50 GB | 2 vCPU, 2 GB, 25 GB |
| attacker | 2 vCPU, 2 GB, 10 GB, Python + requests | 2 vCPU, 2 GB, 10 GB, Go | none |
| target_ports | `[8088]` | `[80, 443]` | `[]` |
| nonce | `/var/lib/xentry/nonce`, owner `www-data`, mode `0640` | `/var/opt/gitlab/xentry-nonce`, owner `git`, mode `0640` | `/root/xentry-nonce`, owner `root`, mode `0600` |
| decisive probe | `http_probe` port 8088, path `/xentry-leak.txt`, 10 s | `proxy_capture` ports 80/443, parse nonce SHA-256, 30 s | `pty_session` + `read_host_evidence`, channel `org.xentry.evidence.0`, 60 s |
| null actor | attacker, step `null-php`, expected no nonce | attacker, step `null-gitlab`, expected no nonce | target, step `null-dirtyfrag`, expected no host root shell/nonce |
| PoC files | `exploit.py` | `CVE-2026-85706.go` | `exp.c` |
| build step | `build-poc-php` | `build-poc-gitlab` | `setup-dirtyfrag` (single owner) |
| invocation | `run-poc-php` | `run-poc-gitlab` | `run-poc-dirtyfrag` |
| evidence channel | `target_probe/http` | `proxy_capture` | `host_serial` |
| timeouts (boot/provision/readiness/poc/validate) | 120/900/120/120/120 s | 120/1800/300/180/180 s | 120/1200/300/120/120 s |
| setup_sha256 / PoC SHA-256 / commit | Gate G | Gate G | Gate G |

`Target.target_ports: list[int]` is part of the model. Gate G records the external image/package/PoC hashes and commits in `config/artifacts.yaml`; implementation does not start until Gate G passes.

### D. Step table corrections

The contracts' 23-step table is the single list. Applicability:

* Remote only: `create_attacker`, `build_poc`, `destroy_attacker`, `proxy_capture` (GitLab's decisive probe), `probe_gitlab_response`.
* Local only: `host_evidence`.
* Dirty Frag only: `reboot_dirtyfrag` and a post-boot `readiness-dirtyfrag` + `uname -r` row after `restore_or_reboot`.
* All targets: fetch, extract, plan, create_network, create_target, provision, readiness, freeze, place_nonce, null_actor, probe_null, place_fresh_nonce, real_actor, target_probe, destroy_target, destroy_network, validate, project.

Probe dispatch:

| Probe | Mechanism | Arguments | Decisive output |
| --- | --- | --- | --- |
| `probe-php-http` | broker `http_probe` | vm_id, network_id, 8088, GET `/xentry-leak.txt` | `ProbeOutcome.nonce_observed` + body hash |
| `probe-gitlab-response` | broker `proxy_capture` + runner parser | vm_id, network_id, 80/443 | `ProbeOutcome.nonce_observed` + capture hash |
| `probe-dirtyfrag-pty` | broker PTY + `read_host_evidence` | vm_id, channel `org.xentry.evidence.0` | `ProbeOutcome.nonce_observed` + host bytes hash |

`ProbeOutcome`: `{step_id, kind, nonce_observed, decisive_evidence_sha256, parser, raw_path, ts}`. The runner writes it; the validator receives the outcome, not a free-form claim.

Other corrections:

* `freeze` uses `kind=memory` for remote targets; Dirty Frag takes no snapshot and uses a fresh boot.
* Dirty Frag's PoC is built once by `setup-dirtyfrag`; `build_poc` is skipped for local targets.
* `target_probe` for GitLab uses the proxy capture; PHP uses `http_probe`; Dirty Frag uses the PTY plus host serial.
* The outcome projector writes `job_outcomes` for every terminal outcome. `validate` runs only after successful evidence; failed/cancelled/interrupted jobs project `not_run`/`inconclusive` without a validation row.
* `collect-host-evidence` is broker-side; `StepSpec.allowed_users` does not include it as a guest root step.

### E. Missing schemas

Add these field-complete models:

| Model | Fields |
| --- | --- |
| `ProbeEvidence` | `step_id:str`, `kind:enum`, `command:str?`, `stdout_sha256:str?`, `stderr_sha256:str?`, `exit_code:int?`, `http_status:int?`, `body_sha256:str?`, `body_excerpt:str?`, `nonce_observed:bool`, `nonce_sha256:str?`, `host_channel:str?`, `raw_path:str`, `ts:str` |
| `RunnerContext` | `job_id:str`, `target_id:str`, `attempt_id:str`, `vm_id:str`, `user:str`, `nonce:str`, `nonce_path:str`, `target_ports:list[int]`, `timeouts:Timeouts` |
| `AttackerContext` | `job_id:str`, `target_id:str`, `attempt_id:str`, `vm_id:str`, `user:str`, `nonce_path:str`, `target_ip:str`, `target_ports:list[int]`, `timeouts:Timeouts`; no nonce value |
| `ProbeOutcome` | `step_id:str`, `kind:enum`, `nonce_observed:bool`, `decisive_evidence_sha256:str`, `parser:str`, `raw_path:str`, `ts:str` |
| `JobRequest` | `cve_url:HttpUrl`, `poc_url:HttpUrl`, `check_id:str` |
| `JobResponse` | `job_id:str`, `state:str`, `outcome:str?`, `verdict:str?`, `authority:str?`, `created_at:str` |
| `JobList` | `items:list[JobResponse]`, `next_cursor:str?` |
| `JobDetail` | `job:JobResponse`, `target_id:str`, `steps:list[StepView]`, `validation:ValidationView?`, `outcome_record:JobOutcome?` |
| `StepView` | `seq:int`, `name:str`, `state:str`, `started_at:str?`, `finished_at:str?`, `reason_code:str?` |
| `ValidationView` | `verdict:str`, `authority:str`, `reason_code:str?`, `nonce_id:str`, `evidence_refs:list[str]` |
| `PlanView` | `check_id:str`, `cve_id:str`, `target_id:str`, `target_profile:str`, `attacker_profile:str?`, `network:str`, `probe:str`, `caps:dict`, `poc_commit:str` |
| `PreflightView` | `checks:list[dict]`, `ok:bool`, `refused_reason:str?` |
| `SystemView` | `orphans:list[ManagedResource]`, `caps:dict`, `version:str` |
| `BundleInfo` | `job_id:str`, `path:str`, `sha256:str`, `bytes:int` |
| `SSEEvent` | `event:enum(state,log,step,validation,done)`, `id:str`, `ts:str`, `data:dict` |
| `JournalRecord` | `seq:int`, `job_id:str`, `attempt_id:str`, `type:str`, `ts:str`, `payload:dict`, `prev_hash:str?` |
| `RecoveryReport` | `interrupted:list[str]`, `destroyed:list[ManagedResource]`, `errors:list[str]` |
| `CleanupReport` | `destroyed:list[ManagedResource]`, `failed:list[ManagedResource]`, `blocked:bool` |
| `ManagedResource` | `job_id:str`, `role:enum(target,attacker,network)`, `name:str`, `state:str`, `created_at:str` |
| `AuthError` | `code:enum(token_missing,token_invalid,csrf_invalid,origin_invalid,host_invalid)`, `message:str` |

API status map adds 401 (`token_missing`/`token_invalid`) and 403 (`csrf_invalid`/`origin_invalid`/`host_invalid`). SSE event names and journal `type` values are enumerated in `web/sse.py` and `events.py`; the journal is append-only with `prev_hash`.

### F. DDL and reason-code corrections

* `job_steps` includes `step_id TEXT NOT NULL` (registry step id).
* `validations.authority` is only `runner_observed+llm_assessed` or `guest_attested+llm_assessed`. `runner_observed` lives only in `job_outcomes`.
* `nonces` is authoritative; the `attempts` nonce columns are removed from the canonical DDL. `validations.nonce_id` references the real-phase nonce.
* `jobs.final_attempt_id` means the attempt whose `job_outcomes` row is current, including failed jobs. `jobs.verdict`/`jobs.authority` are nullable projections with CHECKs matching `job_outcomes`.
* `Artifact.kind` CHECK is `image/package/kernel/poc/evidence/bundle/other`.
* `PRAGMA foreign_keys=ON`; all FKs are indexed; `jobs.last_outcome_id` has an FK to `job_outcomes`.
* Add reason codes: `broker_registry_rejected`, `artifact_hash_mismatch`, `proxy_capture_failed`, `actor_separation_failed`, `deadline_exceeded`, `migration_failed`. Use `null_actor_observed_nonce` everywhere; remove `null_actor_failed`.
* Add `tests/test_migrations.py` for forward migration, backup/restore, and newer-schema refusal.

### G. Retry matrix

| Class | Retry | Attempt | Resources | Failure |
| --- | --- | --- | --- | --- |
| transient fetch | once | same attempt | none | `source_unavailable` |
| network/target/attacker create | once | same attempt | destroy and recreate | `*_create_failed` |
| readiness/version | once | same attempt | re-check; no rebuild | `target_unhealthy` |
| freeze/restore/reboot | once | same attempt | re-run snapshot/boot | `snapshot_failed`/`restore_failed` |
| PoC transient infrastructure | once | new attempt | fresh VM | `exploit_failed` after the rerun |
| exploit failed (no nonce) | none | — | — | `exploit_failed` |
| validator provider error | once | same attempt | none | `validator_error` → `inconclusive` |
| destroy | once | same attempt | retry broker destroy | `teardown_failed`/`security_cleanup_failed` |

`ClassifiedLog` predicates: `infrastructure` = broker/socket/timeout; `network` = proxy/nftables/egress; `guest` = SSH/readiness/boot; `script` = setup/build non-zero; `poc` = PoC non-zero/no output; `validator` = provider/JSON/schema. Each maps to the retry class above.

### H. Budget and job caps

Canonical allocation: Web/API/UI 1,000; runner 1,100; broker 1,700; VM/network/mirror/host evidence 1,250; ingestion 650; extractor/validator 650; storage/security/events/bundle 750; scripts 650; targets/profiles 250. Total 8,000.

File-to-component map (each file assigned once): web/* + templates + static -> Web; runner/queue/cleanup -> Runner; broker.py + broker/* + vm/broker_driver.py -> Broker; vm/probe*/targets/profiles? (see below) -> VM; fetch/sources/evidence -> Ingestion; agent/validator -> Extractor; db/security/events/bundle -> Storage; scripts/* -> Scripts; targets.py/profiles.py -> Targets. `broker/network_ops.py` and `broker/host_evidence.py` are Broker, not VM; `vm/probes.py`, `vm/driver.py`, `vm/fake_driver.py` are VM. This removes the double count.

Module cap: 44; the current `.py` file list is 42, leaving two slots for a broker registry split or a migration helper. Tests are separate.

Job wall-clock caps: PHP2Shell 90 min; GitLab 120 min; Dirty Frag 90 min. Per-step timeouts are maxima; the job deadline cancels the current step and runs a 5-minute teardown; the failure code is `deadline_exceeded`. `RunLimits.per_call_tokens=20000`, `max_vm_minutes=120`.

### I. Phase gates

* Phase 0: Gates B, E, F, G. Gate C moves to Phase 3; Gate D splits: D1 PHP build Phase 1, D2 GitLab build Phase 2, D3 Dirty Frag kernel Phase 3. Gate A splits: A1 PHP Phase 1, A2 GitLab Phase 2.
* Phase 1: app/API/storage, step runner, fake driver, UI, token/SSRF, nonce, PHP2Shell + attacker. Gate A1, D1; two clean runs.
* Phase 2: GitLab + attacker; Gate A2, D2; two clean runs.
* Phase 3: Dirty Frag; Gate C, D3; two clean runs; post-boot `uname -r`.
* Phase 4: prompt-injection, broker/network security, budget gates, bundle, migration/restore, full acceptance. `tests/test_migrations.py` owns the migration/backup/restore exit.

Every phase maps files/tests to an executable command from §13. Gate A records whether the attacker VM is causal or defense-in-depth; Gate C records whether the host channel is forge-proof.

### J. Test plan corrections

* Add `tests/test_evidence.py`; rename `tests/test_noncode_secret.py` to `tests/test_nonce_secret.py`.
* Facts fixtures: 20 valid + 2 invalid = 22; gate is 19/20 valid, 100% citation. Known-fail validator fixtures: 5. Mixed fixtures: 10.
* Add cases for migration/backup/newer-schema, API error/status/check TTL/single-use, preflight admission, host-evidence tamper, and `scripts/run_target_e2e.py`.
* Each test file has a phase and a pass command in its header.

### K. Mirror and packages

`config/packages.yaml` is removed from the runtime mirror. It is replaced by `config/image-manifests.yaml`, consumed by `scripts/build-images.sh`; apt packages are baked into the target and attacker images. The mirror is a static file server on the fixed `10.42.0.1:8081`, serving only the PHP source, GitLab `.deb`, kernel image and modules `.deb`s, and PoC artifacts. It serves no `Packages.gz`/`Release`. The network uses the fixed `10.42.0.0/24`, not `10.<slot>`. A test asserts apt has no internet route and the mirror serves only the listed artifacts.

### L. Cleanup CLI

Add `src/xentry/cli.py` and a console script `xentry = xentry.cli:main` in `pyproject.toml`. `xentry cleanup --force` lists managed resources, destroys attacker/target/networks in order, removes overlays/ISOs, and exits 0 only when `CleanupReport.blocked` is false. `xentry cleanup --status` prints the report.

### M. Metadata and signatures

The main document is revision 5. `snapshot(vm_id, kind)` is the only snapshot signature; `kind` is `memory` for remote targets and unused for Dirty Frag. Use `version_probe_step_id`, `build_step_id`, `invocation_step_id`, and `timeout_s`; the main sketch is illustrative and §3 is authoritative. The contracts file and this corrections section supersede conflicting main-document text.

### N. Gate G kernel-modules correction

`linux-image-6.17.0-23-generic` depends on `linux-modules-6.17.0-23-generic`; the image package alone is not a bootable kernel. Gate G therefore pins two kernel artifacts:

* `kernel-6.17.0-23`: `linux-image-6.17.0-23-generic_6.17.0-23.23~24.04.1_amd64.deb`, SHA-256 `bf4dd0d202ce223878eed54b8f03cfcaa8162630ceed9b0428f1186eaf3ad74e`.
* `kernel-modules-6.17.0-23`: `linux-modules-6.17.0-23-generic_6.17.0-23.23~24.04.1_amd64.deb`, SHA-256 `101465bd48c827e0885a89712717b833313018fae22fd68a05a25029e4ea4f5f`.

The runtime mirror serves both. `targets/dirtyfrag/setup.sh` installs both in one `dpkg` invocation and verifies `uname -r` after the reboot. This supersedes singular `kernel .deb` wording in §K and the setup outline. The broker registry artifact set adds `kernel-modules-6.17.0-23`.

The vendor cloud image is `ubuntu-base-image`; the customized target image is `ubuntu-target-image`. All three `image-manifests.yaml` profiles use `ubuntu-base-image` as their `base_artifact`. The base image is a build input and is not served to guests.

---

## 1. Broker-owned registry

The broker owns one checked-in registry, `broker/registry.py`, loaded at startup and hash-pinned in the broker unit. The app sends ids and typed parameters; it never sends a command template, image path, guest path, or user.

```text
Registry:
  targets:  php2shell, gitlab, dirtyfrag
  profiles: target-php2shell, target-gitlab, target-dirtyfrag, attacker-remote
  images:   ubuntu-24.04-target, ubuntu-24.04-attacker (artifact ids in config/artifacts.yaml)
  steps:    setup-php, setup-gitlab, setup-dirtyfrag,
            readiness-php, readiness-gitlab, readiness-dirtyfrag,
            build-poc-gitlab, build-poc-dirtyfrag,
            run-poc-php, run-poc-gitlab, run-poc-dirtyfrag,
            probe-php-http, probe-gitlab-response, probe-dirtyfrag-pty,
            null-php, null-gitlab, null-dirtyfrag,
            reboot-dirtyfrag, collect-host-evidence
  artifacts: php-8.4.26-src, gitlab-19.2.5-deb, kernel-6.17.0-23,
             kernel-modules-6.17.0-23,
             poc-php2shell, poc-gitlab, poc-dirtyfrag,
             ubuntu-target-image, ubuntu-dirtyfrag-image, ubuntu-attacker-image
```

Each step entry:

```text
StepSpec:
  step_id: str
  argv_template: list[str]        # no shell; typed placeholders only
  params: dict[str, ParamSpec]    # name -> type, required, min/max, enum
  allowed_users: list[str]        # root for setup; xentry-guest for actor/probe
  timeout_s: int
  retry: RetrySpec                # none | transient | once
  evidence: list[EvidenceKind]    # stdout, stderr, http, pty, host_serial, qmp
  cleanup: str                    # no-op | stop-process | destroy-vm | none
  failure_code: str               # closed code from section 7
```

Server-side validation:

* Unknown `target_id`, `step_id`, `image_id`, `profile_id`, `artifact_id`, `vm_id`, `network_id`, or `guest_path` is rejected with `broker_registry_rejected`.
* `params` must match the declared types and ranges; extra params are rejected.
* `allowed_users` is enforced; `xentry-guest` can never be escalated to root; `root` is allowed only for `setup-*` steps and `collect-host-evidence`.
* `copy_in` accepts an artifact id and writes to a broker-chosen path under the job directory; `copy_out` returns an artifact id and hash.
* `place_nonce` is the only nonce writer; it accepts `nonce_id`, `path`, `owner`, `mode`, and the value; the value is never logged.
* `http_probe(network_id, target_ip, port, method, path, timeout, max_bytes) -> HttpResult` is a broker verb. It connects to the target private IP, not the host LAN. `VmDriver` and `BrokerClient` expose it.

The app-side `vm/probes.py` is a plan builder only: it describes probe steps; it does not execute them.

## 2. Privilege model

| Principal | Where | Rights |
| --- | --- | --- |
| `xentry` | host | App process, job dirs, SQLite, evidence store; no libvirt |
| `xentry-broker` (root) | host | Broker socket, libvirt, nftables, mirror, SSH, host evidence |
| `xentry-vm` | host | QEMU process; no shell, no host mounts |
| `root` | guest | Provisioning only, step-id allowlisted (`setup-*`) |
| `xentry-guest` | guest | Actor: PoC, probes, PTY; no sudo/setuid/pkexec; no root-owned writes |

Rules:

* All three setup scripts run as `root` in the guest, allowlisted by their `setup-*` step id.
* `xentry-guest` has no passwordless sudo, no setuid binaries it can execute, no `pkexec`, no shared SSH key, and no writable root-owned path.
* The Dirty Frag root shell must be spawned by the PoC running as `xentry-guest`; the broker rejects any root shell opened by its own credentials. The runner attaches to the PTY as `xentry-guest`.
* The host app user `xentry` and the guest actor `xentry-guest` are distinct; the app user is never used as a guest credential.

`tests/test_actor_separation.py` must assert:

* `sudo -n true` fails as `xentry-guest`.
* `cat /root/xentry-nonce` fails as `xentry-guest`.
* `touch /usr/bin/xentry-test` fails as `xentry-guest`.
* `id -u` is not 0 and no setuid helper is available.
* The Dirty Frag null actor does not produce a host-channel root shell or a root nonce read.

## 3. Typed models

All models are Pydantic v2. `str` values are bounded where noted.

### Facts

| Field | Type | Required | Validation |
| --- | --- | --- | --- |
| `cve_id` | str | yes | `CVE-\d{4}-\d{4,}` |
| `product` | str | yes | 1–200 chars |
| `affected_range` | str | yes | non-empty; parsed by the version probe |
| `version_evidence` | list[EvidenceRef] | yes | at least 1 |
| `protocol` | str | no | `http`, `https`, `tcp`, `local` |
| `ports` | list[int] | no | 1–65535 |
| `auth_required` | bool | yes | — |
| `build_strategy` | str | yes | 1–200 chars |
| `poc_context` | str | yes | `remote` or `local` |
| `marker_candidate` | str | no | 1–500 chars |
| `artifact_candidates` | list[EvidenceRef] | no | — |
| `citations` | list[EvidenceRef] | yes | at least 1 |

`EvidenceRef`: `{artifact_id: str, sha256: str, quote: str, line_start: int?, line_end: int?}`. Every quote must appear in the referenced artifact.

### Target

| Field | Type | Required | Validation |
| --- | --- | --- | --- |
| `target_id` | str | yes | `php2shell`, `gitlab`, `dirtyfrag` |
| `cve_ids` | list[str] | yes | at least 1 |
| `poc_context` | str | yes | `remote` or `local` |
| `script_source` | str | yes | `checked_in` (V1) |
| `base_image_artifact_id` | str | yes | registry artifact |
| `kernel_artifact_id` | str? | no | required for dirtyfrag |
| `resources` | Resources | yes | vcpu 1–8, memory 1024–16384, disk 10–80 |
| `attacker_profile_id` | str? | no | required for remote; null for dirtyfrag |
| `network_profile_id` | str | yes | `isolated` |
| `actor_user` | str | yes | `xentry-guest` |
| `setup_script_path` | str | yes | under `targets/<id>/` |
| `setup_sha256` | str | yes | 64 hex |
| `expected_version` | str | yes | non-empty |
| `version_probe_step_id` | str | yes | registry step |
| `poc` | PocPin | yes | — |
| `probes` | list[ProbeStep] | yes | exactly one `decisive` |
| `nonce` | NonceSpec | yes | — |
| `null_actor` | NullActor | yes | — |
| `evidence_channel` | EvidenceChannel | yes | — |
| `retry_policy` | RetryPolicy | yes | — |
| `timeouts` | Timeouts | yes | — |
| `what_proves` | list[str] | yes | at least 1 |
| `what_does_not_prove` | list[str] | yes | at least 1 |

### Supporting models

| Model | Fields |
| --- | --- |
| `Resources` | `vcpu:int`, `memory_mb:int`, `disk_gb:int` |
| `PocPin` | `artifact_id:str`, `repository:str`, `commit:str`, `files:list[str]`, `sha256:str`, `build_step_id:str`, `invocation_step_id:str` |
| `ProbeStep` | `step_id:str`, `kind:enum(http_get,response_parse,pty_session,host_serial,qmp)`, `decisive:bool`, `params:dict`, `timeout_s:int` |
| `NonceSpec` | `path:str`, `owner:str`, `mode:int`, `value_source:literal("runner")` |
| `NullActor` | `location:enum(attacker,target)`, `step_id:str`, `expected:literal("no_nonce")` |
| `EvidenceChannel` | `kind:enum(target_probe,host_serial,qmp)`, `channel:str` |
| `RetryPolicy` | `transient_fetch_retries:int`, `poc_reruns:int` |
| `Timeouts` | `boot_s:int`, `provision_s:int`, `readiness_s:int`, `poc_s:int`, `validate_s:int` |
| `RunLimits` | `max_tokens:int`, `per_call_tokens:int`, `max_vm_minutes:int`, `max_disk_gb:int` |
| `VmProfile` | `vcpu:int`, `memory_mb:int`, `disk_gb:int`, `image_artifact_id:str` |
| `CommandResult` | `exit_code:int`, `stdout_sha256:str`, `stderr_sha256:str`, `stdout_excerpt:str`, `stderr_excerpt:str`, `timed_out:bool`, `duration_ms:int` |
| `SnapshotRef` | `snapshot_id:str`, `vm_id:str`, `kind:enum(disk,memory)`, `created_at:str` |
| `HttpResult` | `status:int`, `headers_sha256:str`, `body_sha256:str`, `body_excerpt:str`, `bytes:int` |
| `Artifact` | `artifact_id:str`, `kind:enum(image,package,kernel,poc,other)`, `path:str`, `sha256:str`, `bytes:int`, `provenance:str` |
| `Manifest` | `artifact_ids:list[str]`, `manifest_sha256:str` |
| `ClassifiedLog` | `class:enum(infrastructure,network,guest,script,poc,validator)`, `excerpt:str`, `line_refs:list[int]`, `phase:str` |
| `LlmVerdict` | `verdict:enum(reproduced,not_reproduced,inconclusive)`, `reason_code:str`, `evidence_refs:list[str]`, `explanation:str` |
| `JobOutcome` | `id:str`, `job_id:str`, `attempt_id:str`, `outcome:enum(completed,failed,cancelled,interrupted)`, `verdict:enum(reproduced,not_reproduced,inconclusive,not_run)`, `authority:enum(runner_observed+llm_assessed,guest_attested+llm_assessed,runner_observed)`, `reason_code:str`, `ts:str` |
| `NonceRecord` | `nonce_id:str`, `job_id:str`, `attempt_id:str`, `phase:enum(null,real)`, `sha256:str`, `path:str`, `owner:str`, `mode:int`, `created_at:str` |
| `StepRecord` | `id:str`, `job_id:str`, `attempt_id:str`, `seq:int`, `name:str`, `step_id:str`, `state:enum(pending,running,passed,failed,skipped)`, `started_at:str?`, `finished_at:str?`, `reason_code:str?` |
| `BrokerCall` | `id:str`, `job_id:str`, `attempt_id:str`, `seq:int`, `verb:str`, `params_sha256:str`, `started_at:str`, `finished_at:str?`, `status:enum(ok,error)`, `result_sha256:str?` |

### Interface signatures

```text
VmDriver:
  create_target(job_id, target_id, image_id) -> (vm_id, guest_ip, domain)
  create_attacker(job_id, profile_id, image_id) -> (vm_id, guest_ip, domain)
  exec(vm_id, step_id, params, tty: bool, timeout_s: int) -> CommandResult
  copy_in(vm_id, artifact_id, guest_path) -> sha256
  copy_out(vm_id, guest_path) -> (artifact_id, sha256)
  place_nonce(vm_id, nonce: NonceRecord, value: str) -> sha256
  snapshot(vm_id, kind) -> SnapshotRef
  restore(vm_id, snapshot_id) -> None
  reboot(vm_id, timeout_s) -> boot_id
  read_host_evidence(vm_id, channel) -> bytes
  http_probe(network_id, target_ip, port, method, path, timeout_s, max_bytes) -> HttpResult
  destroy_vm(vm_id) -> None
  destroy_network(network_id) -> None
  list_managed() -> list[ManagedResource]

BrokerClient: same methods over the Unix socket.

AgentRuntime:
  extract(excerpts: list[EvidenceRef]) -> Facts

ValidatorClient:
  assess(runner_facts: RunnerFacts, narrative: NarrativeBundle) -> LlmVerdict

JobRunner:
  submit(request: JobRequest) -> job_id
  cancel(job_id) -> None
  recover() -> RecoveryReport
  sweep_orphans() -> CleanupReport
```

`RunnerFacts`: `nonce_observed:bool`, `nonce_id:str`, `nonce_sha256:str`, `null_actor_observed_nonce:bool`, `version_match:bool`, `precondition_ok:bool`, `vm_ids:list[str]`, `network_id:str`, `probe_evidence_sha256:str`, `host_evidence_sha256:str?`.
`NarrativeBundle`: `poc_artifact:str`, `setup_script:str`, `attacker_transcript:str`, `target_response_excerpt:str`, `host_evidence_excerpt:str?`.

## 4. Runner step table

The step list is remote-target and local-target aware. `step_id` is the broker registry id. `user` is enforced by the broker. `retry` is `none`, `transient`, or `once`.

| Seq | Step | step_id | Params | User | Timeout | Retry | Evidence | Cleanup | Failure |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | fetch | n/a | cve_url, poc_url | app | 120 s | transient | artifacts + hashes | none | `source_unavailable` |
| 2 | extract | n/a | excerpts | app | 120 s | none | Facts + citations | none | `evidence_insufficient` |
| 3 | plan | n/a | Facts, target_id | app | 60 s | none | plan + check_id | none | `unsupported_target` |
| 4 | create_network | n/a | network profile | broker | 120 s | once | network id | destroy network | `network_create_failed` |
| 5 | create_target | n/a | target, image | broker | 300 s | once | vm id/ip | destroy vm | `target_create_failed` |
| 6 | provision | setup-* | mirror_url | root | 1800 s | none | setup log | destroy vm | `provision_failed` |
| 7 | readiness | readiness-* | expected_version | xentry-guest | 300 s | once | version output | destroy vm | `target_unhealthy` |
| 8 | create_attacker | n/a | attacker profile, image | broker | 300 s | once | vm id/ip | destroy vm | `attacker_create_failed` |
| 9 | build_poc | build-poc-* | poc artifact | xentry-guest | 600 s | none | build log/hash | destroy attacker | `poc_build_failed` |
| 10 | freeze | n/a | vm id | broker | 120 s | once | snapshot ref | destroy vm | `snapshot_failed` |
| 11 | place_nonce | n/a | nonce id/path/owner/mode | broker | 60 s | none | nonce hash | destroy vm | `nonce_place_failed` |
| 12 | null_actor | null-* | nonce path | xentry-guest | 300 s | none | null transcript | destroy VMs | `null_actor_observed_nonce` |
| 13 | probe_null | probe-* | nonce id | broker | 120 s | once | probe evidence | destroy VMs | `probe_failed` |
| 14 | restore_or_reboot | n/a | snapshot or fresh boot | broker | 300 s | once | boot id | destroy VMs | `restore_failed` |
| 15 | place_fresh_nonce | n/a | nonce id/path/owner/mode | broker | 60 s | none | nonce hash | destroy VMs | `nonce_place_failed` |
| 16 | real_actor | run-poc-* | nonce path | xentry-guest | 600 s | once on transient | transcript | destroy VMs | `exploit_failed` |
| 17 | target_probe | probe-* | nonce id | broker | 120 s | once | decisive evidence | destroy VMs | `nonce_not_observed` |
| 18 | host_evidence | collect-host-evidence | channel | root | 120 s | once | host bytes/hash | destroy vm | `host_evidence_missing` |
| 19 | destroy_attacker | n/a | vm id | broker | 120 s | once | destroy result | none | `teardown_failed` |
| 20 | destroy_target | n/a | vm id | broker | 120 s | once | destroy result | none | `teardown_failed` |
| 21 | destroy_network | n/a | network id | broker | 60 s | once | destroy result | none | `teardown_failed` |
| 22 | validate | n/a | runner facts + narrative | app | 120 s | once on provider error | verdict | none | `validator_error` |
| 23 | project | n/a | outcome, verdict, authority | app | 30 s | none | job_outcome | none | `harness_error` |

Cleanup order: attacker VM → target VM → network. Destroy runs on every failure, cancellation, and interruption; it never runs after validation for a successful job (validation uses the immutable bundle). If `cleanup_state=failed`, the job outcome is still recorded, `security_cleanup_failed` is set, and new jobs are blocked until the broker lists and destroys the resources.

`restore_or_reboot`: remote targets use a memory-inclusive snapshot restore; Dirty Frag uses a fresh boot and then re-runs readiness, version, and `uname -r` before the fresh nonce.

Attempts: attempt 0 is created at step 1 and covers fetch/extract/plan. A transient fetch retry or a PoC rerun creates attempt N+1 and a fresh attempt directory. A Dirty Frag retry starts a fresh VM. `jobs.final_attempt_id` points to the attempt whose outcome is projected.

## 5. Target values

Exact values known at design time; external hashes and commits are resolved by Phase 0 Gate G and recorded in `config/artifacts.yaml`. No implementation starts before the gate.

| Target | CVE | Base image | Kernel | Resources | Attacker | Ports | Actor | PoC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PHP2Shell | CVE-2026-109618 | `ubuntu-24.04-target` (PHP build deps, Apache) | distro | 2 vCPU, 4 GB, 25 GB | `ubuntu-24.04-attacker` (Python, requests) | 8088 | `xentry-guest` | `https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit`, branch `main`, commit pinned at Gate G |
| GitLab | CVE-2026-85706 | `ubuntu-24.04-target` (GitLab deps) | distro | 4 vCPU, 8 GB, 50 GB | `ubuntu-24.04-attacker` (Go) | 80, 443 | `xentry-guest` | `https://github.com/gagaltotal/CVE-2026-85706-gitlab-poc`, branch `main`, commit pinned at Gate G |
| Dirty Frag | CVE-2026-43500 | `ubuntu-24.04-dirtyfrag` (gcc, make, libc headers) | `6.17.0-23-generic` | 2 vCPU, 2 GB, 25 GB | none | none | `xentry-guest` | `https://github.com/V4bel/dirtyfrag`, branch `master`, commit pinned at Gate G |

Artifact pins:

* `php-8.4.26-src`: PHP 8.4.26 source tarball URL and SHA-256.
* `gitlab-19.2.5-deb`: GitLab CE 19.2.5 Omnibus `.deb` URL and SHA-256.
* `kernel-6.17.0-23`: Ubuntu signed kernel image package URL and SHA-256.
* `kernel-modules-6.17.0-23`: matching Ubuntu kernel modules package URL and SHA-256.
* `poc-*`: commit tarball URL and SHA-256, selected files, build/invocation step ids.
* `ubuntu-base-image`: vendor cloud image URL and SHA-256.
* `ubuntu-*image`: built image URL (`build://ubuntu-base-image+...`) and SHA-256; built by `scripts/build-images.sh`.

Target `what_proves`/`what_does_not_prove` are the same as the main design's per-target section.

## 6. Setup-script outlines

Each script is checked in, hash-pinned, and run once as root. `mirror_url` is a typed step parameter; the script must not embed a job-varying address. Base images already contain the apt dependencies, so the scripts do not run `apt-get update` against the internet.

### `targets/php2shell/setup.sh`

1. Verify `mirror_url`, `php_artifact_id`.
2. Download the PHP 8.4.26 source tarball from the mirror; verify SHA-256.
3. Configure with the pinned flags (`--with-apxs2`, `--enable-mbstring`, `--enable-opcache`, etc.).
4. `make -j`, `make install`, install `php.ini`.
5. Enable the Apache module, set `DocumentRoot`, start Apache.
6. Readiness: `curl -fsS http://127.0.0.1:8088/` returns the expected status; `php -v` matches 8.4.26; `apache2ctl -M` includes `php_module`.
7. Write `var/run/xentry/ready` with the version.

### `targets/gitlab/setup.sh`

1. Verify `mirror_url`, `gitlab_artifact_id`.
2. Install the pinned Omnibus `.deb` from the mirror.
3. Run `gitlab-ctl reconfigure`.
4. Wait for `/users/sign_in` to return HTTP 200/302 and for the version endpoint to report 19.2.5.
5. Write the readiness file.

### `targets/dirtyfrag/setup.sh`

1. Verify `mirror_url`, `kernel_artifact_id`, `kernel_modules_artifact_id`.
2. Install both pinned kernel `.deb`s in one `dpkg` invocation; update the boot entry; set the default kernel.
3. Reboot; wait for SSH; verify `uname -r` equals `6.17.0-23-generic`; write the readiness file.
4. Ensure `gcc`, `make`, and libc headers are present from the base image.
5. Copy the pinned PoC source; build as `xentry-guest`; leave the binary in the actor home.
6. The runner performs a post-fresh-boot `uname -r` and readiness check again before the real run.

## 7. Closed reason codes

| Code | Trigger | Retry | Next action |
| --- | --- | --- | --- |
| `source_unavailable` | Fetch failed | transient once | check links |
| `evidence_insufficient` | Facts cannot be cited | none | supply a better link |
| `unsupported_target` | CVE not in the three targets | none | choose a supported CVE |
| `unsupported_poc` | PoC does not match the pin | none | use the pinned PoC |
| `version_unidentified` | Advisory range or version missing | none | supply version evidence |
| `preflight_refused` | Host memory/disk/broker/image gate failed | none | free resources or fix the host |
| `broker_unavailable` | Socket/peer/auth failure | once | check the broker unit |
| `broker_registry_rejected` | Unknown id, param, user, or path | none | fix the call; do not retry |
| `network_create_failed` | libvirt network or nftables failure | once | inspect broker logs |
| `target_create_failed` | Target domain start failure | once | check resources |
| `attacker_create_failed` | Attacker domain start failure | once | check resources |
| `provision_failed` | Setup script non-zero | none | inspect setup log |
| `target_unhealthy` | Readiness/version failure | once | inspect evidence |
| `artifact_hash_mismatch` | Script/PoC/image hash mismatch | none | re-pin after review |
| `snapshot_failed` | Snapshot/restore failure | once | inspect broker |
| `restore_failed` | Restore/reboot failure | once | inspect broker |
| `nonce_place_failed` | Broker place_nonce failure | once | inspect broker |
| `null_actor_observed_nonce` | Null actor produced the nonce | none | fix the probe/nonce |
| `probe_failed` | Probe could not run | once | inspect probe evidence |
| `nonce_not_observed` | Real run/probe did not observe the nonce | none | inspect runner facts |
| `exploit_failed` | PoC ran without the nonce | none | do not auto-retry |
| `poc_build_failed` | Attacker/target build failed | none | inspect build log |
| `host_evidence_missing` | Dirty Frag host channel empty | once | inspect host evidence |
| `validator_error` | Provider/JSON/schema failure | once | park or `inconclusive` |
| `validator_disagreed` | LLM contradicts runner facts | none | clamp and record |
| `timeout` | Step/job timeout | none | inspect in-flight op |
| `budget_exhausted` | Token/disk/time/memory cap | none | raise cap or reduce target |
| `cancelled` | User cancellation | none | cleanup |
| `interrupted` | Crash/restart recovery | none | cleanup |
| `teardown_failed` | Generic destroy/network failure | once | manual cleanup |
| `security_cleanup_failed` | Security-critical destroy failure | none | block new jobs; clean manually |
| `actor_separation_failed` | Actor can sudo/read root-only path/write service binary | none | fix the image/actor policy |
| `policy_blocked` | Prompt injection, SSRF, forbidden op | none | review evidence |
| `harness_error` | Unexpected internal error | none | inspect logs |

`null_actor_observed_nonce` is the only null-actor code; it means the null actor observed the nonce, so the job fails. Acceptance text must say "the null actor must not observe the nonce."

## 8. DDL additions

Add to `migrations/001_initial.sql`:

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE job_outcomes (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  outcome TEXT NOT NULL, verdict TEXT NOT NULL, authority TEXT NOT NULL,
  reason_code TEXT, ts TEXT NOT NULL,
  CHECK (outcome IN ('completed','failed','cancelled','interrupted')),
  CHECK (verdict IN ('reproduced','not_reproduced','inconclusive','not_run')),
  CHECK (authority IN ('runner_observed+llm_assessed','guest_attested+llm_assessed','runner_observed')),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE nonces (
  nonce_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
  phase TEXT NOT NULL, sha256 TEXT NOT NULL, path TEXT NOT NULL,
  owner TEXT NOT NULL, mode INTEGER NOT NULL, created_at TEXT NOT NULL,
  CHECK (phase IN ('null','real')),
  UNIQUE(attempt_id, phase),
  FOREIGN KEY(job_id) REFERENCES jobs(id),
  FOREIGN KEY(attempt_id) REFERENCES attempts(id)
);

CREATE TABLE link_checks (
  check_id TEXT PRIMARY KEY, cve_url TEXT NOT NULL, poc_url TEXT NOT NULL,
  cve_id TEXT, target_id TEXT, bundle_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
  CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE INDEX idx_jobs_outcome ON jobs(outcome);
CREATE INDEX idx_job_outcomes_job ON job_outcomes(job_id);
CREATE INDEX idx_nonces_attempt ON nonces(attempt_id);
CREATE INDEX idx_steps_job ON job_steps(job_id, attempt_id, seq);
CREATE INDEX idx_broker_calls_job ON broker_calls(job_id, attempt_id, seq);
CREATE INDEX idx_artifacts_job ON artifacts(job_id, attempt_id);
```

`jobs` gains `last_outcome_id TEXT` and `verdict TEXT`, `authority TEXT` (nullable projections). `validations.authority` uses only `runner_observed+llm_assessed` and `guest_attested+llm_assessed`. `runner_observed` lives only in `job_outcomes`. `job_steps.state` CHECK is `pending/running/passed/failed/skipped`; `broker_calls.status` CHECK is `ok/error`; `artifacts.kind` CHECK is `image/package/kernel/poc/evidence/bundle/other`.

Migration ownership: `src/xentry/db.py` owns migrations; `scripts/migrate.py` is the CLI wrapper; `migrations/` contains SQL only. `scripts/rebuild_index.py` rebuilds SQLite from the journal and job directories.

## 9. API, token, and check store

Token: 32 bytes from `secrets.token_urlsafe(32)`, stored in `var/instance/token` mode 0600. Delivery: HttpOnly, `SameSite=Strict` cookie named `xentry_token`, plus a double-submit CSRF token in a meta tag and the `X-Xentry-CSRF` header on every non-GET. Every non-GET route checks the cookie, the CSRF header, Origin, and Host. The token is request integrity, not a user account.

Check store: `link_checks` row with TTL 30 minutes, single-use. `POST /api/links/check` returns `{check_id, target_id, cve_id, bundle_sha256, plan}`. `POST /api/jobs` requires an unexpired, unused `check_id`; the job stores `bundle_sha256` and fails `source_unavailable` if the refetch differs.

Error envelope:

```json
{"error": {"code": "unsupported_target", "message": "human text", "details": {}, "request_id": "uuid"}}
```

Status map: 400 validation, 404 unknown, 409 state conflict, 413 too large, 422 unsupported target/PoC, 429 rate, 500 harness, 503 provider/broker unavailable.

Routes: `POST /api/jobs`, `POST /api/links/check`, `GET /api/jobs`, `GET /api/jobs/{id}`, `GET /api/jobs/{id}/steps`, `GET /api/jobs/{id}/validations`, `GET /api/jobs/{id}/evidence/{artifact_id}`, `GET /api/jobs/{id}/events` SSE, `GET /api/jobs/{id}/events?since=`, `POST /api/jobs/{id}/cancel`, `GET /api/jobs/{id}/bundle`, `POST /api/preflight`, `GET /api/system`. The help surface is a modal; no `/help` route.

## 10. Mirror and prebuilt images

* `scripts/build-images.sh` builds `ubuntu-24.04-target`, `ubuntu-24.04-dirtyfrag`, and `ubuntu-24.04-attacker` with their apt dependencies and toolchains. Images are hash-pinned in `config/artifacts.yaml`.
* The mirror is a static file server on `10.42.0.1:8081`, broker-managed, serving only the job's pinned artifacts from `var/mirror/<job_id>/`. It is not an apt repository; apt packages are baked into the images.
* The setup scripts accept `mirror_url` as a typed step parameter and download only the target software artifacts (PHP source, GitLab `.deb`, kernel image and modules `.deb`s).
* Attacker image includes Go and Python `requests`; GitLab's Go PoC uses only the standard library; PHP's Python PoC has no external downloads.
* `scripts/fetch-artifacts.sh` takes a catalog path, verifies vendor checksums/signatures, downloads images/packages/PoC tarballs, and exits non-zero on a missing out-of-band hash. It never writes a new pin from the first fetch.

## 11. Cleanup and orphan identification

Naming: domain `xentry-<job_id>-target`, `xentry-<job_id>-attacker`; network `xentry-<job_id>`; overlay `var/jobs/<job_id>/overlays/<role>.qcow2`; seed ISO `var/jobs/<job_id>/seed-<role>.iso`; log `var/jobs/<job_id>/logs/<role>.log`.

`list_managed()` returns `{job_id, role, domain, state, created_at}` for domains and `{job_id, network, state, created_at}` for networks. The sweep order is attacker → target → network; it marks interrupted jobs, removes overlays/ISOs, and is idempotent. A repeated destroy failure sets `security_cleanup_failed` and blocks new jobs until `xentry cleanup --force` (or the broker's `list_managed` + destroy) succeeds.

## 12. Security and deployment ownership

* Broker code, virtualenv, config, and unit are root-owned (`/opt/xentry-broker`, 0755/0700); the app has read-only access. The app venv is `xentry`-owned; the broker never executes app code.
* Job directories, overlays, ISOs, and evidence are `xentry:xentry`; the broker can write only under `/var/lib/xentry/jobs` and `/var/lib/xentry/mirror`.
* `broker_calls` are written by the broker to `var/jobs/<job_id>/broker_calls.jsonl` (root-owned file, app-readable); the app indexes the returned call record into SQLite.
* Broker unit: `User=root`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/xentry`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN` (validated in Gate B), `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`.
* AppArmor profile `deploy/apparmor/xentry-vm` for QEMU, installed by `scripts/install-apparmor.sh`; `tests/test_actor_separation.py` verifies the actor restrictions.
* Token, CSP (`default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`), redaction patterns, and SSH key lifecycle (per-job key, 0600, deleted after destroy) are specified in `src/xentry/security.py`.
* Host: Ubuntu 24.04.4; libvirt 10+ (tested on 12), QEMU 8.2+ (tested on 10.2.1); `virsh`/libvirt-clients; nftables; cloud-image-utils; qemu-img; openssh-client; systemd; AppArmor. WSL2 requires `/dev/kvm`, libvirtd, systemd lingering, and AppArmor-compatible kernel.

## 13. Test cases and fixtures

| Test file | Cases |
| --- | --- |
| `tests/test_budget.py` | module count, line counts per component, dependency count, non-Python count; fail on overage |
| `tests/test_steps.py` | step order; every failure goes to cleanup, never validate; destroy order attacker→target→network; cancel between steps; cleanup failure terminal |
| `tests/test_broker_contract.py` | valid verbs; unknown target/step/image/profile/artifact ids rejected; raw argv rejected; user allowlist; root only setup; peer UID; idempotent destroy; `http_probe` present |
| `tests/test_actor_separation.py` | `sudo -n true` fails; `/root/xentry-nonce` unreadable; service binary unwritable; no setuid/pkexec; Dirty Frag null actor no host root shell |
| `tests/test_network_mirror.py` | isolated network; mirror during provisioning; default-deny after; egress test fail-closed; no host LAN; no internet; mirror URL parameter |
| `tests/test_two_vm_runner.py` | remote PHP/GitLab; local Dirty Frag; null actor no nonce; fresh nonce after restore/reboot; destroy before validate; attacker transcript not decisive |
| `tests/test_nonce_secret.py` | value absent from SQLite, attacker argv/transcript, validator bundle, audit bundle; nonce id/hash recorded; two phases |
| `tests/test_queue_recovery.py` | kill/restart; interrupted; orphan domains/networks/overlays/ISOs removed; cleanup failure blocks new jobs |
| `tests/test_fetch_ssrf.py` | private/metadata rejection; connect to validated IP; redirect recheck; caps |
| `tests/test_sources.py` | three fixed CVE inputs; PoC pin match; generic fallback rejects unsupported |
| `tests/test_targets.py` | three instances valid; one decisive probe; script/PoC hashes; no target-id branches in runner |
| `tests/test_agent_contract.py` | extract-only; no tools; 19/20 facts; 100% citations; ADK/direct switch |
| `tests/test_validator.py` | runner facts; nonce clamp; authority; refs resolved; egress minimization; downgrade rule |
| `tests/test_security.py` | token all mutations; CSRF/Origin/Host; CSP; redaction; secret absence; AppArmor unit |
| `tests/test_ui_vocabulary.py` | rendered HTML/JSON/static/bundle banned words; state/outcome/verdict/authority mapping |
| `tests/test_prompt_injection.py` | hostile CVE/PoC/setup/transcript fixtures fail with no host effect |
| `tests/test_vm_libvirt.py` | gated real two-VM smoke: broker, network, boot, exec, snapshot, reboot, host evidence, destroy |
| `tests/test_bundle.py` | reconstruction; hashes; no nonce value/secrets |

Fixtures: `tests/fixtures/facts/*.json` (20 valid, 2 invalid), `tests/fixtures/transcripts/*.jsonl` (5 known-fail, 5 known-pass, 10 mixed), `tests/fixtures/injection/*`, and `tests/fixtures/manifests/*`. Each fixture has `case_id`, `target_id`, `expected_verdict`, `expected_reason`, and `sha256`. `test_vm_libvirt.py` is skipped unless `XENTRY_RUN_VM_TESTS=1`.

## 14. Budget map

| Component | Files | Allocation |
| --- | --- | --- |
| Web/API/UI | `web/*`, templates, static | 1,000 |
| Runner/queue/cleanup | `runner.py`, `queue.py`, `cleanup.py` | 1,100 |
| Broker client + broker | `broker.py`, `broker/*`, `vm/broker_driver.py` | 1,500 |
| VM/network/mirror/host evidence | `vm/*`, broker network/evidence rows | 1,300 |
| Ingestion/evidence | `fetch.py`, `sources.py`, `evidence.py` | 650 |
| Extractor/validator | `agent.py`, `validator.py` | 650 |
| Storage/security/events/bundle | `db.py`, `security.py`, `events.py`, `bundle.py` | 800 |
| Scripts | `scripts/*` | 650 |
| Target/profile instances | `targets.py`, `profiles.py` | 350 |
| **Total** | | **8,000** |

Count rule: modules = every `.py` file under `src/`, `broker/`, and `scripts/`, including `__init__.py`; tests are separate. Line counts exclude blank lines, comments, and lockfiles. The module cap is 44 to leave headroom for `broker/registry.py`, `tests/test_actor_separation.py`, and `scripts/build-images.sh`; the line cap remains 8,000. Non-Python/lock/config/docs are not counted in the Python cap; the template/static cap is 1,500 lines for HTML/CSS/JS only.

## 15. Phase mapping and gates

| Phase | Files/tests | Exit check |
| --- | --- | --- |
| 0 (2 weeks) | broker registry/libvirt/network/mirror/exec/host evidence, image build, AppArmor, artifact provenance, ADK extractor gate, prior-tree reuse spike | Gates B, C, D, E, F, G pass; Gate A is measured in Phase 1 |
| 1 (4 weeks) | app/API/storage, step runner, fake driver, UI, token/SSRF, nonce, PHP2Shell target+attacker | Gate A (one-VM causality measurement) recorded; two clean PHP2Shell runs; null actor no nonce; no orphan |
| 2 (3 weeks) | GitLab target+attacker, long-job UX, cancel/recovery | two clean GitLab runs; nonce; teardown |
| 3 (2 weeks) | Dirty Frag target, kernel, reboot, host evidence, actor separation | two clean Dirty Frag runs; guest-attested authority; post-boot `uname -r`; no orphan |
| 4 (3 weeks) | prompt-injection, broker/network security, budget gates, bundle, upgrade/restore, full acceptance | all gates; UI vocabulary; migration/restore test |

Gate A: if the one-VM PHP2Shell/GitLab nonce/null-actor test passes, record that the attacker VM is an isolation/defense-in-depth choice; if it fails, record that the attacker VM is the causal-enabling control. Gate C: if the host channel cannot be made non-forgeable, Dirty Frag keeps `guest_attested+llm_assessed` and the UI states it. Gate F: 19/20 facts and 100% citation. Gate E: no-op removed; raise host capacity or drop GitLab.
