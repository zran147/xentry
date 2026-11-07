# xentry V1 — Local CVE Reproduction with an LLM Agent and libvirt VMs

* **Author:** zran147
* **Status:** Proposed
* **Date:** 2026-11-05

## Overview

xentry V1 is a local web application for one or two users. A user submits a CVE link and a PoC link. The backend fetches a bounded evidence bundle, a DeepSeek-backed Google ADK agent extracts the facts and writes a setup script plus a PoC wrapper, and a runner-owned pipeline creates a libvirt/KVM VM, runs the setup, runs the PoC as a dedicated non-root actor, collects raw evidence, invokes a separate context-isolated LLM validator, and destroys the VM.

The validator returns `reproduced`, `not_reproduced`, or `inconclusive`. Its verdict is stored with `authority: llm` and labeled `llm_assessed`; V1 accepts that an LLM can be fooled. SQLite stores job and CVE records; the filesystem stores scripts, logs, and artifacts.

V1 is Linux-only and uses no container runtime in execution or deployment. The first three acceptance targets are CVE-2026-109618 (PHP2Shell, PHP 8.4.26 with Apache mod_php), CVE-2026-85706 (GitLab CE/EE arbitrary file read), and CVE-2026-43500 (Dirty Frag Linux kernel LPE). The first three setup scripts are hand-reviewed once for malicious content; after those, the normal flow is fully autonomous.

## The Problem

The prior v2 design tried to build a general evidence-first CVE pipeline and knowledge bank. It grew to roughly 12,000 lines across about 20 subsystems, produced three recipes it called verified, and could not be audited by its owner. Its verification path was also self-reported: the generated PoC script printed its own success marker, and the harness never checked it independently.

V1 is a ground-up reset. It narrows the product to a local web UI, three known Linux targets, one VM at a time, and a small runner. The hard problem is not whether an agent can write a setup script. It is whether the system can show that a reported reproduction was caused by the vulnerability and not by the agent, the setup script, the PoC, a leftover file, or a misconfigured target.

V1 does not solve that problem deterministically. It keeps a runner-owned nonce, a null-actor check, and raw evidence, then asks a separate DeepSeek session with no generator context to assess the evidence. The verdict is honest about its authority: it is LLM-assessed, and the full harness-owned verification contract is deferred.

## Goals

* **G1. Local operation.** The app binds to `127.0.0.1` by default and supports one or two users without accounts. Every mutation requires a startup-generated request-integrity token, with CSRF, Host, and Origin checks. LAN access requires the same token, a Host allowlist, and TLS or an SSH tunnel.
* **G2. Bounded input.** The app accepts a CVE link and a PoC link, detects the source shape, fetches a bounded evidence bundle, stores the raw bytes and hashes, and rejects unsupported sources, CVEs, and PoCs before spending a VM.
* **G3. Runner-owned pipeline.** The runner owns the sequence: fetch, extract, create VM, provision, freeze, inject nonce, run null actor, run real actor, collect evidence, validate, destroy. The model is invoked only for extraction and setup authoring or repair; it has no fetch or execute tools and cannot call validate or destroy.
* **G4. VM harness.** libvirt/KVM runs one VM at a time. `qemu:///session` is tested first; system libvirt requires a root-owned broker and a recorded risk acceptance. Domain XML comes from a fixed template with no host mounts, host devices, shared folders, or display devices. Domains are transient and destroyed on every exit path.
* **G5. Target packs.** Each target has a checked-in pack: base image and digest, resources, pinned versions, actor user, provisioning mode (`prebuilt` for the first three, `generated` for the normal flow), setup inputs, pinned PoC artifact, fixed validator probe, expected evidence, and destroy policy. A dummy fourth pack with generated provisioning must require no pipeline edits and no human review.
* **G6. Runner-owned evidence and independent LLM verdict.** The runner collects raw evidence and executes a fresh 128-bit nonce plus a null-actor check. A separate DeepSeek session with no generator history, no plan, no repair history, no tools, and no shared state receives the evidence and returns a structured verdict. The verdict is labeled `llm_assessed`; the job status is a projection of the validation row, and the agent summary is commentary.
* **G7. Execution isolation.** All untrusted PoC code is fetched and pinned on the host, copied into the target VM, built there, and run as a dedicated non-root actor. Nothing from the model or the PoC is built or run on the host. No container runtime is used in xentry or target provisioning. A second attacker VM is the fallback only if same-VM validation cannot be made causal.
* **G8. Job lifecycle.** Jobs are asynchronous, queued, cancellable, and recoverable. The UI reads an append-only event log over SSE with a polling fallback. A startup sweep removes orphan domains, overlays, and ISOs. A database-enforced single worker and single VM slot prevent concurrency.
* **G9. Storage and audit.** The per-job attempt directory and append-only JSONL logs are authoritative. SQLite is a rebuildable index for jobs, tool calls, validations, and artifacts. Failed jobs are retained; secrets are redacted before write; a downloaded bundle reconstructs the job.
* **G10. Honest UI.** Job state, verdict, and verdict authority are separate fields. "Succeeded" and "verified" are banned from the UI. The agent summary is labeled non-authoritative. A pre-run plan and a link check show the target, image, version, probe, caps, and truncation before Start.
* **G11. Budgets and failure codes.** Per-target time, memory, disk, and token caps are enforced by the runner. Every failure has a closed reason code and a next action. Retries cover transient and infrastructure failures, not a failed exploit.
* **G12. Testability.** A fake VM driver covers the job lifecycle without KVM. Validator fixtures, a scripted model client, a prompt-injection corpus, a null-actor test, and a kill-and-restart test are part of V1.
* **G13. Operational readiness.** The app runs from a local virtual environment and a systemd unit, with no Docker. The database has a schema version, forward-only migrations, a backup before migration, and a documented rollback.
* **G14. Autonomous normal flow.** The first three setup scripts are hand-reviewed once for malicious content and hash-pinned for V1 acceptance. After those three, the pipeline is fully autonomous: the LLM writes and repairs setup scripts from evidence and classified logs, with no human approval gate.

## Non-Goals

* User accounts, roles, multi-tenancy, or remote access without a token.
* General CVE coverage. V1 supports the three named CVEs and rejects others before provisioning.
* Arbitrary PoC adaptation. V1 runs the pinned PoC or an alternate that matches the same invocation contract.
* Windows, macOS, browser, GPU, hardware, cloud-only, or network-callback targets.
* Docker or any container runtime in xentry or in target provisioning.
* Concurrent VMs, a second attacker VM by default, multi-VM topologies, high availability, or cloud deployment.
* The full v2 contract: deterministic human-authored validators, harness-owned version-range probes, fixed-build negative controls, immutable bank versions, scoring, multiple advisory and PoC sources, and the five CLI bank verbs. V1 uses a context-isolated LLM validator and accepts the false-positive risk.
* Automatic publication or export of results, and the license gate that would come with it.
* A general agent platform: ADK sub-agents, long-term memory, the ADK web UI, or model-driven tool selection beyond the declared points.
* Proving real-world exploitability or safety. V1 records a lab reproduction, not a production risk assessment.
* A polished single-page app, mobile support, a frontend build chain, a dashboard, or a settings editor for every environment variable.
* Unlimited retries, indefinite artifact retention, or a disk budget beyond the stated ceiling.
* Automatic re-authoring of the exploit for V1.
* A human approval gate for generated setup scripts in the normal flow. Only the first three bootstrap scripts receive a one-time malicious-content review; the normal flow is autonomous.
* Dynamic target packs or a plugin loader.
* Currency display without a versioned and dated pricing table.

## Open Questions

* **Session libvirt.** Will `qemu:///session` support all three targets with user-mode networking, KVM, snapshots, and loopback port forwards on the target host? If not, the root-owned broker path is required.
* **Same-VM causality.** Can GitLab and PHP2Shell be validated with the actor in the target VM and the nonce protected, or does the shared kernel and filesystem force the second attacker VM?
* **Worker durability.** Does the single-process worker survive the kill-and-restart test, or must the web and worker processes split?
* **GitLab package.** Is the GitLab CE 19.2.5 Omnibus `.deb` retrievable with a stable URL and hash, and what are the actual memory and disk needs on the host?
* **Dirty Frag kernel.** Is the pinned `6.17.0-23-generic` kernel package available and installable, and can the PTY root-shell probe be driven reliably enough for two consecutive clean runs?
* **ADK tool calling.** Does ADK plus LiteLLM plus `deepseek/deepseek-chat` meet the tool-call threshold in the spike, or does the direct LiteLLM loop replace it?
* **Image hashes.** What exact SHA-256 values will the operator record for the Ubuntu base image and the Dirty Frag kernel package in `var/base-images/catalog.yaml`?

## Critical User Journeys (CUJs)

### CUJ 1: Submit a supported CVE and get a verdict

* **Given**: the app is running on loopback, the target pack exists, the base image and DeepSeek key are configured, and no job is running.
* **When**: the user pastes the CVE link and the PoC link, runs Check links, reviews the pre-run plan, and presses Start.
* **Then**: the job moves through fetch, extract, create, provision, run, validate, and destroy; the Job Detail page shows the stage timeline, the validator evidence, the verdict, and the `llm_assessed` authority. A completed job always has a validation row tied to its nonce.

### CUJ 2: Review a verdict and its evidence

* **Given**: a completed job.
* **When**: the user opens Job Detail and expands the evidence panel.
* **Then**: the validator verdict, reason code, evidence references, nonce id, version/precondition evidence, and agent summary appear in that order; the summary is labeled non-authoritative; the user can download the audit bundle.

### CUJ 3: Cancel a long GitLab run

* **Given**: a GitLab job is provisioning or running.
* **When**: the user presses Cancel.
* **Then**: the runner stops at the next phase boundary, destroys the domain, removes the overlay and ISO, writes `cancelled`, and the UI shows the cleanup result. A failed destroy is visible as `security_cleanup_failed` for Dirty Frag or a teardown failure otherwise.

### CUJ 4: Recover after a crash

* **Given**: the worker process is killed mid-job.
* **When**: the app starts again.
* **Then**: the job is marked `interrupted`, any xentry-managed domain without an active job is destroyed and undefined, stale overlays and ISOs are removed, and the UI shows an orphan banner if cleanup could not finish.

### CUJ 5: A second user connects remotely

* **Given**: a second user is on another machine.
* **When**: the user opens an SSH local port forward to the host's loopback app and loads the UI.
* **Then**: the app is reachable without LAN exposure; every mutation still requires the request-integrity token; the help page documents the exact tunnel command.

### CUJ 6: Reject an unsupported CVE

* **Given**: the user submits a CVE outside the three supported packs.
* **When**: the user runs Check links.
* **Then**: the app names the unsupported target, shows the supported set, and does not create a VM or spend model tokens.

## Technical Plan (Architecture)

### System shape

xentry V1 is one local process with a web server, a background job runner, and a libvirt/KVM VM backend. The model is not the orchestrator. A deterministic runner owns the job state machine. The DeepSeek-backed ADK agent is invoked at two points: extraction and setup authoring or repair. A separate DeepSeek session, with no generator context and no tools, assesses the runner-collected evidence and returns a verdict.

The VM is the trust boundary. Untrusted PoC code and target provisioning run inside the guest. The host fetches and pins inputs, drives libvirt, and collects evidence.

```text
Browser
  |  HTTP + request-integrity token
  v
Web/API process ── SQLite index ── attempt directory + JSONL logs
  |
  v
Job runner (single worker, one VM)
  |-- fetch and pin evidence (SSRF guard) -> evidence store
  |-- extractor (ADK + DeepSeek, no tools) -> typed facts
  |-- setup author (ADK + DeepSeek, no tools) -> setup script + PoC wrapper
  |-- libvirt/KVM VM: create -> provision -> readiness -> freeze
  |     -> nonce -> null actor -> real actor -> evidence
  |-- validator session (DeepSeek, no tools, fresh context) -> LlmVerdict
  |-- destroy VM -> projection into jobs and validations
  v
SSE or polling -> UI (state, verdict, authority, logs)
```

### Components

| Component | Responsibility |
| --- | --- |
| Web/API | Server-rendered pages, JSON endpoints, SSE, request-integrity token, CSRF/Origin/Host checks, UI state and verdict display. |
| Job runner | Queue claim, state machine, timeouts, cancellation, retries, cleanup, validator invocation. |
| Fetcher and evidence store | Source-aware fetch, SSRF guard, byte caps, content-addressed storage, manifests, bounded evidence bundle. |
| Target pack registry | Checked-in manifests for base image, resources, pinned versions, actor user, provisioning mode, PoC artifact, probe, destroy policy. |
| Agent runtime | ADK plus LiteLLM/DeepSeek, used only for extraction and setup authoring or repair. No fetch or execute tools. |
| Validator client | Direct LiteLLM call to DeepSeek with a fixed versioned prompt, no tools, and a structured verdict. |
| VM driver | libvirt domain lifecycle, snapshots, guest exec transport, port forwards, destroy. |
| Storage | SQLite index plus per-job attempt directories and append-only JSONL event logs. |

### Runner state machine

Job states:

```text
queued -> fetching -> extracting -> planning -> creating -> provisioning
       -> ready -> running_poc -> validating
       -> completed | failed | cancelled | interrupted
       -> destroying -> done
```

`completed` is a job state, not a verdict. The verdict is a separate field: `reproduced`, `not_reproduced`, `inconclusive`, or `not_run`. A job can complete with `not_reproduced`.

The runner writes an intent event before each tool call or guest command and a result event after it. A crash leaves the in-flight action visible. The runner invokes the validator unconditionally after the PoC; the agent cannot call validate or destroy.

Retry rules:

* Setup repair: one bounded repair per attempt, using only the classified log and typed facts.
* PoC rerun: one rerun for transient infrastructure failure, never for a failed exploit.
* Dirty Frag: any retry gets a fresh VM because the page cache is contaminated.
* Every retry gets a fresh attempt directory and records the previous failure.

### Web UI and API

Four screens and one help modal:

* **New Job**: paste the CVE and PoC links, run Check links, review the pre-run plan, then Start.
* **Jobs**: job list with state, verdict, authority, and creation time.
* **Job Detail**: stage timeline, filterable logs, validator verdict and evidence first, agent summary separately labeled non-authoritative.
* **System**: preflight checks, orphan-domain banner, caps, and target estimates.

API surface:

```text
POST /api/jobs                 {cve_url, poc_url} + token -> job id
GET  /api/jobs                 list
GET  /api/jobs/{id}            job row plus latest state
GET  /api/jobs/{id}/events     SSE stream with backfill
POST /api/jobs/{id}/cancel     request cancellation
POST /api/links/check          fetch and summarize both links before a job
POST /api/preflight            libvirt, KVM, images, DeepSeek, database, bind mode
GET  /api/jobs/{id}/bundle     downloadable audit bundle
```

The mutation token is generated at startup, stored in a 0600 file, injected into the same-origin server-rendered page, and required in the `X-Xentry-Token` header on every mutation. CORS denies cross-origin reads. Origin and Host checks are on. Mutations require a JSON content type. The token is request integrity, not a user account.

The UI vocabulary is fixed: job state, verdict, and verdict authority. "Succeeded" and "verified" are banned. The agent summary is always secondary to the validator evidence.

### Target packs

A target pack is a checked-in directory with a manifest and optional hand-written hooks. The generic pipeline does not branch on target ids. The manifest declares:

```text
target_id, cve_ids, base_image, image_sha256, resources,
provisioning: prebuilt | generated, kernel, packages, actor_user,
poc {repository, commit, files, build, toolchain, invocation_template},
probe {nonce_placement, command_or_http_request, expected_evidence},
destroy_policy, timeouts, pack_version, what_proves, what_does_not_prove
```

The first three packs are `prebuilt`: their setup scripts are hand-reviewed once for malicious content and hash-pinned for V1 acceptance. The normal flow is `generated`: the LLM writes and repairs the setup script without human review. A dummy fourth pack with `provisioning: generated` must run without edits outside its directory and without human review.

Target-specific plan:

* **PHP2Shell, CVE-2026-109618**: Ubuntu 24.04 base with PHP 8.4.26 and Apache mod_php built natively from the PoC repository's configure flags and `php.ini`. Actor runs as `xentry`. The runner writes a nonce file readable by the web user, invokes the PoC with `--cmd` to write it to the web root, and fetches it over HTTP. Version evidence: `php -v` and the loaded Apache module.
* **GitLab, CVE-2026-85706**: Ubuntu 24.04 base with a pinned GitLab Omnibus package and its dependencies. The nonce file is owned by the GitLab service user and placed outside the document root. The Go PoC is built in the guest and run with `-u` and `-f`. Version evidence: the GitLab version endpoint.
* **Dirty Frag, CVE-2026-43500**: Ubuntu 24.04.4 with the pinned vulnerable kernel `6.17.0-23-generic`. The C PoC is built in the guest. The runner drives a PTY root shell and runs a command that reads a root-only nonce. Version evidence: `uname -r`. The VM is destroyed on every path.

### Verification path

The runner owns the evidence path:

1. Provision the target and run readiness and version/precondition checks.
2. Freeze the provisioned state with a VM snapshot.
3. Generate a 128-bit nonce with `secrets.token_hex(16)` and place it where the actor has no direct read access.
4. Run the null actor, then the probe. A null actor that produces the nonce fails the job before the LLM validator.
5. Restore the frozen state, generate a fresh nonce, run the real actor, and collect raw evidence.
6. Invoke the validator session.

The validator session receives only the immutable evidence bundle: the target pack probe spec, the pinned PoC, the generated setup script and wrapper, the raw transcript (commands, stdout/stderr, exit codes, HTTP responses, version checks), the nonce value and placement, the null-actor result, and the precondition evidence. It does not receive the generator's chat history, plan, repair history, or final summary.

The validator returns:

```json
{
  "verdict": "reproduced | not_reproduced | inconclusive",
  "reason_code": "closed reason code",
  "evidence_refs": ["transcript line or artifact hash"],
  "model": "provider/model-id",
  "prompt_hash": "sha256:..."
}
```

The runner writes the validation row with `authority: llm`, the model id, the prompt hash, the nonce id, and the evidence hash. The UI labels the verdict `llm_assessed`. V1 accepts that the validator can be fooled; the full harness-owned contract replaces it later.

Per-target probes:

* **PHP2Shell**: the nonce is written to a protected path; the RCE command reads it into the web root; the runner performs its own HTTP GET. The PoC's `--fetch` output is not the pass condition.
* **GitLab**: the runner creates the nonce, passes its path to the PoC, and parses the leaked response. The actor is not the GitLab service user.
* **Dirty Frag**: the runner drives the root shell and reads a root-only nonce. The PoC's printed `uid 0` is not sufficient.

Regression fixtures include known-reproduced and known-not-reproduced transcripts, a null-actor case, and a prompt-injection transcript.

### VM harness and isolation

`qemu:///session` is tested first. It provides user-mode networking, local qcow2 overlays, KVM access, and no host devices. `qemu:///system` is used only if a target requires it, through a root-owned broker with fixed verbs and peer-credential checks; the app stays out of the `libvirt` group.

Domain template: virtio disk and network, serial console, no host mounts, no 9p or virtiofs, no USB, no display or SPICE, no shared clipboard, no host devices. Port forwards bind to `127.0.0.1`. Domains are transient, have no autostart, and are destroyed and undefined on every exit path.

VM lifecycle:

```text
verify base image hash -> create overlay and cloud-init seed -> boot
-> wait for SSH -> provision -> readiness and version checks -> snapshot
-> nonce -> null actor -> probe -> restore -> fresh nonce -> actor -> probe
-> evidence -> validator -> destroy -> remove overlay and ISO
```

Egress control: provisioning gets a logged build window to package mirrors and pinned source URLs. After provisioning, a default-deny rule blocks guest egress to the host LAN and the internet, and an egress test fails closed. The implementation can use a host-side allowlist proxy or per-VM nftables; the plan records which one the Phase 0 spike proves.

Dirty Frag's destroy is a security control. A failed destroy is `security_cleanup_failed`, not a generic job failure.

WSL2 operational checks: `/dev/kvm` after restart, libvirtd startup, monotonic durations, and memory fit for a 4+ GB GitLab guest.

### Ingestion and evidence

Source detection:

* NVD: CVE API JSON.
* cve.org: CVE JSON record or API.
* GitHub advisory: advisory API.
* GitHub repository: default-branch commit, README, named text files, and tarball at that commit.
* Generic page: HTML-to-text with script and style removal.

Fetch caps: 256 KB per artifact, content-type check, timeout, redirect cap of three, no cookies or auth headers, and an SSRF guard that rejects loopback, private, link-local, multicast, and cloud metadata addresses on every redirect. The guard logs the resolved IP and the allow-or-deny decision.

The evidence store is content-addressed. Each artifact has a SHA-256, source, URL, commit, retrieval time, and license. The model receives a bounded bundle of quoted excerpts and hashes, capped at roughly 20k tokens, not raw HTML.

The PoC is pinned by commit and hash. The VM builds it; nothing is cloned at run time. No PoC code is built or executed on the host.

### Model and agent integration

ADK is used behind an `AgentRuntime` interface with `LiteLlm(model="deepseek/deepseek-chat")`. The agent has two declared calls:

* **Extractor**: reads cited excerpts and returns typed facts with evidence references. No tools.
* **Setup author or repair**: reads typed facts and the target pack and returns a setup script and PoC wrapper. No fetch or execute tools; the runner writes the files.

The validator is a direct LiteLLM call, not an ADK agent: fixed system prompt, no tools, no session history, no shared state with the generator.

The runner logs every model request and response, the model id returned by the provider, token counts, prompt hash, and step budget. If the ADK spike fails its tool-call threshold, a direct LiteLLM function-calling loop replaces it behind the same interface.

Prompt injection is assumed to succeed at the text level. Controls are the tool schemas, the two-stage model use, the absence of a fetch tool, the VM boundary, the egress policy, and the runner-owned validator.

### Storage and audit

SQLite is a rebuildable index:

```text
jobs(id, cve_id, poc_url, target_id, state, created_at, started_at, finished_at,
     result, reason_code, image_sha256, attempt_dir, manifest_hash, agent_summary)
tool_calls(id, job_id, seq, tool, params_json, params_sha256, started_at,
           finished_at, status, result_path, result_sha256)
validations(id, job_id, target_pack_id, target_pack_version, validator_kind,
            validator_model, validator_prompt_hash, verdict, reason_code,
            evidence_json, evidence_sha256, null_actor_passed, nonce_id, ts)
artifacts(id, job_id, kind, path, sha256, bytes)
schema_version(version)
```

The per-job attempt directory is authoritative: manifest, raw evidence, scripts, VM logs, transcript JSONL, validator input and output, and `outcome.json` written last and atomically. Failed jobs are retained; bulky overlays and archives are pruned by policy. Redaction runs before any write. Secrets stay in `.env` at 0600 and never enter the guest or the logs.

### Interfaces

```text
VmDriver:      create(profile), exec(user, argv, tty), copy_in, copy_out,
               snapshot, restore, reboot, destroy, get_ip
GuestExec:     run(user, argv, timeout) -> command result
HttpProbe:     get(url, timeout) -> status, headers, body
Fetcher:       fetch(url) -> bounded artifact + manifest
EvidenceStore: put(bytes, manifest) -> hash; get(hash)
AgentRuntime:  extract(excerpts) -> facts; author_setup(facts, pack) -> script
ValidatorClient: assess(evidence_bundle) -> LlmVerdict
JobRunner:     submit, cancel, recover, sweep_orphans
```

The detailed file list and function boundaries are fixed in the Implementation Plan section.

### Security and threat model

* The app is local-only by default. WSL2 localhost forwarding means "bind 127.0.0.1" is not a complete isolation claim; the token and Host/Origin checks stay on.
* SSRF is limited by scheme checks, DNS resolution checks, redirect re-checks, byte caps, and no agent fetch tool.
* Prompt injection is contained by typed-fact extraction, no tool-capable context, VM isolation, egress control, and the validator.
* `qemu:///system` is root-equivalent for a `libvirt`-group user; V1 prefers session mode and records the risk if system mode is needed.
* Guest root is expected during provisioning; the VM boundary and the absence of host mounts/devices are the controls. VM escape is a residual risk.
* Dirty Frag contaminates the page cache; destroy is mandatory.
* No container runtime is used in xentry or target provisioning.

### Deferred decisions

* Session versus system libvirt after the Phase 0 spike.
* One target VM versus a second attacker VM after the PHP2Shell and GitLab probes are tested.
* Single process versus web plus worker after the kill-and-restart test.
* LAN policy for a second user.
* GitLab Omnibus version and resource sizing.
* Dirty Frag kernel source and PTY wrapper details.
* SQLite versus a manifest plus JSONL only.
* ADK survival after the spike.
* Web framework and live-log transport.
* Deployment unit.

### What each target proves and does not prove

* **PHP2Shell**: proves RCE in the pinned PHP 8.4.26 and Apache build through a nonce file. Does not prove other PHP builds, other SAPIs, or real-world exploitability.
* **GitLab**: proves an unauthenticated file read of the runner's nonce file. Does not prove other GitLab versions, other file paths, or broader data access.
* **Dirty Frag**: proves uid 0 on the pinned vulnerable kernel through a root-only nonce. Does not prove persistence, other kernels, or reliability on patched builds.
* **Overall**: V1 records a lab reproduction with an LLM-assessed verdict. It is not a deterministic proof and not a production risk assessment.

## Alternatives Considered

### 1. Agent-owned tool trajectory instead of a runner-owned sequence

* **Pros**: The agent can choose the next step from the observed result, which is flexible for unexpected failures; there are fewer runner states to define.
* **Cons**: The job state becomes model output. The agent can choose when to validate, retry, or destroy, and a malformed tool call can leave a VM running. The concept also hands the model a success verb.
* **Reason for Rejection**: Rejected. The runner owns the sequence, and the model is called only for extraction and setup authoring or repair. A fully deterministic pipeline without the agent was also rejected because it removes the requested LLM capability. Revisit if the agent adds no value over fixed steps.

### 2. Host execution of the PoC instead of a target-side non-root actor

* **Pros**: No second environment to build; the PoC runs where the operator can watch it; the target VM needs fewer tools.
* **Cons**: The PoC is untrusted code from the internet. Building or running it on the host exposes the workstation, the libvirt socket, and the DeepSeek key. It contradicts the rule that the VM is the isolation boundary.
* **Reason for Rejection**: Rejected. The PoC is pinned on the host but built and run inside the target VM as a dedicated non-root actor. A second attacker VM was also rejected as the default because it doubles cost and breaks the one-VM assumption; it remains the fallback if same-VM validation cannot be made causal.

### 3. Human-authored deterministic validators instead of an independent LLM validator

* **Pros**: A checked-in validator is reproducible and cannot be persuaded by a prompt. It would close the self-reported-success gap more strongly than an LLM.
* **Cons**: It adds a validator registry, target-specific code, and a human maintenance burden. The owner chose the independent-session approach for V1.
* **Reason for Rejection**: Rejected for V1. The chosen path is a checked-in target-pack probe with a fresh nonce and null actor, plus a separate DeepSeek session with no generator context and no tools. The verdict is labeled `llm_assessed`; human-authored deterministic validators return with the full harness contract. The full v2 oracle was rejected for scope and schedule.

### 4. Model-callable `validate` and `destroy_vm` tools instead of runner steps

* **Pros**: The five-tool shape matches the original flow diagram and is easy to explain. The agent can react to a failed check.
* **Cons**: The model chooses the decision and the teardown. It can call validate with a weaker expected value, validate before the PoC, or skip destroy. The tool trajectory becomes the state machine.
* **Reason for Rejection**: Rejected. The runner calls the validator and destroy unconditionally. If the five-tool shape is kept for the concept, the tools are requests and the runner enforces order and parameters.

### 5. Regenerating the first three setup scripts on every run instead of hand-reviewed bootstrap scripts

* **Pros**: The generated path is tested from the first run, and the product claim is honest from the start.
* **Cons**: A reactive or malicious setup script can manufacture the evidence the validator sees. Regenerating also moves the environment under test on every run.
* **Reason for Rejection**: Rejected for the first three targets. Their setup scripts are hand-reviewed once for malicious content and hash-pinned for V1 acceptance. After those three, the normal flow is fully autonomous and the LLM generates and repairs setup scripts. Revisit if a generated script is found to manufacture evidence; the validator and null actor are the controls.

### 6. A UI-first build instead of an engine with a thin UI

* **Pros**: A UI-first build produces a visible demo quickly, and the user can click through the flow early.
* **Cons**: The engine tends to grow inside request handlers, which makes long jobs, cancellation, and recovery harder. A CLI-only product was also rejected because the stated requirement is a web UI.
* **Reason for Rejection**: Rejected. The engine and runner are built behind a programmatic interface first, then a thin server-rendered UI and an SSE endpoint read the persisted state. The UI is an adapter, not the core.

### 7. One vertical slice instead of all three targets in V1

* **Pros**: One target is faster to finish and proves the pipeline with less environment work.
* **Cons**: One target does not prove the target-pack boundary, the kernel path, or the different validation types.
* **Reason for Rejection**: Rejected for the product scope. All three remain V1 acceptance targets, but the build order is PHP2Shell, GitLab, then Dirty Frag. Dirty Frag is the cut line: if its PTY validation or kernel pin cannot be observed reliably, it becomes V1.1 rather than weakening the validator.

### 8. `qemu:///system` as the default instead of `qemu:///session`

* **Pros**: System libvirt has the familiar service model, system networks, and broader device support.
* **Cons**: A `libvirt`-group user is close to root on the host, and the system QEMU process runs as root. A guest root shell then becomes host file access. The app has no auth by default.
* **Reason for Rejection**: Rejected as the default. V1 tests `qemu:///session` first, which provides user-mode networking, local overlays, and KVM access without root-equivalent authority. System mode requires a root-owned broker, a dedicated user, and a recorded risk acceptance.

### 9. HTML-only ingestion instead of source-aware ingestion

* **Pros**: One fetch path works for any page, and the implementation is smaller.
* **Cons**: CVE pages are often JavaScript-heavy or expose structured JSON; a PoC link is usually a repository, so the HTML page gives the README and file list but not the source the model needs. Sending raw HTML burns context and increases prompt-injection surface.
* **Reason for Rejection**: Rejected. V1 detects the source shape: NVD and cve.org JSON, GitHub advisory and repository APIs, a pinned tarball at a commit, and HTML-to-text as a fallback. The model receives a bounded evidence bundle with hashes and quotes.

### 10. SQLite for everything instead of filesystem attempt directories plus a SQLite index

* **Pros**: One store is easier to query and back up, and there is no split between rows and files.
* **Cons**: Command output, setup logs, and LLM transcripts are append-only and large. SQLite rows bloat, `sqlite3` inspection becomes painful, and log retention couples to schema migrations. A no-database option was also rejected because it makes job and validator queries harder.
* **Reason for Rejection**: Rejected. The per-job attempt directory and append-only JSONL logs are authoritative. SQLite is a rebuildable index for jobs, tool calls, validations, and artifacts.

### 11. A blocking HTTP request instead of an asynchronous queue

* **Pros**: Blocking is simpler and needs no queue, worker, or event stream.
* **Cons**: GitLab runs for tens of minutes. The browser times out, the server worker is tied up, and a restart loses the job. A refresh would cancel the work.
* **Reason for Rejection**: Rejected. Jobs are asynchronous and queued with one worker, SSE with polling fallback, cancellation, and startup recovery.

### 12. Separate web and worker processes instead of one process with a background worker

* **Pros**: Separation isolates a crash, allows independent restart, and scales the worker separately.
* **Cons**: A message broker or supervisor adds operational surface for one or two users. The queue and claim already live in SQLite.
* **Reason for Rejection**: Rejected for V1. One process runs the web server and a background worker with a durable claim. Revisit if restart robustness proves insufficient; split the worker and keep SQLite as the queue.

### 13. One base image instead of a small per-target image catalog

* **Pros**: One image is simpler to build, hash, and maintain.
* **Cons**: Dirty Frag needs a pinned vulnerable kernel, GitLab needs more memory and disk, and PHP2Shell needs a specific PHP build. Forcing one image hides those differences or makes the image unusable for one target.
* **Reason for Rejection**: Rejected. V1 uses a small, hash-pinned catalog: one Ubuntu 24.04 base where it works, plus a pinned-kernel image or a kernel package stored at image-build time for Dirty Frag. Resources belong in the target pack.

### 14. Agent re-authoring the exploit instead of pinning the public PoC

* **Pros**: Re-authoring can adapt a PoC that does not build, and it gives the agent more freedom.
* **Cons**: It adds a second source of error, weakens the link between the linked PoC and the validation, and turns the agent into an exploit developer. The public PoC is the artifact under test.
* **Reason for Rejection**: Rejected for V1. The backend pins the commit and hash, copies the artifact into the VM, builds it there, and the agent writes only the build and invocation wrapper. Revisit if a public PoC cannot be built or invoked.

### 15. No token on loopback instead of a request-integrity token

* **Pros**: No token is the simplest local experience; there are no accounts to manage.
* **Cons**: A malicious website can POST to `http://127.0.0.1` from the user's browser. WSL2 also forwards Windows localhost to WSL services. Full user accounts were also rejected because one or two users do not need identity management.
* **Reason for Rejection**: Rejected. V1 uses no user accounts, but every mutation requires a startup-generated request-integrity token, plus CSRF, Origin, and Host checks and a Host allowlist.

### 16. A direct LiteLLM loop without an ADK spike instead of testing ADK first

* **Pros**: A direct loop is smaller, easier to audit, and avoids a young framework. The old tree already had an 80-line DeepSeek-compatible client.
* **Cons**: It gives up ADK's session and event model without measuring whether they help. The old client was written for the old pipeline and is not proven for this runner.
* **Reason for Rejection**: Rejected for now. V1 runs a one-week ADK plus LiteLLM plus DeepSeek spike behind an `AgentRuntime` interface, with a direct LiteLLM function-calling loop as the fallback. Revisit if the spike shows poor tool-call reliability or if the runner-owned sequence needs no agent.

### 17. Reusing the old tree instead of ground-up code

* **Pros**: The old tree has a working QEMU harness, content-addressed evidence store, recipe fixtures, and failure notes. Reuse could save weeks.
* **Cons**: The old tree is roughly 12,000 lines with a Postgres/Alembic stack and about 20 subsystems. Importing it re-creates the audit problem V1 is trying to escape.
* **Reason for Rejection**: Rejected. V1 is ground-up, using the old LLM client, evidence-store shape, fixtures, failure notes, and ADRs as references only. Revisit if the libvirt harness exceeds its schedule; the old QEMU code remains a reference, not a dependency.

### 18. Deferring all verification work instead of keeping the nonce and null actor now

* **Pros**: Deferring everything gets the end-to-end path running sooner with less code.
* **Cons**: It repeats the old failure immediately: a PoC that prints its own marker or a setup script that writes the expected file passes. The self-reported success returns.
* **Reason for Rejection**: Rejected. V1 keeps a runner-owned probe, a fresh nonce, and a null actor now, adds the independent LLM validator, and defers the deterministic version-range probe, fixed-build control, and immutable bank. Revisit when the end-to-end path is stable.

### 19. One job status field instead of separate state, verdict, and authority

* **Pros**: One field is simpler to store and display.
* **Cons**: "Finished" and "reproduced" are different claims. One field lets a completed pipeline read as a successful exploit, and the agent summary fills the gap.
* **Reason for Rejection**: Rejected. The UI and database keep job state, verdict, and verdict authority separate. "Succeeded" and "verified" are banned from the UI.

### 20. Blind submit instead of a pre-run plan and link check

* **Pros**: Blind submit is one step and gets the job started immediately.
* **Cons**: The user discovers the target, version, truncation, and validator after committing an hour. A wrong link or unsupported CVE wastes a VM.
* **Reason for Rejection**: Rejected. The New Job flow includes a Check links step and a pre-run plan showing the target pack, image, kernel, resources, probe, and caps before Start.

### 21. Ad hoc schema changes instead of versioned migrations

* **Pros**: Ad hoc columns are faster in the first week.
* **Cons**: The first added column breaks existing databases, and the audit log is the product. A deployment can silently corrupt or lose job history.
* **Reason for Rejection**: Rejected. V1 has a schema version, forward-only migrations, a backup before migration, and a refusal to start against a newer database.

### 22. Same-session self-check instead of a second LLM session

* **Pros**: A same-session check is cheaper and sees the full context.
* **Cons**: The generator's framing, plan, and repair history carry over, so the check is not independent. The same session is more likely to defend its own work.
* **Reason for Rejection**: Rejected. The validator is a second DeepSeek session with a fixed prompt, no generator history, no tools, and raw evidence only. The residual risk is correlated model failure and prompt injection; the verdict is labeled `llm_assessed`.

## Non-Functional Requirements

* **Security and privacy**: loopback binding, request-integrity token, CSRF/Origin/Host checks, SSRF guard, two-stage prompt-injection controls, VM boundary, no host mounts or devices, no secrets in the guest or logs, and no container runtime. The system libvirt risk is recorded if the broker path is used.
* **Performance and latency**: one VM at a time. GitLab provisioning is expected to take 20–40 minutes; PHP2Shell and Dirty Frag are shorter. The UI uses SSE with polling fallback and never blocks an HTTP request on a job. Model calls have per-call timeouts and per-job token caps.
* **Reliability and recovery**: append-only events, per-phase timeouts, cancellation, idempotent destroy, startup orphan sweep, and interrupted-job marking. A failed destroy is a visible security failure, not a silent cleanup miss.
* **Storage and retention**: per-job attempt directories and JSONL are authoritative; SQLite is rebuildable. Failed jobs are retained; overlays and downloaded archives are pruned by policy. The disk ceiling stops new jobs before exhaustion.
* **Rollout and rollback**: a systemd user unit with a local virtual environment; forward-only migrations with a backup; a schema newer than the code refuses to start; an upgrade marks in-flight jobs interrupted and destroys their VMs.

## Additional Resources

* `concepts_brief.md` — the approved V1 brainstorm brief.
* `docs/adr/0001-v1-reset.md` — the decision record for the reset and the independent LLM validator.
* The three pinned PoC repositories and the CVE records for CVE-2026-109618, CVE-2026-85706, and CVE-2026-43500.

## Future Improvements

* Replace the LLM-assessed verdict with the full harness-owned contract: deterministic validators, version-range probes, fixed-build negative controls, and an immutable bank.
* Add a second attacker VM if same-VM validation cannot be made causal.
* Add more target packs without changing the pipeline, and add Windows or client-side targets only with their own isolation design.
* Add cached base images with a corrected key, parallel job execution, and a proper LAN auth story if the user count grows.
* Add model-free revalidation of stored recipes and a cost dashboard once the pricing table is versioned.

## Detailed Implementation Plan

### Implementation order

1. Project skeleton, configuration, SQLite schema and migrations, event log.
2. Fetcher, SSRF guard, source adapters, evidence store.
3. Target pack loader, the three packs, and the dummy fourth pack.
4. Fake VM driver and the runner state machine with scripted model and validator clients.
5. Web UI, API, SSE, request-integrity token, and security middleware.
6. Real libvirt driver, guest SSH transport, cloud-init seed, network and egress control.
7. PHP2Shell end to end, then GitLab, then Dirty Frag.
8. Hardening: prompt-injection corpus, recovery, bundle, systemd, acceptance runs.

### Defaults fixed by this plan

* Python 3.12, FastAPI, Jinja2 server-rendered pages, `sse-starlette`, `httpx`, Pydantic, PyYAML.
* `google-adk` plus `litellm` for the two generator calls; a direct LiteLLM call for the validator. ADK sits behind `AgentRuntime`; the direct loop is the fallback.
* `libvirt-python` for domain lifecycle and `asyncssh` for guest exec, copy, and PTY.
* `qemu:///session` first. System libvirt is out of scope unless the Phase 0 spike proves session mode cannot run the targets; then the root-owned broker is a separate change.
* One worker, one VM at a time. A second attacker VM is not built in V1; it remains the documented fallback.
* One process with a background worker. Splitting the worker is a later change.
* SQLite is the index; per-job directories and JSONL are authoritative.
* The app binds `127.0.0.1`. A second remote user is supported through an SSH local port forward, not LAN exposure.
* GitLab CE 19.2.5 is the pinned vulnerable Omnibus version; the pack records the exact `.deb` URL and SHA-256.
* Dirty Frag uses Ubuntu 24.04.4 with the pinned `6.17.0-23-generic` kernel package; the setup script installs it, reboots, and gates on `uname -r`. If the package is unavailable in Phase 0, the target is re-scoped rather than substituting the host kernel.
* No `cves` table in V1. The job row carries `cve_id`; a fetch cache can be added later.
* The first three setup scripts are checked-in and hand-reviewed once. The normal flow is generated by the LLM.

### Target Files to Create/Modify

#### Project, configuration, and deployment

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `pyproject.toml` | Create | Python 3.12 project metadata; runtime dependencies `fastapi`, `uvicorn[standard]`, `jinja2`, `python-multipart`, `sse-starlette`, `httpx`, `pydantic`, `pyyaml`, `python-dotenv`, `google-adk`, `litellm`, `libvirt-python`, `asyncssh`; dev dependencies `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`. Pin exact versions in the lockfile. Configure ruff, mypy, and pytest. One dependency and tooling source. |
| `README.md` | Create | Install, base-image download, `.env`, run, systemd user unit, supported targets, security model, and limitations. |
| `.env.example` | Modify | Add `XENTRY_TOKEN_FILE`, `XENTRY_SSH_KEY_DIR`, `XENTRY_EGRESS_MODE`, `XENTRY_MAX_TOKENS_PER_JOB`, `XENTRY_MODEL_TIMEOUT_SECONDS`, and `XENTRY_VALIDATOR_MODEL`; keep secrets empty. |
| `.gitignore` | Modify | Keep `.env` ignored; add `var/`, `*.qcow2`, `*.iso`, `*.key`, `*.pem`, and test artifacts. |
| `deploy/xentry.service` | Create | systemd user unit for the local app with a virtual environment, `EnvironmentFile`, `Restart=on-failure`, and `NoNewPrivileges`. Session libvirt pairs with a user unit; system libvirt requires the broker change. |
| `scripts/fetch-base-images.sh` | Create | Download the Ubuntu 24.04 cloud image and the Dirty Frag kernel package; verify SHA-256 against `var/base-images/catalog.yaml`; never execute downloaded content. |
| `scripts/migrate.py` | Create | Apply forward-only SQL migrations; back up the database before a migration; refuse a schema newer than the code. |
| `scripts/run-dev.sh` | Create | Create or reuse `.venv`, install editable dependencies, load `.env`, and run uvicorn with reload. |
| `scripts/preflight.py` | Create | Thin CLI wrapper around `src/xentry/preflight.py` for terminal checks. |
| `scripts/run_target_e2e.py` | Create | Submit one target through the runner with a real VM and print the job state, verdict, authority, and evidence paths. Used for the Phase 2/3 acceptance runs. |
| `var/base-images/catalog.yaml` | Create | Base image name, URL, SHA-256, version, cloud-init requirements, and Dirty Frag kernel package URL and SHA-256. |

#### Prompts

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `prompts/extract.md` | Create | Tool-less extractor prompt: typed facts, evidence citations, no raw HTML, and an `evidence_insufficient` outcome. Versioned and hashed. |
| `prompts/setup.md` | Create | Setup author prompt: typed facts plus target pack, returns setup script and PoC wrapper, no fetch or execute tools, line cap, and no invented versions or URLs. |
| `prompts/repair.md` | Create | Bounded repair prompt: classified log plus typed facts, one repair, no invented artifacts, and a required concrete log line. |
| `prompts/validator.md` | Create | Independent validator prompt: evidence bundle only, no generator context, no tools, structured JSON verdict, reason code, and evidence references. |
| `prompts/README.md` | Create | Prompt versioning, hashing, and regression-fixture policy. |

#### Target packs

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `targets/README.md` | Create | Pack contract, manifest fields, hash pinning, `prebuilt` versus `generated`, probe hooks, and the dummy-pack enforcement test. |
| `targets/php2shell/pack.yaml` | Create | CVE-2026-109618, Ubuntu 24.04 base, 2 vCPU, 4 GB RAM, 20 GB disk, `provisioning: prebuilt`, actor `xentry`, setup hash, PoC pin, probe, destroy policy, timeouts, and what-proves text. |
| `targets/php2shell/setup.sh` | Create | Hand-reviewed native PHP 8.4.26 plus Apache mod_php build/install with pinned source URL and hash, `php.ini`, and readiness check. |
| `targets/php2shell/poc.pin.yaml` | Create | Repository, commit, selected file, build command, toolchain, and invocation template for the PHP2Shell Python exploit. |
| `targets/php2shell/probe.py` | Create | Places a nonce readable by the web user, runs the PoC `--cmd` to write it to the web root, fetches it over HTTP, records `php -v` and the Apache module, and returns `ProbeEvidence`. |
| `targets/gitlab/pack.yaml` | Create | CVE-2026-85706, Ubuntu 24.04 base, 4 vCPU, 8 GB RAM, 40 GB disk, `provisioning: prebuilt`, actor, setup hash, GitLab 19.2.5 pin, probe, destroy policy, and timeouts. |
| `targets/gitlab/setup.sh` | Create | Hand-reviewed Omnibus `.deb` download, SHA-256 check, install, service readiness, and version endpoint check. |
| `targets/gitlab/poc.pin.yaml` | Create | Go PoC repository, commit, build command, and `-u`/`-f` invocation template. |
| `targets/gitlab/probe.py` | Create | Creates a git-owned nonce outside the document root, runs the Go PoC with the nonce path, parses the leaked response, records the GitLab version, and returns evidence. |
| `targets/dirtyfrag/pack.yaml` | Create | CVE-2026-43500, Ubuntu 24.04.4 base, pinned `6.17.0-23-generic` kernel package URL and SHA-256, 2 vCPU, 2 GB RAM, 20 GB disk, `provisioning: prebuilt`, actor, setup hash, C PoC pin, PTY probe, mandatory destroy, and timeouts. |
| `targets/dirtyfrag/setup.sh` | Create | Installs the pinned kernel package, updates the boot entry, reboots, verifies `uname -r`, and installs the C build tools. |
| `targets/dirtyfrag/poc.pin.yaml` | Create | C PoC repository, commit, source file, `gcc` build command, and invocation. |
| `targets/dirtyfrag/probe.py` | Create | Drives a PTY root shell, runs a command that reads the root-only nonce, records `uname -r`, verifies the VM was fresh, and returns evidence. |
| `targets/_dummy/pack.yaml` | Create | Test-only `provisioning: generated` pack with a synthetic CVE and no real target. Proves the generic pipeline needs no edits. |
| `targets/_dummy/probe.py` | Create | Canned probe evidence for the dummy pack's pass and fail tests. |

#### Database and migrations

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `migrations/001_initial.sql` | Create | `jobs`, `tool_calls`, `validations`, `artifacts`, and `schema_version` tables; indexes on job state and timestamps; foreign keys. |
| `migrations/README.md` | Create | Forward-only policy, file naming, backup rule, and refusal to start on a newer schema. |

#### Core services

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `src/xentry/__init__.py` | Create | Package marker and version. |
| `src/xentry/config.py` | Create | Load `.env`, validate required values, resolve absolute paths, check file modes, expose `Settings` and per-target limits. Reject relative SQLite URLs and a v2-shaped data directory. |
| `src/xentry/models.py` | Create | Pydantic models and enums: `JobState`, `Verdict`, `VerdictAuthority`, `FailureReason`, `Job`, `ToolCall`, `ValidationRecord`, `Artifact`, `TargetPack`, `ProbeEvidence`, `LlmVerdict`, `RunLimits`. |
| `src/xentry/db.py` | Create | SQLite connection factory with WAL, foreign keys, busy timeout; migration runner; repository functions; claim query; job state projection. |
| `src/xentry/security.py` | Create | Startup token generation and 0600 storage, constant-time comparison, Origin/Host checks, CSRF helpers, security headers, and secret redaction patterns. |
| `src/xentry/events.py` | Create | Per-job append-only JSONL event writer, event schema, monotonic timestamps, SSE formatting, backfill reader, and redaction before write. |
| `src/xentry/queue.py` | Create | Enqueue, claim one job, worker lock, cancellation flag, retry bookkeeping, and recovery query. |
| `src/xentry/runner.py` | Create | Runner-owned pipeline and state machine: fetch, extract, plan, create, provision, freeze, nonce, null actor, real actor, evidence, validate, destroy, project outcome. Per-phase timeouts, retry policy, and destroy on every path. |
| `src/xentry/cleanup.py` | Create | Startup orphan sweep by domain prefix, overlay and ISO removal, interrupted-job marking, idempotent destroy, and `security_cleanup_failed`. |
| `src/xentry/fetch.py` | Create | `httpx` fetch with http/https only, DNS resolution and private/loopback/link-local/metadata rejection, redirect re-checks, byte and time caps, content-type checks, no cookies or auth, and decision logging. |
| `src/xentry/sources.py` | Create | Source detection and adapters for NVD API, cve.org JSON, GitHub advisory API, GitHub repository API and pinned tarball, and generic HTML-to-text. Returns a bounded evidence bundle with hashes and citations. |
| `src/xentry/evidence.py` | Create | Content-addressed store under `var/evidence/<sha256>`, manifests, quote verification, and a roughly 20k-token evidence bundle builder. |
| `src/xentry/packs.py` | Create | Load and validate `targets/*/pack.yaml`, verify script and PoC hashes, import each pack's `probe.py` from its checked-in directory, reject unknown targets, and expose `TargetPack`. |
| `src/xentry/agent.py` | Create | `AgentRuntime` protocol, `AdkRuntime` using ADK plus `LiteLlm(model="deepseek/deepseek-chat")`, direct LiteLLM fallback, prompt loading and hashing, extraction/setup/repair calls, request and response logging, and token caps. |
| `src/xentry/validator.py` | Create | Build the evidence bundle without generator context, call LiteLLM directly with `prompts/validator.md`, validate the JSON verdict with Pydantic, and write the `validations` row with `authority: llm`. |
| `src/xentry/bundle.py` | Create | Build the downloadable audit bundle with a hash manifest and no secrets; include evidence, scripts, transcript, validation, and outcome. |
| `src/xentry/preflight.py` | Create | Check libvirt connection, KVM, base image and kernel presence, DeepSeek reachability and auth, database writability, bind mode, and orphan domains. Shared by startup and the System screen. |

#### Web application

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `src/xentry/web/__init__.py` | Create | Package marker. |
| `src/xentry/web/app.py` | Create | FastAPI app factory, lifespan startup (config, DB, token, recovery, worker), middleware (token, Origin/Host, security headers, JSON content type), Jinja2 setup, and static files. |
| `src/xentry/web/routes.py` | Create | UI and JSON routes: create/list/detail jobs, cancel, bundle, link check, preflight, and system. |
| `src/xentry/web/sse.py` | Create | SSE endpoint with backfill, heartbeat, reconnect support, and terminal-state close. |
| `src/xentry/web/schemas.py` | Create | Request and response models for job creation, link check, plan, preflight, and error responses. |
| `src/xentry/web/deps.py` | Create | Dependencies for settings, database, token, current job, and template context. |

#### VM harness

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `src/xentry/vm/__init__.py` | Create | Package marker. |
| `src/xentry/vm/driver.py` | Create | `VmDriver` protocol and value objects: `VmProfile`, `VmState`, `SnapshotRef`, `CommandResult`. |
| `src/xentry/vm/libvirt_driver.py` | Create | libvirt-python implementation: fixed domain XML, create/start/stop/destroy/undefine, snapshots, port forwards, overlay and ISO paths. |
| `src/xentry/vm/fake_driver.py` | Create | In-memory fake driver with canned commands, HTTP responses, snapshots, and failure injection for tests. No KVM required. |
| `src/xentry/vm/guest.py` | Create | `asyncssh` transport with a per-job key: exec, copy in/out, PTY sessions, reboot wait, timeouts, and complete command logging. |
| `src/xentry/vm/probes.py` | Create | `HttpProbe`, guest file checks, nonce placement helpers, version checks, and probe-evidence capture. |
| `src/xentry/vm/network.py` | Create | User-mode networking, loopback-bound port forwards, egress allowlist or nftables rules, egress test, and attempt logging. |
| `src/xentry/vm/images.py` | Create | Base image catalog loading, SHA-256 checks, cloud-init seed ISO creation via `cloud-localds`, per-job overlays, per-job SSH key generation, and cleanup. |

#### Templates and static files

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `templates/base.html` | Create | Page frame, navigation, CSP, token meta tag, CSS and JS includes. |
| `templates/new_job.html` | Create | Link inputs, Check links, fetched/truncated summary, pre-run plan, and Start. |
| `templates/jobs.html` | Create | Job list with state, verdict, authority, and timestamps. |
| `templates/job_detail.html` | Create | Stage timeline, filterable logs, validator verdict and evidence first, agent summary separate, cancel, bundle link. |
| `templates/system.html` | Create | Preflight results, orphan-domain banner, target estimates, and caps. |
| `templates/help.html` | Create | Usage, supported targets, security model, second-user SSH tunnel instructions, and limitations. |
| `static/app.css` | Create | Minimal accessible layout and status styling. |
| `static/app.js` | Create | Token-aware fetch helper, link check, SSE reconnect and backfill, log filters, cancel, and bundle download. No framework. |

#### Tests and fixtures

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `tests/conftest.py` | Create | Temp data directory, test database, settings, token, fake driver, app test client, and scripted model/validator fixtures. |
| `tests/test_state_machine.py` | Create | Allowed transitions, runner-owned validate/destroy, failure paths, and verdict projection. |
| `tests/test_queue_recovery.py` | Create | Claim, single-worker enforcement, kill-and-restart, interrupted marking, and orphan sweep. |
| `tests/test_fetch_ssrf.py` | Create | Private, loopback, link-local, multicast, and metadata rejection; redirect re-check; byte cap; content-type check. |
| `tests/test_sources.py` | Create | NVD, cve.org, GitHub advisory, GitHub repository tarball, and generic HTML detection; citation checks. |
| `tests/test_evidence.py` | Create | Content-addressed store, manifests, quote verification, and token cap. |
| `tests/test_packs.py` | Create | Manifest schema, hash checks, unknown-target rejection, probe import, and the dummy fourth pack requiring no pipeline edits. |
| `tests/test_agent_contract.py` | Create | Extractor/setup prompts, no tools, typed-fact and citation validation, token caps, ADK and LiteLLM runtime parity. |
| `tests/test_validator.py` | Create | Evidence bundle excludes generator context, structured verdict validation, `llm_assessed` authority, and disagreement copy. |
| `tests/test_runner_fake_vm.py` | Create | End-to-end fake-VM path: nonce, null actor, setup repair, PoC failure, destroy on failure, and verdict projection. |
| `tests/test_security.py` | Create | Mutation token, CSRF/Origin/Host, redaction, secret absence, and security headers. |
| `tests/test_ui_vocabulary.py` | Create | No "succeeded" or "verified" in templates; state, verdict, and authority present; agent summary labeled. |
| `tests/test_bundle.py` | Create | Bundle reconstruction, hash manifest, and absence of secrets. |
| `tests/test_prompt_injection.py` | Create | Fake CVE page requesting a host mount and fake PoC printing a marker; both fail with no host effect. |
| `tests/test_vm_libvirt.py` | Create | Real libvirt session smoke test gated by `XENTRY_RUN_VM_TESTS=1`: boot, SSH, snapshot, restore, port forward, egress test, destroy. |
| `tests/fixtures/nvd/CVE-2026-109618.json` | Create | Synthetic NVD record for extraction and source tests. |
| `tests/fixtures/github/php2shell/README.md` | Create | Synthetic PoC README for citation and pinning tests. |
| `tests/fixtures/transcripts/php2shell_pass.jsonl` | Create | Known-reproduced validator fixture. |
| `tests/fixtures/transcripts/php2shell_fail.jsonl` | Create | Known-not-reproduced validator fixture. |
| `tests/fixtures/transcripts/null_actor.jsonl` | Create | Null-actor fixture that must fail. |
| `tests/fixtures/prompt_injection/cve_page.html` | Create | Host-mount injection fixture. |
| `tests/fixtures/prompt_injection/poc_readme.md` | Create | Marker-printing injection fixture. |
| `tests/fixtures/packs/dummy/` | Create | Dummy pack fixtures for the no-pipeline-edit test. |

#### Documentation and decision record

| File | Type | Proposed changes and rationale |
| --- | --- | --- |
| `docs/adr/0001-v1-reset.md` | Create | Records the reversal of the old ADR 0007: runner-owned sequence, model at two declared points, independent LLM validator with accepted risk, no container runtime, and first-three hand review only. |
| `docs/security/threat-model.md` | Create | Web, SSRF, prompt-injection, VM-escape, system-libvirt, secret, and Dirty Frag page-cache risks, with controls and residual risks. |
| `docs/designs/xentry-v1.md` | Create at finalization | Final design document generated from `design_draft.md`. |
| `docs/designs/SITEMAP.md` | Create or modify | Register the design if the designs directory is used. |

### Verification Plan

* **Build**: `python -m venv .venv`, `pip install -e '.[dev]'`, `python -m compileall src`.
* **Unit tests**: `pytest -q`; core modules use the fake VM driver and scripted model/validator clients.
* **Static analysis**: `ruff check src tests`, `ruff format --check`, `mypy src`.
* **Coverage**: `pytest --cov=src/xentry --cov-fail-under=80`; templates, static files, and scripts are excluded.
* **Security tests**: `tests/test_fetch_ssrf.py`, `tests/test_security.py`, and `tests/test_prompt_injection.py` must pass.
* **Recovery test**: kill the worker mid-job, restart, confirm the job is `interrupted`, no domain is running, and no overlay or ISO remains.
* **Real VM smoke test**: `XENTRY_RUN_VM_TESTS=1 pytest -q tests/test_vm_libvirt.py` on a host with nested KVM.
* **Target acceptance**: two consecutive clean runs per target through `scripts/run_target_e2e.py`; the null actor fails; no completed job lacks a validation row tied to its nonce; the verdict is `llm_assessed`.
* **Dummy pack test**: `pytest -q tests/test_packs.py` proves a new `provisioning: generated` target needs no edits outside its directory and no human review.
* **ADK spike**: 20 scripted scenarios with two tools, malformed arguments, and a prompt-injection page. If the valid tool-call rate is below the agreed threshold, switch `AgentRuntime` to the direct LiteLLM loop.
* **Phase 0 gates**: session libvirt boots and destroys one VM; the PHP2Shell native build is repeatable; Dirty Frag's pinned kernel is installable. A failed gate changes the plan before Phase 1, not during acceptance.
* **UI check**: a rendered-page test asserts that "succeeded" and "verified" do not appear and that state, verdict, and authority are separate fields.
