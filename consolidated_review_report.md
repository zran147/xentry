# Consolidated Goldfish Review Report — xentry V1

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (712 lines; FeatureRange 1–519, DetailedRange 520–712)
**Review mode:** Consolidated, uninterrupted full flow (Stages 5–9)
**Date:** 2026-11-05

**Stage reports:**
- [Stage 5 — Initial Zoom Out](zoom_out_report.md)
- [Stage 6 — Comprehension Test](comprehension_report.md)
- [Stage 7 — Critic Review](critic_report.md)
- [Stage 8 — Intermediate Zoom Out](intermediate_zoom_out_report.md)
- [Stage 9 — Implementation Readiness](implementation_readiness_report.md)

## Reviewer status and counts

| Stage | Reviewers | Status | Findings |
| --- | --- | --- | --- |
| 5. Initial Zoom Out | `egm-zoom-out` | completed | 1 Blocker, 12 Major, 4 Nit |
| 6. Comprehension | `egm-comprehension` | completed | 0 Blocker, 17 Major, 6 Nit |
| 7. Critic | `egm-design`, `egm-structural`, `egm-style` | all completed | 5 Blocker, 19 Major, 22 Nit |
| 8. Intermediate Zoom Out | `egm-zoom-out` | completed | 4 Blocker, 8 Major, 2 Nit |
| 9. Implementation Readiness | `egm-implementation-readiness`, `egm-codebase-details`, `egm-style` | all completed; style retried once | 9 Blocker, 18 Major, 7 Nit |

The five stage reports contain 134 findings after each stage's own deduplication. This report consolidates them into 35 action items: 9 Blockers, 16 Majors, and 10 Nits. The traceability matrix at the end maps each consolidated item back to the stage reports.

## Overall verdict

The design is not implementation-ready. The problem is not a missing sentence; it is that V1's scope is a full product rebuild and its central causal-evidence contract is undefined or contradicted. The reviewers found five independent Blockers in the feature specification alone (Stage 7), nine in the implementation plan (Stage 9), and a scope Blocker that the later stages enlarged rather than withdrew.

What holds up:

- The honest `llm_assessed` label and the separation of job state, verdict, and verdict authority are the right direction. They reject the old self-reported-success failure instead of hiding it.
- The runner-owned sequence is the right control plane. The model is limited to extraction and setup authoring; it does not choose validation or teardown.
- The pinned public PoC and the rule that nothing from the PoC is built or run on the host are the right isolation defaults.
- The three target packs are concrete enough to test in principle, and the first-three hand-review compromise is defensible if the generated path is actually exercised.
- The no-container VM boundary is the right intent. The implementation does not yet enforce it.

The design should not proceed to coding as written. The owner must choose one of two paths:

1. **Cut V1 to a single-target verification spine.** The zoom-out reviewers recommend PHP2Shell as the only V1 acceptance target: one input path, one VM, one target pack, the runner-owned nonce/null-actor/evidence path, and a minimal submit/job view. GitLab, Dirty Frag, multi-source ingestion, the four-screen UI/SSE surface, ADK, migrations/backup, and the dummy pack move to V1.x.
2. **Keep all three targets and treat V1 as a multi-harness program.** This requires an explicit line/subsystem/effort budget, the missing contracts below, and an honest statement that V1 is not the narrow reset described in the Problem section.

## Consolidated Blockers

### B-01. V1 is a full product rebuild, not a defensible first version

**Evidence:** The design criticizes v2 for roughly 12,000 lines and about 20 subsystems, then plans roughly 100 file rows across ten areas: a four-screen UI with token, CSRF, Host/Origin, and CSP; source-aware ingestion for five source shapes; a content-addressed evidence store; a five-table SQLite schema with migrations, backup-before-migration, and rollback; a libvirt harness with cloud-init, SSH, snapshots, PTY, port forwards, and egress control; three heterogeneous target harnesses; ADK plus a LiteLLM fallback plus a spike; an audit bundle; a systemd unit; and 23 test and fixture files. No line, subsystem, or effort budget is stated. The later stages enlarge this finding: Stage 7 found five independent Blockers in the feature range alone, and Stage 8 confirmed that the Stage 5 scope verdict still holds.

**Sources:** Stage 5 "V1 Scope Is a Full Product Rebuild" (Blocker); Stage 8 "V1 Scope Verdict Confirmed and Enlarged" (Blocker); Stage 5 "Three Acceptance Targets Require Three Harnesses" (Major); Stage 5 "UI, SSE, and Preflight Surface Is Product Scope" (Major); Stage 6 finding 9 and 11.

**Required action:** Cut V1 to the verification spine: one target (PHP2Shell is the reviewers' recommendation), one input path, the runner-owned nonce/null-actor/evidence path, one validator, a minimal submit/job/evidence view, and minimal storage. Defer GitLab, Dirty Frag, multi-source ingestion, the four-screen UI/SSE surface, ADK, migrations/backup/rollback, and the dummy pack. If all three targets are non-negotiable, state an explicit line/subsystem/effort budget and show how the result remains auditable.

### B-02. Provisioning mode is contradictory; the reviewed hash does not describe what runs

**Evidence:** All three real targets are `provisioning: prebuilt` with setup scripts hand-reviewed once and hash-pinned, yet setup repair still applies to prebuilt packs. A repaired script is therefore an unreviewed, root-privileged script while the pack continues to advertise the reviewed hash. The validator is told it receives "the generated setup script" even for prebuilt packs. The only `generated` pack is the test-only dummy, whose probe returns canned evidence, so the autonomous generated flow is never exercised on a real target. G14's central autonomy claim has no real acceptance evidence.

**Sources:** Stage 5 "Autonomous Generated-Provisioning Claim Is Exercised Only by a Synthetic Pack" (Major); Stage 7 "Generated vs. prebuilt flow contradiction" (Blocker); Stage 8 "Prebuilt Packs Still Execute the Repair Path" (Blocker); Stage 6 finding 7.

**Required action:** Split the pack contract explicitly: `script_source: checked_in | generated`. For `checked_in`, execute byte-for-byte, record the executed hash in the validation row, and either disable LLM repair or surface any repair as a new unreviewed hash. For `generated`, define authoring and bounded repair. Either make one real target generated or state plainly that autonomy is deferred beyond V1. Define what the dummy pack proves and what it cannot.

### B-03. The causal evidence path is undefined and self-contradictory

**Evidence:** "Actor" is never defined. The nonce is described as readable by the web user, owned by the GitLab service user, and unreadable by the actor. The runner is said to place it, the pack manifest declares `nonce_placement`, and each pack's `probe.py` is also described as placing it. The setup author receives the target pack, including the nonce placement. The null actor is never defined operationally: its identity, command, difference from the real actor, pass criterion, evidence record, and failure code are absent. The core assumption is that a non-root actor in the same VM with a protected nonce is enough for PHP2Shell and GitLab, but the second attacker VM fallback is explicitly out of scope. A reactive setup script can pass the null run and manufacture the real evidence, and the null actor cannot detect it.

**Sources:** Stage 5 "Evidence-Producing Probe Lives Outside the Reviewed Trusted Base" (Major); Stage 5 "Same-VM Causality Is the Central Unproven Assumption" (Major); Stage 7 "Nonce isolation is self-contradictory and the null-actor control is undefined" (Blocker); Stage 8 "Same-VM Causality Is Contradicted" (Blocker); Stage 9 B6; Stage 6 findings 2 and 8.

**Required action:** Define "actor" on first use as the non-root account that runs the PoC, distinct from the service account the vulnerability compromises. Make the nonce runner-owned: randomize its path at run time, place it after the freeze, and keep the path out of model context. Define the null actor per pack with the same wrapper and invocation contract, the exploit parameter removed or invalidated, the exact probe read path, and the recorded transcript. Add a deterministic runner precondition: `nonce_observed` must be true before the LLM may return `reproduced`. Add a reactive-setup-script fixture and state whether the outcome is a failed job or an explicitly accepted residual risk. Decide the second attacker VM now, or state that same-VM targets can only be `inconclusive` by construction.

### B-04. Dirty Frag's decisive evidence is guest-kernel-attested

**Evidence:** Dirty Frag is a guest-kernel local privilege escalation. Once it succeeds, the guest kernel is hostile, and every evidence channel for that target is produced by that kernel: the SSH transcript, stdout/stderr, exit codes, `uname -r`, and the PTY root shell. The nonce proves that a root-only file was read somewhere inside the guest, not that the PoC's read occurred in the sequence the runner observed. The null actor cannot detect the compromise because it exists only in the real run. The PTY root-shell provenance is also unspecified: the runner already has a root SSH channel, and if it uses that channel, the nonce read is vacuous. Destroy is ordered after the LLM call, so a validator timeout keeps the contaminated VM alive.

**Sources:** Stage 7 "Dirty Frag evidence is guest-kernel-attested" (Blocker); Stage 8 "Same-VM Causality Is Contradicted" (Blocker; includes Dirty Frag); Stage 7 "Dirty Frag root shell provenance" (Major); Stage 8 "Destroy is deferred until after the LLM call" (Major); Stage 6 finding 3; Stage 9 M11.

**Required action:** Collect the decisive evidence out of band: host-side serial console or QMP state, virtio-serial with host-side arbitration, or a second VM. State what the validator may conclude when the guest kernel is untrusted. Require the non-root actor to start the PoC and the PoC to spawn the shell; the runner attaches to that PTY as the actor and rejects any shell opened by runner root credentials. Record a fresh-VM signal. Destroy before invoking the validator, and record the destroy result first.

### B-05. The VM trust boundary is contradicted by egress and libvirt privilege

**Evidence:** "The VM is the trust boundary" requires default-deny egress after provisioning. The design leaves the mechanism open between per-VM nftables, which needs host root, and a host-side allowlist proxy, which still has to force guest traffic through it and is not controlled under slirp user-mode networking. The prior tree's only working egress mechanism depends on a privileged bridge, a Docker proxy container, and `sudo`; V1 rules out root, Docker, and non-system libvirt. The project therefore cannot simultaneously keep `qemu:///session`, no root broker, no containers, and a default-deny egress rule. The system-libvirt fallback controls appear in four different forms, and the fallback is declared "out of scope" while also being the only fallback. Host prerequisites and preflight coverage are missing.

**Sources:** Stage 5 "Guest-Egress Control Behind the VM Trust Boundary Is Undecided" (Major); Stage 8 "VM Trust Boundary Is Contradicted by the Egress and Privilege Constraints" (Blocker); Stage 7 "libvirt privilege and egress model is unresolved" (Major); Stage 9 B7 and M5.

**Required action:** Choose and design one egress mechanism with its actual privilege model. Make the fail-closed egress test a Phase 0 gate. Decide session versus system libvirt before coding. If session mode cannot provide default-deny egress without host root, either accept the residual exposure in writing or withdraw the VM trust-boundary claim. State the canonical system-libvirt control set once: dedicated user, fixed broker verbs, peer-credential checks, app outside the `libvirt` group, and a recorded risk acceptance. Evaluate direct QEMU as the lower-privilege alternative.

### B-06. No testable definition of done, budgets, or validator quality gate

**Evidence:** G11 promises per-target time, memory, disk, and token caps, but no ceiling, token cap, memory value, disk value, retention period, or timeout appears anywhere in the feature range. "Capped at roughly 20k tokens" is prose, not an enforced cap. The only quantitative acceptance notion is Dirty Frag's "two consecutive clean runs," which is undefined and buried in an Open Question. There is no validator accuracy threshold, no PHP2Shell or GitLab reproducibility requirement, and no per-job cost estimate. The regression fixtures are not required to classify correctly, and `llm_assessed` has no acceptance bar. Closed reason codes and the classified-log taxonomy are never enumerated.

**Sources:** Stage 7 "No testable definition of done, quantified budgets, or validator quality gate" (Blocker); Stage 9 B9 and M14; Stage 5 "Validator Has No Determinism or Repeatability Contract" (Major); Stage 7 "Closed reason codes and log-classification taxonomy are undefined" (Major).

**Required action:** Add a "V1 acceptance" section with numbers: N/N consecutive `reproduced` verdicts per target, null actor always fails, fixture-classification threshold for the validator, kill-and-restart pass criterion, per-job token cap, per-VM disk cap, host free-disk stop threshold, retention days, and per-phase timeouts. Pin the exact provider model snapshot if available, set temperature 0, and define replay/agreement over stored evidence. Enumerate the closed reason-code table and the log-classification taxonomy.

### B-07. Runner state machine, verdict/authority projection, and persistence are mutually inconsistent

**Evidence:** G6 says "the job status is a projection of the validation row," but that is false for link rejection, fetch failure, null-actor failure before the validator, cancellation, interruption, and validator provider failure. The schema stores `state`, `result`, and `reason_code` on `jobs` and `verdict`, `reason_code`, `validator_kind`, and related fields on `validations`, with no precedence and no explicit authority column. `jobs.result` is undefined and may be the merged status field that Alternative 19 rejects. The state diagram presents outcome states as predecessors of destruction and `done` as terminal for every outcome, while the system diagram and CUJ 1 put destroy before completion, and CUJs 3 and 4 mark the job `cancelled`/`interrupted` before cleanup. `security_cleanup_failed` is neither a state in the graph nor a defined reason code. `not_run` has no defined storage. The database-enforced single worker and single VM slot have no claim, lease, or slot schema. Retries get a fresh attempt directory while `jobs` stores one `attempt_dir`, and `validations`/`artifacts` have no attempt identifier.

**Sources:** Stage 7 "Job lifecycle, verdict, authority, and storage projection are mutually inconsistent" (Blocker); Stage 9 B2 and B5; Stage 6 findings 5, 6, and 10; Stage 7 "Attempt and retry model is overloaded" (Major); Stage 9 M12 and M13.

**Required action:** Replace the inline chain with a transition table: current state, trigger, guard, next state, emitted events, timeout, terminal flag, and cleanup behavior. Separate lifecycle state, verdict, verdict authority, and cleanup outcome. Add a data-contract row for each outcome: completed with each verdict, null-actor failure, cancelled, interrupted, validator error, and teardown failure. Publish the complete `001_initial.sql` DDL with types, constraints, indexes, `authority`, cancel, lease/claim, and attempt identifiers. Add an attempts table or scope `tool_calls`/`artifacts`/`validations` to an attempt. Define migration ownership and a rebuild/reindex function.

### B-08. Target-pack and probe contracts are undefined, and the host-executed probe hook undermines the trust boundary

**Evidence:** The manifest is a field-name sketch with no types, required/optional flags, defaults, validation errors, or field definitions for `TargetPack`, `PocPin`, `ProbeEvidence`, or `RunLimits`. The probe exists in three forms: a manifest block (`nonce_placement`, `command_or_http_request`, `expected_evidence`), a per-target `probe.py` that places the nonce, runs the PoC, parses responses, and returns `ProbeEvidence`, and generic `vm/probes.py` plus the `HttpProbe` interface. `packs.py` imports and executes the pack `probe.py` in the host process, so pack code runs with the app's filesystem, network, libvirt socket, and DeepSeek-key authority, while the document says only setup scripts are hand-reviewed and hash-pinned. No typed probe can express the Dirty Frag PTY flow, the GitLab response parse, or the PHP2Shell host GET. The manifest has no setup-script hash, no PoC SHA-256, no null-actor definition, no retry policy, and no destroy policy.

**Sources:** Stage 6 finding 8; Stage 7 "Target pack manifest cannot express the contract" (Major); Stage 8 "Probe Is Specified in Three Places" (Major); Stage 9 B1 and B3; Stage 7 "Pipeline does not branch on target ids" (Major).

**Required action:** Publish a versioned JSON Schema or exact Pydantic models for `TargetPack`, `PocPin`, `ProbeContext`, `ProbeEvidence`, and `RunLimits`. Choose one probe mechanism. Prefer runner-owned generic primitives driven by a typed pack spec. If hooks remain, declare them part of the trusted computing base, include them in review and hash pinning, and capability-restrict them. Add pack-level `retry_policy` and `destroy_policy` so the runner does not hard-code Dirty Frag behavior. Add a test that no target-id strings exist in the runner.

### B-09. The Detailed Implementation Plan is a file inventory, not an implementation-ready specification

**Evidence:** Every file row is a one-sentence responsibility summary. There are no signatures, parameter types, return types, error modes, or value-object fields for `VmDriver`, `GuestExec`, `HttpProbe`, `Fetcher`, `EvidenceStore`, `AgentRuntime`, `ValidatorClient`, or `JobRunner`. `VmProfile`, `CommandResult`, `SnapshotRef`, `EvidenceBundle`, the SSE event record, and `outcome.json` have no schemas. `AgentRuntime` declares only `extract` and `author_setup`, but repair is a separate model call with its own prompt and retry policy. The typed-facts model, prompt input/output contracts, model parameters, malformed-JSON behavior, and prompt-hash canonicalization are undefined. The ADK spike tests "20 scenarios with two tools" while the agent is described as tool-less, and the switch threshold is only "the agreed threshold." Host packages and versions, preflight coverage, Phase 0 tasks and exit criteria, the API route table, event schemas, lockfile, and deployment entry point are missing. The plan mixes a ground-up build with "Modify" rows for files that already exist, and several references cannot be resolved.

**Sources:** Stage 9 B3, B4, B7, B8, M1, M2, M4, and M18; Stage 6 findings 9, 11, and 14; Stage 7 "Interface inventory is asymmetric" (Nit, but the implementation gap is Blocking).

**Required action:** Add an interface and schema appendix covering every interface and value object, including `repair_setup`. Define the complete `AgentRuntime` protocol, a versioned `Facts` model, every prompt's input/output contract and model settings, and a numeric ADK spike metric and threshold or a Phase 0 gate. Publish the complete DDL, the API endpoint table with request/response models, the event and outcome schemas, the host-prerequisite list with exact packages and versions, a Phase 0 task list with exit criteria, a lockfile tool and file, and the deployment entry point. Fix the file-operation markers and dangling references.

## Consolidated Majors

### M-01. The LLM validator duplicates a deterministic observation the runner already makes

The runner performs the HTTP GET, parses the leaked response, or drives the shell, so it deterministically knows whether the nonce appeared. The design then sends the same evidence to a tool-less LLM and makes its verdict the product's authority, with no rule that a runner-observed nonce is a precondition for `reproduced` and no requirement that the runner resolve the free-form `evidence_refs`. The validator layer adds a model call, a prompt, a bundle builder, fixtures, and third-party data egress without adding an authority the runner lacks. The validator also self-reports `model` and `prompt_hash`, which the runner already knows. **Sources:** Stage 8 "LLM Validator Duplicates a Deterministic Observation" (Major); Stage 7 "LLM verdict is not anchored to the runner's deterministic observation" (Major); Stage 5 "Validator Has No Determinism" (Major); Stage 7 "Validator self-reports `model` and `prompt_hash`" (Nit). **Action:** Record `nonce_observed`, version match, and null-actor pass as runner facts; clamp `reproduced` to false when the nonce was not observed; resolve every `evidence_ref` against transcript and artifact hashes; stamp `model` and `prompt_hash` from the runner; limit the LLM to a reason code and explanation or define the precise causal criterion it applies.

### M-02. ADK plus LiteLLM plus spike plus fallback is over-engineering for two tool-less calls

The agent has exactly two declared calls, extraction and setup authoring or repair, and both are tool-less. The design still commits to ADK plus LiteLLM, a one-week 20-scenario spike, a direct-LiteLLM fallback, an `AgentRuntime` abstraction, and a runtime-parity test. The tool gate is contradictory: the agent is tool-less, but the spike measures a tool-call threshold with "two tools," and the threshold, metric, and tools are never defined. The framework is the least proven and most replaceable component in the plan, and the old tree already had an 80-line DeepSeek-compatible client. **Sources:** Stage 5 "ADK Plus LiteLLM Plus Spike Plus Fallback Is Over-Engineering" (Major); Stage 6 finding 1; Stage 7 "No tools conflicts with the ADK tool-call threshold" (Nit); Stage 9 B4; Stage 8 "Two Model Points Undercounts the Generator Surface" (Nit). **Action:** Use one direct LiteLLM/provider call for the two tool-less calls and delete ADK, the spike, the fallback, and the parity test. Keep a thin function boundary for testability. Reintroduce ADK only if the design later adds model-chosen tool trajectories. If ADK is non-negotiable, define the exact tools, metric, threshold, owner, and decision point.

### M-03. Prior-tree reuse is unassessed: direct QEMU and typed provisioning modules

The design compares only `qemu:///session` against `qemu:///system` and never considers driving QEMU directly. The old tree has a direct-QEMU harness that invokes `qemu-system-x86_64` and implements qcow2 overlays, snapshots, SSH, provisioning, PoC attempts, and port forwards. Libvirt adds a daemon, domain XML, the session/system split, and the root-equivalent system-mode hazard. Separately, the old tree has a tested typed provisioning-module system (`base`, `apt_package`, `build_source`, `pip_package`, `composer_project`) where the model selects a module and supplies typed configuration while deterministic code emits the shell fragment. V1 replaces that with free-form root shell. The old `http_poc` module should not be reused because it prints its own success marker. **Sources:** Stage 5 "Direct QEMU Is Never Evaluated" (Major); Stage 8 "Prior Tree's Typed Provisioning-Module System Is an Unassessed Reuse Opportunity" (Major); Stage 5 "Source-Aware Ingestion" (Nit). **Action:** Evaluate porting the old QEMU harness behind `VmDriver`. Evaluate reusing the provisioning modules or adopting their contract: the LLM returns a module list plus typed configuration, and runner code renders it; free-form shell becomes an explicitly reviewed escape hatch. Do not reuse `http_poc`.

### M-04. Storage is a dual-write system with migrations, backup, and rebuild while SQLite itself is still open

The design specifies a SQLite index with `jobs`, `tool_calls`, `validations`, `artifacts`, and `schema_version`, WAL/foreign keys, a claim query, forward-only migrations, backup-before-migration, rollback, and a rebuild path. It also says the attempt directory and JSONL are authoritative, so SQLite is a second copy; `tool_calls` rows duplicate the append-only event log. Meanwhile the Deferred Decisions section still asks whether SQLite is needed at all. The design specifies both answers to an undecided question. **Sources:** Stage 5 "Storage Design Is a Dual-Write System" (Major); Stage 9 B5; Stage 8 confirmation note on three stores; Stage 7 "Job lifecycle..." (Blocker). **Action:** Use the attempt manifest plus JSONL as the only authoritative store, with a minimal `jobs` index only if the job list needs it. Defer migrations, backup/rollback, and the `tool_calls`/`artifacts` tables until a second consumer or real schema churn appears. Resolve the SQLite decision.

### M-05. UI, SSE, and preflight surface is product scope, and the browser is a trust boundary

Four screens plus a help modal, a System preflight screen, link check, pre-run plan, filterable logs, SSE with backfill/heartbeat/reconnect/terminal close, polling fallback, orphan banner, bundle download, and a token-aware JS client is a full product surface for one or two users. The token is injected into a same-origin page that renders model summaries, logs, validator evidence, and PoC-derived text, with no stated autoescaping rule or CSP. A stored XSS in that page can read the token and drive every mutation. The token protects against cross-origin browser POSTs and unauthenticated network clients, not local processes; on WSL2, any local Windows process that can reach `127.0.0.1` can read the page and token. **Sources:** Stage 5 "UI, SSE, and Preflight Surface" (Major); Stage 8 "Request-Integrity Token and UI Form a Browser Trust Boundary" (Major); Stage 7 "Model- and PoC-controlled text is rendered in the token-bearing UI without escaping or CSP" (Major); Stage 5 "Request-Integrity Token Threat Model Is Narrower Than G1 Implies" (Nit). **Action:** Ship one submit page and one job/evidence page; put preflight in startup/CLI; poll the job state and JSONL first, and add SSE only if a measured UX need appears. Require autoescaping and inert-text rendering for all model, PoC, and transcript content; add a strict CSP; move the token out of the DOM or use an HttpOnly, SameSite cookie. State the token threat model in one place, including local processes and WSL2.

### M-06. Evidence egress to DeepSeek is an unmodeled trust boundary

The validator bundle includes the pinned PoC, the generated setup script and wrapper, the raw transcript, the nonce value and placement, the null-actor result, and precondition evidence, and it is sent to a third-party DeepSeek endpoint. The privacy NFR lists only local controls and "no secrets in the guest or logs"; it does not cover provider egress, provider retention, or the fact that the nonce is a bearer proof value leaving the host. The approved brief required that fetched content sent to DeepSeek be disclosed in the UI, but the design's UI, help page, and threat-model file do not mention it. **Sources:** Stage 8 "Evidence Egress to DeepSeek Is an Unmodeled Trust Boundary" (Major); Stage 7 "Missing consolidated Risks & Mitigations" (Major). **Action:** Add a data-egress and threat-model section. Disclose provider egress in the UI and help page. Minimize the bundle: send the observation that the nonce appeared rather than the nonce value, and prefer hashes or tagged excerpts over raw attacker-controlled text the validator does not need. Record provider, model, prompt hash, and retention assumption in the validation row, and state whether PoC source may be sent.

### M-07. LAN access is contradictory

G1 specifies token, Host allowlist, and TLS or SSH for LAN access, implying LAN exposure is supported. The plan binds only `127.0.0.1` and says the second user is supported "not [by] LAN exposure." Deferred Decisions still lists "LAN policy for a second user." The token is request integrity, not authentication, and WSL2 localhost forwarding means a local Windows process can reach the app. **Sources:** Stage 6 finding 15; Stage 5 "Request-Integrity Token Threat Model" (Nit); Stage 8 "Request-Integrity Token and UI Form a Browser Trust Boundary" (Major). **Action:** Choose loopback-only plus an SSH tunnel for the second user, or design LAN authentication. Remove the contradictory G1 and Deferred Decisions entries. State that the token protects mutations and cross-site requests, not local processes or a hostile Windows session.

### M-08. Configuration and pinning contradict the design's fixed defaults

The existing `.env.example` sets `qemu:///system`, three setup attempts, three PoC attempts, a two-hour global timeout, and relative data/database paths. The design fixes session libvirt first, one setup repair, one PoC rerun, per-target caps, and an absolute data directory that rejects relative SQLite URLs. The plan's `.env.example` row only adds variables; it does not correct the stale values. Separately, the base image and Dirty Frag kernel pins appear in both `var/base-images/catalog.yaml` and the pack, `var/` is git-ignored so a fresh clone cannot verify images, PoC pins omit SHA-256, and GitLab's `.deb` and Dirty Frag's kernel are fetched at run time. **Sources:** Stage 8 "Existing `.env.example` Encodes the Opposite of V1's Fixed Defaults" (Major); Stage 9 M3 and M8; Stage 7 "Run-time package downloads undermine pinning" (Major); Stage 6 finding 17. **Action:** Rewrite `.env.example` to match the design, with per-target caps in packs and absolute paths. Move the catalog to a tracked path, declare one source of truth for each image, kernel, and PoC pin, add the PoC SHA-256 values, and pin package artifacts on the host or bake them into the base image. Add a startup assertion or test that the resolved settings match the design defaults.

### M-09. The API surface lacks the plan, evidence, polling, help, SSE, and error contracts

Job Detail must show the verdict, reason code, evidence references, nonce id, version/precondition evidence, and agent summary, but no endpoint returns validation rows or evidence; `GET /api/jobs/{id}` is only "job row plus latest state." The pre-run plan required by G10 has no endpoint. There is no polling-fallback endpoint despite G8. `POST /api/jobs` accepts only `{cve_url, poc_url}` with no reference to the evidence pinned by the link check, so whether Start re-fetches or reuses bytes is undefined and creates a TOCTOU gap. SSE event names, payloads, backfill, heartbeat, and terminal close are unspecified. There is no help route despite `help.html`, and `POST /api/jobs` has no idempotency key. **Sources:** Stage 6 finding 12; Stage 9 M1; Stage 7 "`POST /api/jobs` has no idempotency key" (Nit); Stage 8 "Check Links and the Job Fetch Are Separate" (Nit). **Action:** Publish an endpoint table with methods, paths, status codes, request/response bodies, and an error envelope. Add the plan/check-id route, validation/evidence reads, polling fallback, help route, SSE event schema, and idempotency key. Make Check links produce a content-addressed manifest that the job adopts, or drop the separate check and render the plan from the job's own fetch.

### M-10. The attempt, retry, and classified-log model is undefined

"Attempt directory" means the per-job storage directory, "one bounded repair per attempt" means a per-run allowance, and "every retry gets a fresh attempt directory" means retries produce new directories. `jobs.attempt_dir` is singular while retries claim multiple, and `validations` links only to `job_id`. `tool_calls` and `artifacts` have no attempt key. The schema cannot say which attempt produced the verdict or which directory is authoritative. "Classified log" is the sole repair input, but no classifier, class labels, selection rule, size bound, or format exists. **Sources:** Stage 6 finding 10; Stage 7 "Attempt and retry model is overloaded" (Major); Stage 9 M12, M13, and M15; Stage 8 "Model-call count omits repair" (Nit). **Action:** Define job, attempt, retry, and repair as four distinct terms. Add an attempts table (`job_id`, `attempt_no`, `attempt_dir`, start/end, failure code, previous attempt) and scope `tool_calls`, `artifacts`, and `validations` to `attempt_id`. State that the job verdict comes from the final attempt. Define the classifier schema, class labels, repair prompt contract, and how `.env` attempt limits map to the one-repair/one-rerun rule.

### M-11. Snapshot, restore, and freshness semantics are undefined

The runner freezes the provisioned state with "a VM snapshot" and restores "the frozen state," but never says whether the snapshot is memory-inclusive or disk-only. If disk-only, the null run's guest writes remain on the overlay and the real run inherits them, reintroducing the leftover-file failure mode. For Dirty Frag, a disk-only restore also leaves guest page-cache and kernel state from the null run. "Freeze" and "snapshot" are used interchangeably, and it is unstated whether nonce placement is inside the snapshot or recreated after restore. The probe's "verifies the VM was fresh" states an outcome, not an observable signal. **Sources:** Stage 6 finding 3; Stage 7 "Snapshot and restore semantics are undefined" (Major); Stage 8 "Destroy is deferred" (Major); Stage 9 M11. **Action:** Define the snapshot type. Use a memory-inclusive system checkpoint for freeze/restore, or a fresh VM per run, and say which. For Dirty Frag, require a fresh boot or memory-inclusive restore after any prior exploit execution. Define the fresh-VM signal (domain UUID, boot id, overlay creation time, or attempt id) and a leftover-artifact assertion. Standardize on "snapshot" and "restore," and define or delete "freeze."

### M-12. GitLab and Dirty Frag pins are still unresolved

The plan fixes GitLab CE 19.2.5 as the vulnerable Omnibus version, but the Open Questions ask whether that `.deb` is retrievable with a stable URL and hash, and Deferred Decisions still lists "GitLab Omnibus version and resource sizing." The Dirty Frag kernel package URL/SHA and base-image hashes are also unresolved. The GitLab pack drops the CE edition, and the service user, nonce path, version endpoint, and authentication requirement are unnamed. **Sources:** Stage 6 finding 17; Stage 9 M8 and M17; Stage 7 "Run-time package downloads" (Major). **Action:** Resolve the exact GitLab `.deb` URL and SHA-256, the Dirty Frag kernel package URL and SHA-256, and the base-image hashes in Phase 0. Record the service user (`git`), nonce path and ownership, version endpoint and auth, readiness check, and host resource estimate. If a pin cannot be resolved, re-scope the target rather than substituting a similar artifact.

### M-13. The user's PoC link may not be the artifact that runs

The user submits a CVE link and a PoC link, while the pack pins the PoC by repository and commit. The design says V1 runs "the pinned PoC or an alternate that matches the same invocation contract," with no definition of the contract check, and says unsupported PoCs are rejected before a VM. An engineer cannot tell whether the user's link is used, used only to locate the repository, or rejected when it differs. The pre-run plan does not show the resolved commit and hash. Check links and the job fetch are separate, so the reviewed bundle is not necessarily the executed bundle. **Sources:** Stage 7 "User-supplied PoC link may not be the artifact that runs" (Major); Stage 8 "Check Links and the Job Fetch Are Separate" (Nit); Stage 9 M1. **Action:** State that the PoC link is a locator that must resolve to the pack's pinned repository and commit; anything else is rejected at Check links with a reason code. Show the resolved commit and hash in the pre-run plan. Remove the "alternate invocation contract" sentence or define the contract test precisely. Pin the checked bundle or reuse its hash for the job.

### M-14. Host-side archive handling and the SSRF guard leave trust gaps

The host fetches and pins the PoC and says "nothing is built or run on the host," but `poc.files` and the validator bundle's "pinned PoC" imply host-side unpacking and reading of an attacker-controlled archive. Tar or zip path traversal and decompression bombs are host-level risks not in the threat model. The SSRF guard checks DNS resolution and re-checks redirects but does not require the HTTP client to connect to the validated address, disable environment proxies, or handle DNS rebinding; IPv6/ULA and metadata-address enumeration are omitted. **Sources:** Stage 7 "Host-side handling of the untrusted PoC archive is unspecified" (Major); Stage 9 N7; Stage 5 "Source-Aware Ingestion" (Nit). **Action:** State the rule: the host stores and hashes the archive as opaque bytes, and extraction or file selection happens inside the guest. If host extraction is required, mandate a path-safe, size-capped extractor and log the archive hash. Require connecting to the validated IP (or a custom transport), set `trust_env=False`, re-resolve on every redirect, and add a rebinding test.

### M-15. Document structure lacks a risk register and a single decision register

The standard's Risks & Limits requirement is not met as a consolidated section. Security sits as an H3 under Technical Plan, reliability and retention sit in the NFRs, uncertainties sit in Open Questions and Deferred decisions, and claim limits sit in a third H3. There is no risk -> impact -> mitigation -> residual/acceptance mapping, and "recorded risk acceptance" names no record location or format. Six of seven Open Questions have a near-duplicate in Deferred decisions, and some deferred entries reopen decisions presented as settled elsewhere. The document mixes a ground-up build with "Modify" rows for existing files, and the ADR is both an existing resource and a Create. **Sources:** Stage 7 "Missing consolidated Risks & Mitigations" (Major); Stage 7 "Decision state is duplicated" (Major); Stage 6 finding 14; Stage 9 M18. **Action:** Add an H2 Risks & Mitigations table with risk ID, category, trigger, impact, mitigation, residual risk, owner, and status. Add a single Decision Register with IDs, status (Settled/Open/Deferred), current default, owner, and gate. Fix the ADR, SITEMAP, and `design_draft.md` references, and restrict file-operation types to `Create | Modify | Copy from old tree`.

### M-16. The global "no self-reported output" invariant is missing

The document explains that self-reported success was the old failure and states the rule only as per-target exceptions: the PHP2Shell `--fetch` output is not the pass condition, and the PoC's printed `uid 0` is not sufficient. The global invariant that would force consistency for new packs is never stated, which matters because G5 requires a dummy fourth pack to work without pipeline edits. **Sources:** Stage 7 "`No self-reported output` invariant is stated only as per-target exceptions" (Major); Stage 5 "Adversarial Test Plan" (Major). **Action:** State the invariant once: no self-reported output is admissible evidence; only runner-authored observations count. Present the per-target lines as applications of it. Add a test that a new pack cannot declare PoC stdout as the pass condition.

## Consolidated Nits

### N-01. Source-aware ingestion is over-scoped for three fixed CVEs

V1 supports three named CVEs and pinned PoCs, but the fetcher supports NVD API JSON, cve.org JSON/API, GitHub advisory API, GitHub repository API plus tarball, and generic HTML, with five adapter tests. That is speculative input coverage for fixed inputs. **Sources:** Stage 5 "Source-Aware Ingestion Supports Five Source Shapes" (Nit); Stage 6 finding 8. **Action:** Accept only the exact three CVE records and three pinned PoC repositories for V1. Add a generic HTML fallback only if a real input requires it. Defer the advisory and cve.org adapters.

### N-02. Internal inconsistencies remain

The document says SQLite stores "job and CVE records" but also says "No `cves` table in V1." It includes `not_run` in the verdict enum while the validator returns only `reproduced`, `not_reproduced`, and `inconclusive`. It lists `docs/adr/0001-v1-reset.md` as an existing resource and as a file to create. **Sources:** Stage 5 "Internal Inconsistencies" (Nit); Stage 6 Nits; Stage 9 M18. **Action:** Pick one source of truth for each: remove `not_run` or define it as a pre-validation state, remove the CVE-record claim or add the table, and mark the ADR as pending.

### N-03. Terminology and glossary drift

"Evidence" names four artifacts: raw evidence, the immutable evidence bundle, the evidence store, and `evidence_sha256`. Setup authoring and repair are named six ways. "Job status" and "job state" are used interchangeably, as are "help page" and "one help modal." "Manifest" is overloaded across evidence, attempt, pack, and bundle manifests. "Attempt," "plan," and "target" also carry multiple meanings. **Sources:** Stage 6 Nits c, d, and f; Stage 7 "Residual terminology drift" (Nit); Stage 9 N1 and N5. **Action:** Add a short glossary near the state machine defining evidence vs. evidence bundle vs. evidence store, setup author vs. repair, job state vs. status, page vs. modal, and the four manifest types. Standardize on "setup author (initial)" and "repair (bounded, one per attempt)."

### N-04. Numeric and sizing statements are approximate or inconsistent

"Capped at roughly 20k tokens" is an approximation where a cap is intended. "Roughly 12,000 lines" appears twice as a quality indictment, a proxy metric with no bearing on the argument. The 256 KB per-artifact ingestion cap is not reconciled with the pinned PoC repository tarball and `poc.files` selection. `var/base-images/catalog.yaml` and the pack's `image_sha256` both claim the image hash with no authoritative source or verification order. "Tens of minutes" conflicts with "20–40 minutes" for the same GitLab duration. **Sources:** Stage 7 "Numeric and sizing statements" (Nit); Stage 9 M8 and M14; Stage 5 "Premature Implementation Detail" (Nit). **Action:** Use exact integers where caps are intended and state whether they cap input, output, or both. Declare whether the PoC artifact is exempt from the 256 KB cap or has a separate cap. Name the authoritative image-hash source and verification order. Use the NFR figure everywhere. Keep the line count only as background.

### N-05. Evaluative claims, v2 vocabulary, and prior-art counts remain

"Honest about its authority" and the goal name "Honest UI" are value judgments, not measurable requirements. "Broader device support" is comparative with no baseline. "Painful," "weakens the link," "harder," and "stronger" assert subjective judgments without a metric. "The five-tool shape" and "the five CLI bank verbs" refer to prior artifacts the document does not name. "Bank," "oracle," "scoring," "corrected key," "stored recipes," and "currency display" are unexplained leftovers. **Sources:** Stage 7 "Evaluative and non-verifiable claims" (Nit); Stage 7 "Unenumerated prior-art counts" (Nit); Stage 7 "Narrative voice and scenario formatting" (Nit); Stage 6 Nit e. **Action:** Rename G10 to its measurable content: verdict and authority are separately displayed, and no UI string claims proof. Replace evaluative verbs with the property being measured. Name the prior tools and verbs, or delete the counts. Define or remove the v2 vocabulary.

### N-06. Small specification gaps remain

`null_actor_passed` is vestigial in the validation row because a null-actor failure stops the job before the validator. The validator self-reports `model` and `prompt_hash`. Orphan domain identification has no tagging rule. The shared token gives two users no attribution or isolation. The System page's "target estimates" have no source. CUJ 3 conflates `security_cleanup_failed` with generic teardown failure. `/dev/kvm` access and WSL2 systemd lingering are missing from preflight. `POST /api/jobs` has no idempotency key. **Sources:** Stage 7 nits on `null_actor_passed`, validator self-report, orphan tagging, shared token, System estimates, CUJ 3, `/dev/kvm`, and idempotency. **Action:** Move the null-actor result to the attempt record or remove the column. Stamp `model` and `prompt_hash` from the runner. Define the domain name prefix or metadata tag. State the shared-token limitation as accepted or add a self-declared user id. Define the estimate source. Name both cleanup codes and their precedence. Add both preflight checks. Add an idempotency key.

### N-07. Dependency and plugin wording conflicts

`python-multipart` supports form bodies, but the API requires JSON for mutations and no form endpoint is planned. Non-Goals reject a dynamic plugin loader, while the plan imports checked-in Python hooks from each pack directory. **Sources:** Stage 9 N3 and N4. **Action:** Remove `python-multipart` or document the form endpoints that justify it. Clarify that packs are static, checked-in code imports, not dynamically discovered plugins.

### N-08. Banned-vocabulary tests, table voice, and heading rules are inconsistent

The banned-vocabulary rule is stated with inconsistent capitalization, and both tests scan template source only; rendered HTML, JSON responses, `static/app.js`, and bundle text can contain the banned words while the test passes. The file table's column "Proposed changes and rationale" promises rationale, but almost no cell contains one, and the voice is mixed. H2/H3 heading case and standard-header naming are inconsistent. **Sources:** Stage 9 N2 and N6; Stage 7 "Heading case..." (Nit). **Action:** State the ban once as case-insensitive, word-boundary matching, and test rendered responses, static assets, and bundle text. Rename the column "Required contents," write every cell as a parallel noun phrase, and adopt one heading-case rule.

### N-09. Undefined terms and unverifiable quality claims remain

"v2-shaped data directory" is never defined, so the check and its test cannot be written. "Disagreement copy" is ambiguous between UI text and a copy operation. "Token-aware" overloads "token," which also names the request-integrity token, the nonce, model tokens, the token file, and the mutation token. "Minimal accessible," "Thin," and "Proves" are unverifiable quality claims or overstate what a test demonstrates. **Sources:** Stage 9 N1. **Action:** Define the exact paths, terms, and UI strings; replace quality adjectives with testable criteria (for example WCAG 2.2 AA checks and "wrapper around `src/xentry/preflight.py`"); and name the header in the fetch helper.

### N-10. Reference and source-of-truth hygiene

The ADR is both an existing Additional Resource and a file to create. `docs/designs/SITEMAP.md` is "Create or modify" but already exists. `design_draft.md` has no path and is not in Additional Resources. The old "ADR 0007" is not present. The file table mixes a ground-up build with "Modify" rows for files that already exist, and the Type column has no controlled vocabulary. **Sources:** Stage 6 finding 14; Stage 9 M18; Stage 8 confirmation note. **Action:** Fix the ADR reference and add the file to the create list. Give the design-draft path or remove the row. Mark existing files as Modify with a baseline. Restrict Type to `Create | Modify | Copy from old tree`. Align phase references.

## Traceability matrix

Stage 5 findings are referenced by their title; Stage 6 by its numbered findings; Stage 7 by its finding title; Stage 8 by its stage IDs; Stage 9 by its B/M/N IDs.

| Consolidated | Severity | Source findings |
| --- | --- | --- |
| B-01 Scope | Blocker | S5 "V1 Scope Is a Full Product Rebuild"; S5 "Three Acceptance Targets"; S5 "UI, SSE, and Preflight Surface"; S8-B1; S6-9, S6-11 |
| B-02 Provisioning mode | Blocker | S5 "Autonomous Generated-Provisioning Claim"; S7 "Generated vs. prebuilt flow contradiction"; S8-B2; S6-7 |
| B-03 Causal path | Blocker | S5 "Evidence-Producing Probe"; S5 "Same-VM Causality"; S7 "Nonce isolation..."; S8-B3; S9-B6; S6-2, S6-8 |
| B-04 Dirty Frag evidence | Blocker | S7 "Dirty Frag evidence is guest-kernel-attested"; S8-B3; S7 "Dirty Frag root shell provenance"; S8 "Destroy is deferred"; S6-3; S9-M11 |
| B-05 VM boundary/egress | Blocker | S5 "Guest-Egress Control"; S8-B4; S7 "libvirt privilege and egress model"; S9-B7, S9-M5 |
| B-06 Definition of done | Blocker | S7 "No testable definition of done"; S9-B9, S9-M14; S5 "Validator Has No Determinism"; S7 "Closed reason codes..." |
| B-07 State/verdict/storage | Blocker | S7 "Job lifecycle..."; S9-B2, S9-B5; S6-5, S6-6, S6-10; S7 "Attempt and retry model"; S9-M12, S9-M13 |
| B-08 Pack/probe contract | Blocker | S6-8; S7 "Target pack manifest..."; S8 "Probe Is Specified in Three Places"; S9-B1, S9-B3; S7 "Pipeline does not branch..." |
| B-09 Implementation plan | Blocker | S9-B3, S9-B4, S9-B7, S9-B8, S9-M1, S9-M2, S9-M4, S9-M18; S6-9, S6-11, S6-14 |
| M-01 Validator redundancy | Major | S8 "LLM Validator Duplicates..."; S7 "LLM verdict is not anchored"; S5 "Validator Has No Determinism"; S7 "Validator self-reports..." |
| M-02 ADK over-engineering | Major | S5 "ADK Plus LiteLLM..."; S6-1; S7 "No tools conflicts..."; S9-B4; S8 "Two Model Points..." |
| M-03 Prior-tree reuse | Major | S5 "Direct QEMU Is Never Evaluated"; S8 "Prior Tree's Typed Provisioning-Module System"; S5 "Source-Aware Ingestion" |
| M-04 Storage dual-write | Major | S5 "Storage Design Is a Dual-Write System"; S9-B5; S8 confirmation note; S7 "Job lifecycle..." |
| M-05 UI/browser trust | Major | S5 "UI, SSE, and Preflight Surface"; S8 "Request-Integrity Token and UI..."; S7 "Model- and PoC-controlled text..."; S5 "Token Threat Model" |
| M-06 DeepSeek egress | Major | S8 "Evidence Egress to DeepSeek"; S7 "Missing consolidated Risks..." |
| M-07 LAN/loopback | Major | S6-15; S5 "Token Threat Model"; S8 "Request-Integrity Token and UI..." |
| M-08 Config/pinning | Major | S8 "Existing `.env.example`..."; S9-M3, S9-M8; S7 "Run-time package downloads"; S6-17 |
| M-09 API gaps | Major | S6-12; S9-M1; S7 "POST /api/jobs..."; S8 "Check Links and the Job Fetch..." |
| M-10 Attempt/retry/classifier | Major | S6-10; S7 "Attempt and retry model"; S9-M12, S9-M13, S9-M15; S8 "Model-call count..." |
| M-11 Snapshot/freshness | Major | S6-3; S7 "Snapshot and restore semantics"; S8 "Destroy is deferred"; S9-M11 |
| M-12 Version pins | Major | S6-17; S9-M8, S9-M17; S7 "Run-time package downloads" |
| M-13 PoC link vs artifact | Major | S7 "User-supplied PoC link..."; S8 "Check Links and the Job Fetch..."; S9-M1 |
| M-14 Host archive/SSRF | Major | S7 "Host-side handling of the untrusted PoC archive"; S9-N7; S5 "Source-Aware Ingestion" |
| M-15 Risks/decision register | Major | S7 "Missing consolidated Risks..."; S7 "Decision state is duplicated"; S6-14; S9-M18 |
| M-16 Global no-self-report invariant | Major | S7 "`No self-reported output` invariant..."; S5 "Adversarial Test Plan" |
| N-01 Source-aware ingestion | Nit | S5 "Source-Aware Ingestion"; S6-8 |
| N-02 Internal inconsistencies | Nit | S5 "Internal Inconsistencies"; S6 Nits; S9-M18 |
| N-03 Terminology/glossary | Nit | S6 Nits c, d, f; S7 "Residual terminology drift"; S9-N1, S9-N5 |
| N-04 Numeric/sizing | Nit | S7 "Numeric and sizing statements"; S9-M8, S9-M14; S5 "Premature Implementation Detail" |
| N-05 Evaluative/v2 vocabulary | Nit | S7 "Evaluative and non-verifiable claims"; S7 "Unenumerated prior-art counts"; S7 "Narrative voice"; S6 Nit e |
| N-06 Small spec gaps | Nit | S7 nits on `null_actor_passed`, validator self-report, orphan tagging, shared token, System estimates, CUJ 3, `/dev/kvm`, idempotency |
| N-07 Dependency/plugin wording | Nit | S9-N3, S9-N4 |
| N-08 Banned-vocabulary/table/headings | Nit | S9-N2, S9-N6; S7 "Heading case..." |
| N-09 Undefined terms/quality claims | Nit | S9-N1 |
| N-10 Reference/source-of-truth hygiene | Nit | S6-14; S9-M18; S8 confirmation note |

## Recommended next decisions

The report does not decide these for the owner. The review makes the cost of each option explicit:

1. **Scope.** Cut V1 to PHP2Shell only and defer GitLab and Dirty Frag, or keep all three and accept a multi-harness V1 with an explicit budget. The reviewers recommend the first path.
2. **Causal claim.** Decide whether V1 builds the second attacker VM. If it does not, Dirty Frag and the same-VM web targets cannot support `reproduced`; the UI and validator must say `inconclusive` or state a weaker guest-attested claim.
3. **VM boundary.** Decide session versus system libvirt and the egress mechanism before coding. If session mode cannot enforce default-deny egress without root, withdraw the boundary claim or accept the residual exposure in writing.
4. **Contracts before code.** Produce the target-pack schema, runner transition table, SQLite DDL, interface and value-object appendix, `AgentRuntime` contract with repair, validator decision rule, closed reason codes, and numeric acceptance gates.
5. **Reuse assessment.** Evaluate the old direct-QEMU harness and typed provisioning modules before committing to libvirt and free-form root shell.

## Review limitations

This review is document-based. The reviewers read the design and the files it references; they did not run the system, boot a VM, or execute any PoC. The findings are model output, not a deterministic proof. The reports should be treated as a prioritized reading of the document, not as evidence that the described system works or fails at runtime.
