# Consolidated Goldfish Review Report — xentry V1, Revision 2

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (743 lines; FeatureRange 1–595, DetailedRange 596–743)
**Review mode:** Consolidated, uninterrupted full flow (Stages 5–9), revision 2
**Date:** 2026-11-06

**Stage reports:**
- [Stage 5 — Initial Zoom Out, revision 2](zoom_out_report_rev2.md)
- [Stage 6 — Comprehension Test, revision 2](comprehension_report_rev2.md)
- [Stage 7 — Critic Review, revision 2](critic_report_rev2.md)
- [Stage 8 — Intermediate Zoom Out, revision 2](intermediate_zoom_out_report_rev2.md)
- [Stage 9 — Implementation Readiness, revision 2](implementation_readiness_report_rev2.md)

## Reviewer status and counts

| Stage | Reviewers | Status | Findings |
| --- | --- | --- | --- |
| 5. Initial Zoom Out | `egm-zoom-out` | completed | 3 Blocker, 11 Major, 6 Nit |
| 6. Comprehension | `egm-comprehension` | completed on retry after an output-limit failure | 0 Blocker, 12 Major |
| 7. Critic | `egm-design`, `egm-structural`, `egm-style` | all completed; design and style completed on retry | 4 Blocker, 20 Major, 16 Nit |
| 8. Intermediate Zoom Out | `egm-zoom-out` | completed | 1 Blocker, 6 Major, 1 Nit |
| 9. Implementation Readiness | `egm-implementation-readiness`, `egm-codebase-details`, `egm-style` | all completed | 10 Blocker, 11 Major, 5 Nit |

The five reports contain 106 findings after each stage's own deduplication. This report consolidates them into 37 action items: 9 Blockers, 18 Majors, and 10 Nits. The traceability matrix maps each item back to the stage reports.

## Overall verdict

Revision 2 fixes the central same-VM causality problem for the remote targets and adds real contracts: a runner-owned nonce, a null actor, destroy-before-validate, a typed DDL, a state table, a pack schema, and an explicit budget. The Stage 8 reviewer confirms that the nonce, null actor, and destroy ordering remain the real causal controls.

The revision is still not implementation-ready. It added the two-VM and root-broker architecture faster than it resolved the contracts that architecture needs. The binding budget is already exceeded by the file plan; the two-VM and broker defaults bypass the Phase 0 gates and decision record the approved plan required; the broker, state machine, target-pack schema, and typed models are not implementable as written; the checked-in-script decision still has a live author/repair path; Dirty Frag's evidence and privilege transition remain contradictory; and the network/mirror/egress and nonce-identity contracts are incomplete.

The prior review's status is mixed. Substantially resolved: broker/network/egress direction, acceptance numbers and reason codes, loopback policy, and host archive/SSRF handling. Partly resolved: most Blockers and several Majors. Not resolved: ADK/reuse/snapshot/PoC-link/risk-register findings. No finding lowers the prior verdict.

The owner must decide one of three paths before coding:

1. **Simplify to the budget.** Cut the ADK/extractor/author/repair path, the typed pack layer, the 22-state machine, SSE/backfill, and the extra source adapters; use three checked-in target instances and a step list; keep the runner-owned nonce, null actor, broker, and validator. This is the cheapest route under the existing 26-module cap.
2. **Keep the two-VM/broker scope and raise the budget.** Add explicit budget lines for the attacker VM, broker daemon, root unit, tests, and host-evidence channel; restore the Phase 0 gates; record the decision in ADR 0001; and accept a larger program.
3. **Cut a target or a VM.** Drop Dirty Frag or the attacker VM and re-scope. The owner has already chosen all three targets, so this is a fallback only if the budget or the Dirty Frag evidence channel cannot be made defensible.

## Consolidated Blockers

### B-01. The binding budget is already exceeded by the plan

**Evidence:** The budget says at most 5,500 lines across at most 26 modules. The file plan lists 30 non-package Python modules under `src/` and `broker/` (33 including package markers) plus three Python scripts. The "module" unit and per-module line allocation are undefined. Phase 0 is one week for eight gates (broker, network, two-VM smoke, PHP2Shell build, Dirty Frag kernel, GitLab package, ADK gate, artifact hashes), and the 10-week effort has no slack or cut line.

**Sources:** Stage 5 "Binding budget is already exceeded by the plan" (Blocker); Stage 8 "Two-VM and root-broker defaults bypass the approved Phase 0 gates and have no decision record or budget line" (Blocker); Stage 9 finding 1 (Blocker); Stage 7 "Binding budget is not fully quantified or enforceable" (Major).

**Required action:** Do a bottom-up per-file estimate. Define module and counting rules for tests, scripts, and package markers. Either cut the speculative surfaces (ADK author/repair and fallback, typed pack layer, 22-state machine, SSE/backfill, four source adapters, dummy pack) to get under 26, or raise the cap explicitly and add a CI count gate. Add budget lines for the attacker VM, broker daemon, root systemd unit, host-evidence channel, and their tests. Split Phase 0 or add a named cut line.

### B-02. The two-VM and root-broker defaults lack the required Phase 0 gates, ADR, and budget lines

**Evidence:** The approved V1 brief made the target VM with a non-root actor the chosen design and the second minimal attacker VM a fallback only if a web target could not be validated causally. It also said V1 tests `qemu:///session` first and uses a system-libvirt broker only if a target needs it. Revision 2 makes both unconditional and removes the session-vs-system and one-VM-vs-two gates from Phase 0. The ADR is still a Create file, and the budget has no line for the broker daemon, root unit, attacker VM, or their tests. The two-VM's causal justification is also inconsistent: the same-kernel objection is applied to remote PoCs but not to Dirty Frag, the one kernel exploit. The attacker VM does not observe the nonce; the runner does. The attacker VM is an isolation control, not the causal fix.

**Sources:** Stage 8 "Two-VM and root-broker defaults bypass the approved Phase 0 gates..." (Blocker); Stage 8 "The two-VM's causal justification is inconsistent and untested..." (Major); Stage 5 "Binding budget..." (Blocker); Stage 5 "Dirty Frag's decisive evidence is not established" (Blocker).

**Required action:** Restore both Phase 0 gates with a named decision owner and a pass/fail test. Run the one-VM causality test for PHP2Shell and GitLab with the protected nonce and null actor; keep the second VM only if that path fails, or record it as an isolation/defense-in-depth choice. Record the decision in ADR 0001. Add explicit budget lines for the attacker VM, broker, root unit, host evidence, and tests. State Dirty Frag's authority separately if the host channel remains forgeable.

### B-03. The broker fixed-verb, privilege, and transport contract is incomplete

**Evidence:** The broker's verb set has no operation to apply nftables default-deny, run the egress test, start or stop the artifact mirror, or interrupt an in-flight guest command, although the app-side `NetworkManager` exposes those operations. `exec(vm_id, user, argv, tty, timeout)` accepts arbitrary argv and any user, including root; `copy_in` accepts an arbitrary guest path; `start_target`/`start_attacker` accept an arbitrary image id. The validation list covers only job id, profile id, and host path. The design does not state the socket owner, mode, or expected peer UID; the QEMU/domain process UID; seccomp/AppArmor; the guest exec/copy transport (qemu-guest-agent, SSH, or serial); or the credential model. `VmDriver` and `BrokerClient` overlap on seven operations with different names. `NetworkManager` and the broker duplicate network ownership.

**Sources:** Stage 7 "Broker fixed-verb contract is incomplete and accepts unvalidated parameters" (Blocker); Stage 9 findings 3 and 4 (Blockers); Stage 5 "Broker/network/reboot/transport interfaces are incomplete and partly duplicate" (Major); Stage 8 "The root broker is over-privileged..." (Major); Stage 7 "Component and interface inventories are incomplete" (Major).

**Required action:** Extend the broker with explicit verbs for nftables apply/verify, mirror start/stop, egress test, and cancel/in-flight exec. Replace free-form `exec` and `copy_in` with step-bound calls validated against pack command templates and a user allowlist; permit root only for the declared Dirty Frag step. Validate every id, path, user, and argv. State the socket identity and peer UID, domain UID, seccomp/AppArmor profile, and guest transport. Make `VmDriver` the runner-facing port and `BrokerClient` its only adapter, or delete the duplicate. Assign one owner to network policy.

### B-04. The runner state machine is contradictory and cannot terminate

**Evidence:** `completed`, `failed`, `cancelled`, and `interrupted` are declared terminal but every one has an outgoing edge. `failed`, `cancelled`, and `interrupted` route to `destroying`; `destroying` permits `validating` or `failed`; `failed -> destroying -> failed` is an unguarded loop. `done` is the only true terminal state but has no row, trigger, or guard. A cancelled or interrupted job can reach validation. There is no persistence for a cancel request, no else-branch in `running_null`, no reboot state for Dirty Frag, no nonce-injection state, no host-evidence state, and no domain/network naming rule for the orphan sweep. The table has no per-state timeout.

**Sources:** Stage 7 "Runner state machine is internally contradictory" (Blocker); Stage 9 finding 2 (Blocker); Stage 5 "The state machine loops, and pre-validation outcomes have no projection" (Major); Stage 6 finding 6; Stage 8 "The runner state machine models a fixed linear program as 22 job states" (Major).

**Required action:** Replace the table with a total transition specification, or use an ordered step list plus `outcome` and `cleanup_state`. Route every outcome to destroy; never route a failed/cancelled/interrupted job to validation. Define or delete `done`. Add guards for every branch, a cancel flag persisted in the database, reboot/nonce/host-evidence steps, domain/network naming, and per-state timeouts. Ensure `failed -> destroying -> failed` cannot loop; a repeated teardown failure needs an operator action and a terminal state.

### B-05. The target-pack and probe schema cannot express the three packs, and the typed models are names only

**Evidence:** The manifest is pseudo-YAML with field names but no values, types, required/optional flags, defaults, or validation errors. `probe.kind` omits `qmp`; a single `probe` cannot express PHP2Shell's HTTP fetch plus nonce parse or Dirty Frag's PTY plus host-serial read. `network.target_port` is scalar while GitLab needs 80/443. The promised nonce path/owner/mode block is missing. `attacker_profile` is mandatory although Dirty Frag has no attacker. `kernel` is optional but required for Dirty Frag. The inline `poc` duplicates `poc.pin.yaml`; the pack image/kernel pins duplicate `config/artifacts.yaml`; the attacker profile duplicates `profiles/attacker.yaml`; there is no precedence rule. `models.py` lists `Facts`, `SetupBundle`, `TargetPack`, `PocPin`, `RunLimits`, `VmProfile`, `CommandResult`, `SnapshotRef`, `HttpResult`, `Artifact`, `Manifest`, and the classified-log type without fields or types. `ids` (`target_id`, `target_pack_id`, `profile_id`, `pack_id`) are inconsistent.

**Sources:** Stage 7 "Typed target-pack schema cannot express the three V1 packs" (Blocker); Stage 9 findings 5 and 6 (Blockers); Stage 5 "The target-pack and probe contracts are still untyped sketches" (Major); Stage 8 "The typed target-pack abstraction is premature for three checked-in targets" (Major); Stage 6 finding 9.

**Required action:** Choose one of two paths. **Simplify:** define one `Target`/`Probe` Pydantic model and three checked-in instances in `src/xentry/targets.py`; collapse the per-target YAML and shared profiles into those instances; keep the pack schema as a V1.1 input. **Keep the pack:** publish exact Pydantic models or a versioned JSON Schema with required/optional fields, defaults, enums, conditional fields, and validation errors; make `probe` an ordered list with one decisive primitive; add `qmp`; use `target_ports`; add an explicit `nonce {path, owner, mode, value_source}` block; mark `attacker_profile` optional; choose one source of truth for each image/kernel/PoC/attacker pin; define the template variable set and renderer. In either path, publish field tables for every model and the classified-log schema.

### B-06. Checked-in scripts still have a live author/repair path, hash pins are not verified, and the null-actor wording is inverted

**Evidence:** All three V1 targets are `script_source: checked_in`, and the generated path is V1.1. Yet `planning` is triggered by "Setup author/repair," `provision_failed` permits one repair, the budget reserves one repair, `AgentRuntime` exposes `author_setup`/`repair_setup`, and V1 includes setup/repair prompts, `test_agent_contract.py`, and the dummy generated pack. A repaired script cannot match the reviewed hash, but the pack still advertises it. No state or guard verifies `setup_script.sha256` or `poc.sha256` before execution; line 358 says "record," not "compare," and there is no `artifact_hash_mismatch` code. The null-actor acceptance phrase "the null actor must fail" is the opposite of `null_actor_failed`, which means the null actor did observe the nonce. The null actor's location, invocation, expected target-side observation, and retained artifacts are undefined for remote targets.

**Sources:** Stage 5 "Checked-in provisioning still has a live repair path" (Blocker); Stage 7 "V1 both requires and defers setup authoring and repair" (Blocker); Stage 9 findings 8 and 10 (Blockers); Stage 7 "Checked-in script and PoC hash pins are recorded but never verified" (Major); Stage 7 "Null-actor contract is defined two ways..." (Major); Stage 6 finding 1; Stage 8 "The extractor/ADK pipeline has no load-bearing V1 consumer" (Major).

**Required action:** For `script_source: checked_in`, the planning step loads and hash-checks the script; no model call, no repair. Remove author/repair from V1 states, retry policy, budget, prompts, tests, and the dummy pack; move them to V1.1. Add `artifact_hash_mismatch` and a guard that compares setup and PoC hashes before provisioning. Define the null actor as "runs the same wrapper without the exploit and must not observe the nonce." Rename `null_actor_failed` to state the observed condition. Add `null_actor.location`, invocation, expected target-side observation, and artifacts for both topologies. Replace "the null actor must fail" with "the null actor must not observe the nonce."

### B-07. Dirty Frag's flow and decisive evidence remain contradictory

**Evidence:** Dirty Frag is described as running as a non-root actor, but the runner drives a "PTY root shell" and `pty_session` opens a PTY "as the actor." The broker `exec` accepts `user=root`, so the runner can read the nonce without the exploit. The C PoC has a build step but no target toolchain is defined; G7 forbids host builds; the design says "no compiler needed for the remote PoCs" while GitLab needs Go and Dirty Frag needs C. The nonce is root-only, but the null actor runs as `xentry` and cannot reach it. "Restore or fresh boot" is an unresolved either/or. `running_null` transitions directly to `restoring`, so the null-actor host-evidence observation has no state. The host serial channel is guest-writable, and the forgery-resistance question is deferred. Acceptance still requires `reproduced` with `runner_observed+llm_assessed` for Dirty Frag.

**Sources:** Stage 5 "Dirty Frag's decisive evidence is not established" (Blocker); Stage 8 "The two-VM's causal justification is inconsistent and untested..." (Major); Stage 9 finding 7 (Blocker); Stage 7 "Dirty Frag flow contradicts itself" (Blocker in the Stage 9 numbering; Stage 7 reports it under the schema and state findings); Stage 6 finding 3.

**Required action:** Specify the exact privilege transition: the non-root actor starts the PoC, the PoC spawns the root shell, and the runner attaches to that PTY as the actor. Reject any root shell opened by the broker or runner. Define the target's C build toolchain and the build step. Choose fresh boot or memory-inclusive restore, and add the host-evidence observation state. Define a distinct authority (`guest_attested+llm_assessed`) or `inconclusive` until the host-channel tamper analysis shows a non-forgeable channel. Make that gate a precondition for the Dirty Frag `reproduced` claim.

### B-08. The network, artifact mirror, and offline provisioning contract is unimplementable

**Evidence:** The network block sets `forward mode: none` and `host route: none`, yet the target must reach a host-local artifact mirror, and `http_get`/`response_parse` have the runner GET a target URL from the host. The mirror has no serving process, address, port, nftables exception, or lifecycle before default-deny. The probe path is not a port nftables can allow. `fetch-artifacts.sh` fetches only images, the GitLab `.deb`, and the Dirty Frag kernel, not the apt build/runtime dependencies for the PHP 8.4.26 build or the GitLab Omnibus install. The attacker VM has no vendored Go/Python dependency cache. The catalog is trust-on-first-use: the fetch script writes the same pins it is meant to verify. The egress test has no broker verb, state, or failure code.

**Sources:** Stage 9 findings 3 and 9 (Blockers); Stage 6 finding 4; Stage 7 "Network contract conflates traffic directions and contradicts the artifact mirror" (Major); Stage 5 "The offline provisioning mirror/catalog does not cover the setup scripts' package needs" (Major); Stage 8 "The artifact hash catalog is trust-on-first-use" (Nit); Stage 7 "Attacker build dependencies are unpinned despite no egress" (Nit).

**Required action:** Define the mirror as a host service on the bridge gateway with a stated address, port, bind rule, nftables exception, and lifecycle. Define post-provision rules per direction: guest-to-guest, host-to-guest probe, and guest-to-outside egress. State the probe execution locus. Add broker verbs for nftables apply/verify, mirror start/stop, and egress test; add a state and failure code. Fetch all offline dependencies, prebuild them into the images, or run a pinned host-side apt proxy with a recorded package set. Vendor attacker build dependencies or use a hash-pinned builder image. Seed the catalog from vendor checksums/signatures and refuse to write a new pin without an out-of-band value.

### B-09. Nonce identity, secret boundary, and placement are undefined

**Evidence:** The nonce is the only causal anchor, but the schema stores only `runner_nonce_observed`; there is no nonce id, hash, path, or creation timestamp in `attempts` or `validations`. Acceptance requires a validation row "tied to its nonce," and CUJ 3 shows a "nonce id," but neither can be measured. The nonce is generated after provisioning in G6 and after the freeze in the nonce section; the state table has no nonce step. The broker has no write-file, chmod, or chown verb; `copy_in`/`exec` are the only primitives, and neither is specified to set ownership or mode. `ProbeContext` bundles `nonce` and `nonce_path`, and the attacker runs the PoC with the nonce path; no rule keeps the value out of the attacker VM. The validator "may see the nonce value" and line 378 only "prefer[s]" hashes. A disk-only restore can revert the nonce or leave null-run state.

**Sources:** Stage 6 finding 2; Stage 8 "The nonce value's secret boundary is unenforced..." (Major); Stage 7 "Nonce identity is never persisted..." (Major); Stage 7 "Nonce injection conflicts with freeze/restore..." (Major); Stage 5 "`validations` has no nonce id/hash" (Nit); Stage 9 finding 14 (DDL nonce columns).

**Required action:** Add a nonce identity (`nonce_id`, `nonce_sha256`, path, owner, mode, creation time) to `attempts` and reference it from `validations`; never store the value. Generate and place the nonce after the freeze through an explicit broker verb that sets owner and mode. Split `ProbeContext` into a runner-only secret and an attacker context with `nonce_path` only. Make `poc.invocation_template` accept only the path. Add a test that the value never appears in attacker argv, transcripts, or `copy_in`. Send only `nonce_observed` and `nonce_sha256` to the validator; forbid the value in the audit bundle. Re-run readiness and version checks after restore.

## Consolidated Majors

### M-01. Authority, verdict, and acceptance projection are not closed

`authority` is used as `llm_assessed`, `runner_observed`, and `runner_observed+llm_assessed`, and the last is stamped on every validation row even when `nonce_observed` is false. `not_run` is a job verdict but not a validator verdict. A null-actor failure writes `not_run`/`runner_observed` but never reaches the validator, and `validations` makes authority/model/prompt/nonce NOT NULL, so the main failure path has no projection source. Acceptance "tied to its nonce" is not measurable. **Sources:** Stage 6 finding 8; Stage 7 "`authority` has incompatible values..." (Major); Stage 9 finding 15 (Major); Stage 5 "The state machine loops..." (Major). **Action:** Define a closed `authority` enum and an outcome-to-value mapping, including a Dirty Frag guest-attested value and a validator-error value. Add a runner-owned outcome record for non-validated outcomes. Define the exact `jobs` projection for every outcome. Replace "tied to its nonce" with a measurable nonce-id check. Stop calling the verdict `llm_assessed`.

### M-02. ADK, the extractor, the typed pack layer, and the 22-state machine have no load-bearing V1 consumer

All three targets are checked in; the generated path and `author_setup`/`repair_setup` are V1.1. The extractor's typed facts are fixed by the pack, script, or pinned PoC. The pack has no `expected_version` field, and `ready_target` could read a pack field. The only V1 output is the non-authoritative agent summary. V1 still pays for ADK + LiteLLM, three prompts, `agent.py`, a 20-fixture ADK gate, the prompt-injection corpus, the 150k token cap, and the extraction state. The typed pack layer is a four-source configuration layer for three fixed targets; target branching moves from Python into YAML, not away. The 22-state runner models a fixed linear pipeline with two branches. **Sources:** Stage 8 "The extractor/ADK pipeline has no load-bearing V1 consumer" (Major); Stage 8 "The typed target-pack abstraction is premature..." (Major); Stage 8 "The runner state machine models a fixed linear program..." (Major); Stage 5 "The design reinvents the VM harness..." (Major). **Action:** For V1, cut the extractor/author/repair path, ADK, the three prompts, and the token cap; use a static `expected_version`/precondition in the checked-in target definitions. Use three `Target`/`Probe` instances and a step list. Keep the independent validator. Move ADK, prompts, fixtures, and the generated path to V1.1. If ADK is non-negotiable, define a load-bearing V1 consumer and a budget line.

### M-03. Failure codes have gaps and overlaps, and the clamp target is underdetermined

Failure points with no code: egress-test failure, image/script/PoC hash mismatch, snapshot/restore failure, nonce placement failure, artifact-mirror failure, and preflight admission refusal. `nonce_not_observed` permits one rerun while `exploit_failed` permits none for the same observation. `teardown_failed` and `security_cleanup_failed` overlap. `validating` failure does not name the replacement verdict when `reproduced` is clamped. `validator_error` says "park or record inconclusive." **Sources:** Stage 7 "Reason-code coverage has gaps and overlaps..." (Major); Stage 9 finding 15 (Major); Stage 5 "`nonce_not_observed` and `exploit_failed` overlap" (Nit). **Action:** Add the missing codes, define overlap boundaries with a discriminator, make one closed enum shared by runner and validator, define a single clamp verdict, and align `reason_code`/`failure_code`.

### M-04. The attempt model and DDL cannot record pre-attempt calls, and `tool_calls` has no writer

`tool_calls.attempt_id` is NOT NULL, but fetch/extract/plan happen before any VM attempt. `jobs.attempt_dir` is singular while `attempts` can have many; there is no `final_attempt_id`; `attempts.state` duplicates the job state; `vms` has no `attempt_id`; there is no network table or per-job disk cap. `tool_calls` reads as model tool invocations but the agent has no tools, and no component writes the rows. Redaction-before-write conflicts with raw-evidence hashes. **Sources:** Stage 5 "The attempt/retry model is ambiguous..." (Major); Stage 7 "Attempt model is undefined..." (Major); Stage 7 "`tool_calls` table has no defined writer" (Major); Stage 7 "Redaction-before-write contradicts raw-evidence storage" (Major); Stage 9 finding 14 (Major). **Action:** Create an attempt row at job start (attempt 0) or make `attempt_id` nullable for pre-attempt calls; add `final_attempt_id`; add `attempt_id` to `vms`; record network ids; rename `tool_calls` to `broker_calls` or remove it; write and hash raw bytes first, redact derived copies, and store both hashes; one migration owner.

### M-05. Snapshot, restore, and freshness semantics are undefined

"Freeze," "snapshot," and "restore" are used interchangeably; the design never says whether the snapshot includes memory. A disk-only restore leaves null-run writes and page-cache state, so the real run inherits them. There is no fresh-VM signal or leftover-artifact assertion; Dirty Frag's "restore or fresh boot" is an unresolved choice. **Sources:** Stage 5 "Snapshot/restore semantics are undefined" (Major); Stage 7 "Nonce injection conflicts with freeze/restore..." (Major); Stage 9 finding 7/11 (Major). **Action:** Require a memory-inclusive system checkpoint or a fresh VM per run. Define a fresh-VM signal (domain UUID, boot id, overlay creation time). Add a leftover-artifact assertion. Choose fresh boot for Dirty Frag or define the restore. Standardize "snapshot"/"restore," delete "freeze," and re-run readiness after restore.

### M-06. Setup-script deliverables and hash verification are not actionable

The setup scripts are described in one line each: no mirror URL, package sources, readiness command, nonce path/permissions, reboot/wait handling, or `uname -r` mechanics. No state or guard verifies the setup or PoC hash before execution; there is no mismatch code. **Sources:** Stage 9 finding 11 (Major); Stage 7 "Checked-in script and PoC hash pins..." (Major); Stage 5 "Checked-in provisioning..." (Blocker). **Action:** Add a per-script step outline and the readiness contract (command, expected output, timeout) consumed by `provisioning`/`ready_target`. Add hash comparison guards and `artifact_hash_mismatch` with no retry.

### M-07. Budget enforcement details are missing

The per-call token value, `VM-cycle` definition, `RunLimits` fields, memory admission headroom, disk accounting (overlays, ISOs, artifacts), pruning policy, job timeout, and line-cap value are undefined. The pack schema has no token or VM-cycle fields. `retry_policy`, `attempt_no`, `previous_attempt_id`, and `fresh_vm_on_retry` imply multiple attempts, but no state edge creates an attempt row. **Sources:** Stage 7 "Binding budget is not fully quantified or enforceable" (Major); Stage 9 finding 12 (Major). **Action:** Give each cap a value, owner, measurement point, and failure behavior. Define attempt creation, reuse, and cleanup. Add the missing fields to the pack or config.

### M-08. The HTTP API contract is incomplete

`check_id` is optional with no store, TTL, or reuse rule; `jobs.cve_id` is NOT NULL although submit accepts URLs only; CUJ 6's "no model spend" conflicts with extractor-based target identification; no error envelope or status codes are specified; the request-integrity token is marked only on `POST /api/jobs`, not on links/check, cancel, or preflight. `static/app.js` needs a readable token while the design offers an HttpOnly cookie. **Sources:** Stage 5 "The request-integrity token is not applied..." (Major); Stage 7 "Check links and Start are not bound..." (Major); Stage 9 finding 13 (Major). **Action:** Define the check store, TTL, single-use rule, and bundle-hash comparison; a deterministic target-identification step; a single error schema with status codes; token middleware on every non-GET route; one token-delivery mechanism consistent with the JS client.

### M-09. Host prerequisites and dependency ownership are infeasible or incomplete

libvirt 12+/QEMU 10+ is not available on the Ubuntu 24.04 baseline used elsewhere; the host OS is unpinned; there are no install/enable commands, AppArmor/SELinux policy, image-store layout, or broker runtime environment. The host memory statement misstates 10 GB as guest memory rather than 8 GB target + 2 GB attacker. The dependency list omits `uvicorn` and the dev/test tools, includes `asyncssh` with no consumer, and puts `libvirt-python` in the app environment although the app cannot open libvirt. **Sources:** Stage 9 findings 16 and 17 (Major); Stage 7 "Component and interface inventories..." (Major); Stage 6 finding 11. **Action:** Pin the host OS and versions, add exact setup steps and broker dependencies/environment, align memory/disk, and publish exact runtime/dev dependency lists with an owner per dependency.

### M-10. Risk acceptance, ADR, and decision record are missing

The design repeatedly says "the risk acceptance is recorded," but no location, format, owner, or status is given. The threat model is a future file. The new root broker, two-VM escalation, Dirty Frag guest attestation, LLM false positive, and DeepSeek egress have no risk register entry. ADR 0001 is a Create file but cited as existing. The alternatives section titles nine chosen designs as if they were rejected and gives preference-based reasons. **Sources:** Stage 5 "The risk acceptance is claimed but not recorded" (Major); Stage 7 "Mandatory Risks and Mitigations area is missing..." (Major); Stage 7 "Alternatives section labels the chosen design as rejected..." (Major); Stage 8 B1 (ADR). **Action:** Add a risks table (risk, impact, likelihood, mitigation, residual, owner, status) and an ADR that records the two-VM/broker/checked-in/validator decisions. Rewrite the Alternatives headings as rejected alternatives with pros, cons, and reason, and label owner constraints as such.

### M-11. The PoC-link, source-shape, and admission contract is undefined

No section enumerates supported CVE-source or PoC-link shapes, or how detection maps a link to a pack. A Non-Goal permits "an alternate that matches the same invocation contract," while `unsupported_poc` rejects any PoC that does not match the pack pin. `Fetcher.fetch(url)` takes one URL, but packs describe repository, commit, files, and SHA-256; no git/archive resolution, commit verification, or post-extraction file-hash check is defined. Check links returns `check_id`/`bundle_sha256`, but jobs do not persist them, so Start can refetch different bytes. **Sources:** Stage 7 "Source-shape detection and PoC admission/retrieval are undefined..." (Major); Stage 7 "Check links and Start are not bound..." (Major); Stage 5 "The PoC-link contract is ambiguous..." (Major); Stage 9 finding 13. **Action:** Enumerate source shapes and the PoC match rule in one place. Make the link a locator that must resolve to the pack's repository and commit; reject anything else. Verify commit and per-file hashes after extraction. Persist `check_id`/`bundle_sha256` on the job and fail if the refetched bundle differs.

### M-12. The artifact catalog is trust-on-first-use and attacker build dependencies are unpinned

`fetch-artifacts.sh` writes the pins it is meant to verify, and Open Question 99 asks the operator to record the hashes. A MITM or upstream replacement at first fetch becomes the trusted pin. The attacker VM receives only the PoC archive and a toolchain; a Go or Python build that needs downloads will fail offline. **Sources:** Stage 8 "The artifact hash catalog is trust-on-first-use" (Nit); Stage 7 "Attacker build dependencies are unpinned..." (Nit); Stage 9 finding 9 (Blocker). **Action:** Seed the catalog from vendor checksums/signatures, verify in CI, and refuse to write a new pin without an out-of-band value. Vendor attacker dependencies or use a hash-pinned builder image.

### M-13. Phase 0 consequences, preflight freshness, and phase actionability are undefined

A failed Phase 0 gate has no stated consequence; preflight is user-triggered and used as a `queued` guard with no freshness rule; the phases are week buckets, not tasks; Phase 1 requires the two-VM PHP2Shell path while Phase 2 lists the attacker VM as new work. **Sources:** Stage 7 "A failed Phase 0 gate has no stated consequence..." (Major); Stage 9 finding 19 (Major). **Action:** Add a per-gate consequence and decision owner, a preflight TTL/admission rule, a file-to-phase mapping with exit checks, and move the attacker VM into Phase 1 or defer the two-VM acceptance.

### M-14. Component and interface ownership is unmapped, and `VmDriver`/`BrokerClient` overlap

No component owns the artifact mirror, preflight, audit-bundle export, or the runner's plan. `Fetcher` and `EvidenceStore` are two interfaces but one component row. `NetworkManager`, `GuestExec`, and `HttpProbe` appear only in Interfaces. `VmDriver` and `BrokerClient` overlap on seven operations, and the spec never says which the runner calls or which the fakes implement. **Sources:** Stage 7 "Component and interface inventories are incomplete and unmapped" (Major); Stage 9 finding 4 (Blocker). **Action:** Add the missing components, map each interface to an owner, define `VmDriver` as the runner-facing port with `BrokerClient` as its only adapter (or delete one), and assign one owner to network/probe/evidence.

### M-15. Redaction and append-only evidence conflict

The attempt directory contains "raw evidence" and "redaction runs before any write." Both cannot hold for the same bytes. The runner resolves evidence against transcript/artifact hashes, but it is unstated whether the hashes cover observed or redacted bytes. "Append-only JSONL" has no write-once or hash-chain mechanism. **Sources:** Stage 7 "Redaction-before-write contradicts raw-evidence storage..." (Major). **Action:** Write and hash raw bytes first; apply redaction to derived copies (validator input, bundle, UI); record both hashes; state how append-only is enforced.

### M-16. The artifact mirror and offline package set are incomplete

The mirror has no serving process, address, port, bind rule, nftables allowance, or lifecycle; hash-pinned setup scripts cannot embed a job-varying mirror address; the fetch script covers only images/`.deb`/kernel, not apt build dependencies; the Dirty Frag C PoC needs a compiler the target never provisions. **Sources:** Stage 9 finding 9 (Blocker); Stage 5 "The offline provisioning mirror/catalog..." (Major); Stage 7 "Network contract conflates traffic directions..." (Major). **Action:** Define the mirror process and static address/alias, the nftables exception and lifecycle, the full offline package set or prebuilt images, and the target toolchain for Dirty Frag.

### M-17. Phase 0 gates are not integrated into the implementation order

The implementation order is eight steps, but Phase 0 is a separate one-week bucket with eight gates; the gates are not mapped to steps or exit criteria; the ADK gate is not in the order; the GitLab package and host sizing are omitted from the gate list. **Sources:** Stage 5 B1; Stage 9 finding 19; Stage 6 finding 9 (from the prior review). **Action:** Make Phase 0 the first numbered step with tasks, artifacts, pass/fail criteria, and decision records; map every file and open question to a phase; remove the week bucket ambiguity.

### M-18. Help surface and entity terminology are inconsistent

The feature spec requires one help modal; the plan creates a `GET /help` page and `templates/help.html`. "Two VM profiles" conflicts with "one target profile per target; one attacker profile." `xentry` names both the host app user and the guest actor. "Target files" is ambiguous between CVE target and target VM. **Sources:** Stage 9 findings 20 and 21 (Major); Stage 7 Nits on terminology. **Action:** Choose modal or page and align route/template/test; say "two profile types"; qualify "host app user" vs. "guest actor"; rename the file table "Repository files to create or modify."

## Consolidated Nits

### N-01. DDL lacks CHECKs, indexes, and enum constraints

State, verdict, authority, reason code, target id, and VM role are plain TEXT with no CHECKs; foreign keys are unindexed; `PRAGMA foreign_keys` is unstated. **Sources:** Stage 7 "DDL does not encode the closed sets..." (Nit); Stage 9 finding 14 (Major). **Action:** Add CHECK constraints or lookup tables, index foreign keys, and state the foreign-key pragma.

### N-02. Additional resources are not resolvable

`concepts_brief.md`, `consolidated_review_report.md`, and "the five stage reports" have no paths or links; the three CVEs have no advisory URLs. **Sources:** Stage 6 finding 10; Stage 7 "Additional Resources are not resolvable" (Nit). **Action:** Use repository-relative paths and advisory URLs.

### N-03. The title overstates the topology

"Two-VM CVE Reproduction" describes only remote targets; Dirty Frag uses one target VM. **Sources:** Stage 7 "Title overstates the topology" (Nit). **Action:** Retitle as "Target and Attacker VM" or "One-or-Two-VM."

### N-04. Terminology drift and line length

"Bundle" names the evidence bundle and the audit bundle; "the model," "the agent," "the LLM," "the generator," and "the session" name different actors; "null actor fails" is ambiguous; `v2`/`V1` casing is inconsistent; most Goals/Non-Goals bullets are 300–600-character unbroken lines. **Sources:** Stage 7 nits on bundle, actor terminology, version casing, line length; Stage 9 finding 24/25. **Action:** Use "evidence bundle" and "audit bundle"; define one term per actor; replace "null actor fails" with "must not observe the nonce"; use one casing; wrap lines.

### N-05. Probe types and evidence fields are under-specified

`ProbeContext`/`ProbeEvidence` have no field types or required markers; `ProbeEvidence` has no job/target/attempt key; the probe-kind enums differ across lines. **Sources:** Stage 7 "Probe types are under-specified" (Nit); Stage 9 finding 5/6. **Action:** Add field tables, keys, and one probe-kind enum.

### N-06. The prompt-injection gate has no detection oracle

The gate requires hostile fixtures to fail, but no rule maps detected injection to `policy_blocked`, and the validator is told to treat narrative as data. A hostile transcript could be ignored while the nonce is observed. **Sources:** Stage 7 "Prompt-injection gate has no detection oracle" (Nit). **Action:** Define the detection/policy rule and expected reason code per fixture, or narrow the gate to "no host effect and no fabricated evidence."

### N-07. Job-slot allocation is undefined

`10.<job-slot>.0.0/24` has no slot range, allocator, persistence, or reuse rule; with one job the value is effectively constant. **Sources:** Stage 5 "`job-slot` is undefined and speculative" (Nit); Stage 7 "Job-slot allocation is undefined" (Major). **Action:** Fix the subnet to a constant or define the allocator and collision handling.

### N-08. Retention and bundle reconstruction conflict

G9 promises a bundle that reconstructs the job while overlays/archives are pruned by policy with no window; indefinite retention is a Non-Goal. **Sources:** Stage 7 "Retention and bundle reconstruction conflict" (Nit). **Action:** State the retention window and whether pruning breaks reconstruction, or qualify the promise.

### N-09. File-operation metadata is incomplete

`.env.example`, `.gitignore`, and `SITEMAP.md` are marked Modify without create-if-absent behavior; no deletion list is given. **Sources:** Stage 9 finding 22 (Nit). **Action:** State create-if-absent behavior and confirm no deletions.

### N-10. Undefined settings and shorthand remain

"Session-to-broker settings," "attempt defaults," "engine," "token/SSRF," "tamper notes," "monotonic durations," "minimal accessible layout," and "they do not become acceptance surprises" are undefined or colloquial. **Sources:** Stage 9 findings 24–26 (Nits); Stage 7 style nits. **Action:** Name the actual settings, use "runner and state machine," say "token and SSRF guard," align tamper terminology, say "monotonic clock for all durations and timeouts," and state the accessibility criterion.

## Traceability matrix

Stage 5 and 8 findings are referenced by title; Stage 6 by its numbered findings; Stage 7 by title and severity; Stage 9 by its numbered findings.

| Consolidated | Severity | Source findings |
| --- | --- | --- |
| B-01 Budget exceeded | Blocker | S5 "Binding budget is already exceeded"; S8 B1; S9 1; S7 "Binding budget is not fully quantified" |
| B-02 Two-VM/broker gates, ADR, budget | Blocker | S8 B1; S8 "The two-VM's causal justification..."; S5 "Binding budget..."; S5 "Dirty Frag's decisive evidence..." |
| B-03 Broker verb/privilege/transport | Blocker | S7 "Broker fixed-verb contract..."; S9 3, 4; S5 "Broker/network/reboot/transport..."; S8 "The root broker is over-privileged..."; S7 "Component and interface inventories..." |
| B-04 State machine | Blocker | S7 "Runner state machine is internally contradictory"; S9 2; S5 "The state machine loops..."; S6 6; S8 "The runner state machine models..." |
| B-05 Pack/probe/types | Blocker | S7 "Typed target-pack schema..."; S9 5, 6; S5 "The target-pack and probe contracts..."; S8 "The typed target-pack abstraction..."; S6 9 |
| B-06 Checked-in scripts/hash/null actor | Blocker | S5 "Checked-in provisioning still has a live repair path"; S7 "V1 both requires and defers..."; S9 8, 10; S7 "Checked-in script and PoC hash pins..."; S7 "Null-actor contract..."; S6 1; S8 "The extractor/ADK pipeline..." |
| B-07 Dirty Frag flow/evidence | Blocker | S5 "Dirty Frag's decisive evidence..."; S8 "The two-VM's causal justification..."; S9 7; S7 "Dirty Frag flow contradicts itself"; S6 3 |
| B-08 Network/mirror/offline | Blocker | S9 3, 9; S6 4; S7 "Network contract conflates..."; S5 "The offline provisioning mirror/catalog..."; S8 "The artifact hash catalog..." |
| B-09 Nonce identity/boundary | Blocker | S6 2; S8 "The nonce value's secret boundary..."; S7 "Nonce identity is never persisted..."; S7 "Nonce injection conflicts..."; S5 "`validations` has no nonce id/hash"; S9 14 |
| M-01 Authority/verdict/acceptance | Major | S6 8; S7 "`authority` has incompatible values..."; S9 15; S5 "The state machine loops..." |
| M-02 ADK/extractor/pack/state YAGNI | Major | S8 "The extractor/ADK pipeline..."; S8 "The typed target-pack abstraction..."; S8 "The runner state machine models..."; S5 "The design reinvents the VM harness..." |
| M-03 Failure codes/clamp | Major | S7 "Reason-code coverage..."; S9 15; S5 "`nonce_not_observed` and `exploit_failed` overlap" |
| M-04 Attempt/tool_calls/DDL | Major | S5 "The attempt/retry model..."; S7 "Attempt model is undefined..."; S7 "`tool_calls` table has no defined writer"; S7 "Redaction-before-write..."; S9 14 |
| M-05 Snapshot/restore/freshness | Major | S5 "Snapshot/restore semantics..."; S7 "Nonce injection conflicts..."; S9 7, 11 |
| M-06 Setup scripts/hash verify | Major | S9 11; S7 "Checked-in script and PoC hash pins..."; S5 "Checked-in provisioning..." |
| M-07 Budget enforcement details | Major | S7 "Binding budget is not fully quantified..."; S9 12 |
| M-08 API/check/token | Major | S5 "The request-integrity token is not applied..."; S7 "Check links and Start are not bound..."; S9 13 |
| M-09 Host prerequisites/dependencies | Major | S9 16, 17; S7 "Component and interface inventories..."; S6 11 |
| M-10 Risks/ADR/alternatives | Major | S5 "The risk acceptance is claimed but not recorded"; S7 "Mandatory Risks and Mitigations..."; S7 "Alternatives section labels..."; S8 B1 |
| M-11 PoC link/source shape/admission | Major | S7 "Source-shape detection and PoC admission..."; S7 "Check links and Start..."; S5 "The PoC-link contract..."; S9 13 |
| M-12 Catalog TOFU/build deps | Major | S8 "The artifact hash catalog..."; S7 "Attacker build dependencies..."; S9 9 |
| M-13 Phase 0 consequences/preflight/phases | Major | S7 "A failed Phase 0 gate..."; S9 19 |
| M-14 Component/interface ownership | Major | S7 "Component and interface inventories..."; S9 4 |
| M-15 Redaction/append-only | Major | S7 "Redaction-before-write..." |
| M-16 Mirror/offline package set | Major | S9 9; S5 "The offline provisioning mirror/catalog..."; S7 "Network contract conflates..." |
| M-17 Phase 0 in implementation order | Major | S5 "Binding budget..."; S9 19; S6 9 |
| M-18 Help/terminology | Major | S9 20, 21; S7 terminology nits |
| N-01 DDL constraints | Nit | S7 "DDL does not encode the closed sets..."; S9 14 |
| N-02 Additional resources | Nit | S6 10; S7 "Additional Resources are not resolvable" |
| N-03 Title | Nit | S7 "Title overstates the topology" |
| N-04 Terminology/line length | Nit | S7 bundle/actor/version/line-length nits; S9 24, 25 |
| N-05 Probe field types | Nit | S7 "Probe types are under-specified"; S9 5, 6 |
| N-06 Prompt-injection oracle | Nit | S7 "Prompt-injection gate has no detection oracle" |
| N-07 Job-slot | Nit | S5 "`job-slot` is undefined"; S7 "Job-slot allocation is undefined" |
| N-08 Retention/reconstruction | Nit | S7 "Retention and bundle reconstruction conflict" |
| N-09 File metadata | Nit | S9 22 |
| N-10 Undefined settings/shorthand | Nit | S9 24–26; S7 style nits |

## Recommended next decisions

The report does not choose for the owner. The revision makes the choice sharper:

1. **Budget versus scope.** Cut the ADK/extractor/author/repair path, the typed pack layer, the 22-state machine, SSE/backfill, and the extra source adapters to fit 26 modules, or raise the budget explicitly and add the missing budget lines for the two-VM/broker work. The reviewers recommend the simplification; the owner has chosen all three targets, so the raise path needs an explicit line for the attacker VM, broker, root unit, host evidence, and tests.
2. **Two-VM/broker decision record.** Run the restored Phase 0 session-vs-system and one-VM-vs-two gates. If the owner has already decided, record it in ADR 0001 and add the budget lines; do not leave it as an implicit default.
3. **Dirty Frag authority.** Decide whether the host-side channel can be made non-forgeable. If not, use `guest_attested+llm_assessed` or make Dirty Frag `inconclusive` rather than claiming `reproduced`.
4. **Contracts before code.** Freeze the pack/probe schema, broker verbs and transport, nonce id/boundary, state machine, DDL, authority enum, reason codes, and acceptance numbers. The current documents still leave an implementer to invent them.
5. **Artifact and offline provisioning.** Define the mirror process, the complete package set, and the vendor-seeded catalog before Phase 1.

## Review limitations

This review is document-based. The reviewers read the design and the files it references; they did not run the system, boot a VM, create the broker, or execute any PoC. The findings are model output, not a deterministic proof. The earlier revision-2 reports and the prior consolidated report remain as the audit trail.
