# Goldfish Review Report

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (DetailedRange lines 596..743)
**Mode:** REVIEW — Stage 9 (Implementation Readiness Test), revision 2
**Standard:** `implementation-readiness-standard` for `egm-implementation-readiness` and `egm-codebase-details`; persona default for `egm-style`

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-implementation-readiness` | completed |
| `egm-codebase-details` | completed |
| `egm-style` | completed |

All three reviewers reported. No reviewer failed, timed out, or required a retry.

## Prioritized Findings (Blockers -> Major -> Nits)

### 1. Budget gate cannot pass its own binding caps - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 65-66, 616-718
* **Discrepancy Description:** The file table lists 33 Python modules under `src/` and `broker/` (30 excluding `__init__` markers), plus three scripts, against the binding budget of "at most 26 modules" and "5,500 lines." No per-module line allocation or counting rule is given, so neither the implementer nor the G14 budget gate can determine compliance.
* **Rationale & Recommendation:** A plan that fails its own acceptance gate cannot be implemented to completion. Reduce or recount the module list and add a per-module table with target line counts and an explicit counting rule (tests, scripts, and `__init__` markers).

### 2. Runner state machine has no reachable terminal outcome and cannot record cancellation - Severity: Blocker
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`
* **Affected Scope:** Lines 244-272, 396-448, 579
* **Discrepancy Description:** `completed`, `failed`, `cancelled`, and `interrupted` are declared terminal, but every one has an outgoing Next row: `completed -> done`; the other three go to `destroying`. `destroying` permits only `validating` or `failed`, so `failed -> destroying -> failed` is an infinite loop and cancelled/interrupted jobs can never record a terminal outcome. `done` is the only true terminal state but is absent from the outcome list. There is also no persistence for a cancel request, no else-branch in `running_null`, no reboot/repair state for Dirty Frag, and no domain-naming convention for the orphan sweep.
* **Rationale & Recommendation:** The implementer cannot encode a total transition function or guarantee job termination. Complete the transition table with every edge and guard, add cancel/lease columns and persistence, define terminal outcomes explicitly, add the missing reboot/evidence states, and define domain and network naming.

### 3. Broker verb set cannot implement network control, mirror lifecycle, or cancellation - Severity: Blocker
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`
* **Affected Scope:** Lines 185-198, 267-272, 499-500, 684, 688
* **Discrepancy Description:** The fixed verb set has no root-side operation for nftables default-deny, the egress test, starting/stopping the artifact mirror, or interrupting a running guest command. Yet the app-side `NetworkManager` exposes `allow_artifact_mirror`, `default_deny`, and `egress_test`, and cancellation requires interrupting the current `exec`. The unprivileged app cannot perform these operations, so the stated privilege split is unachievable. `read_host_evidence(vm_id, channel)` also has no stated QMP/serial semantics matching the evidence-channel enum. Host-side `http_get`/`response_parse` requires host-to-guest reachability, but the network profile says `host route: none` with default-deny.
* **Rationale & Recommendation:** Extend the fixed verb set and protocol with explicit operations for nftables apply/verify, mirror start/stop, and `cancel(vm_id, request_id)` or an equivalent request-id cancel message. Define `exec` timeout, partial-output, and abort-on-disconnect behavior; define host-evidence QMP/serial semantics; and state the probe execution locus and any nftables/host-route exception.

### 4. Broker cannot resolve packs, profiles, images, guest IPs, or provide guest exec/copy - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 186-197, 315, 486-501, 610-614, 633-634, 686-688
* **Discrepancy Description:** `start_target(job_id, profile_id, image_id)` passes only ids, yet target resources live in packs, only `profiles/attacker.yaml` exists, and no file defines a broker-side target-profile registry, a fixed domain XML template, `image_id` to host-path resolution, or a verb returning a guest IP even though `VmDriver` exposes `private_ip`. The guest `exec`/`copy_in`/`copy_out` mechanism is unchosen: qemu-guest-agent plus virtio-serial, or SSH. Host prerequisites omit the guest agent/channel; the network allow-list covers only the target port; `asyncssh` is declared with no consumer. The implementer must invent the profile registry, XML template, image lookup, IP discovery, and transport.
* **Rationale & Recommendation:** Add a broker profile catalog (per-target vCPU, memory, disk, image), the fixed domain template file, start-result fields including guest IP and domain name, the image-path validation rule, and an explicit exec/copy transport with its host and guest prerequisites.

### 5. Typed contracts are named but not defined - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 317-329, 350, 384-388, 485-502, 658, 681
* **Discrepancy Description:** `models.py` lists names only: `Facts`, `SetupBundle`, `TargetPack`, `PocPin`, `RunLimits`, `VmProfile`, `CommandResult`, `SnapshotRef`, `HttpResult`, `Artifact`, `Manifest`, and the classified-log type have no fields, types, requiredness, or validation rules. `LlmVerdict` exists only as example JSON. `SetupBundle`, `RunnerFacts`, `Manifest`, `Artifact`, and `HttpResult` are used but unowned; `models.py` lists none of the first five. `target_id`, `target_pack_id`, `profile_id`, and `pack_id` are used inconsistently. The extractor prompt, pack loader, fake driver, and validator tests cannot be written without these definitions.
* **Rationale & Recommendation:** Add field tables (name, type, required, validation) for every model and the classified-log schema; define the `Facts` citation rule; and unify the target/profile/pack identifier vocabulary.

### 6. Pack contract is internally inconsistent and incomplete - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** Lines 306-336, 338-357, 633-655
* **Discrepancy Description:** (a) Line 355 promises the pack declares the nonce path, owner, and mode, but the schema has only an undefined `nonce_placement`. (b) Probe and evidence kinds differ across lines 321, 347, and 687; `evidence_channel.kind` mixes probe kinds with channel kinds; a single `probe.kind` cannot express Dirty Frag's required `pty_session` plus `host_serial`; and `qmp` appears in the evidence/probe contract but not the probe-kind enum. (c) `network.target_port` is scalar, but GitLab requires 80 and 443. (d) `request`, `expected`, `build`, `invocation_template`, and `null_actor.command_template` have no shape, placeholder vocabulary, or escaping rules. (e) `attacker_profile` is mandatory although Dirty Frag has none, and both `profiles/attacker.yaml` and the inline pack field define the attacker profile without stated precedence. (f) `pack.yaml`, `probe.yaml`, `poc.pin.yaml`, `config/artifacts.yaml`, and `profiles/*.yaml` duplicate image, hash, network, and resource values with no precedence or merge rule.
* **Rationale & Recommendation:** Publish one schema table per pack file, define the template variable set and renderer, state the single source of truth for hashes and resources, and specify merge/precedence rules so `packs.py` can implement a deterministic loader.

### 7. Dirty Frag flow contradicts itself - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** Lines 233-240, 258-260, 264, 334-336, 602, 643-652
* **Discrepancy Description:** The pack says actor `xentry` is non-root, while line 336 says the runner drives a PTY root shell. The C PoC has a "build" step but no target toolchain exists and G7 forbids host builds; "no compiler needed for the remote PoCs" also contradicts the Go build for GitLab and the C build for Dirty Frag. The null actor runs as `xentry`, yet the nonce is root-only. "Restore or fresh boot" is left as an explicit either/or. `running_null` transitions directly to `restoring`, leaving the null-actor host-evidence observation without a state or step.
* **Rationale & Recommendation:** State the exact privilege transition, where and with which toolchain the PoC is built, how a non-root null actor exercises the same read path without the runner's privilege, and whether restore or fresh boot is chosen. Add the missing host-evidence observation state and remove the ambiguous compiler claim.

### 8. Checked-in scripts contradict the author/repair path - Severity: Blocker
* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** Lines 250-251, 287, 324, 358, 384-386, 606, 636-637
* **Discrepancy Description:** `planning` is triggered by "Setup author/repair" and `provision_failed` permits one repair, but V1 uses hash-pinned `checked_in` scripts for all targets. A repaired script cannot match the reviewed hash, breaking the executed-hash claim; otherwise author/repair is dead code, contradicting G3 and the repair budget.
* **Rationale & Recommendation:** State the V1 planning step (load and hash-check the checked-in script, no model call) and whether repair is reachable at all. Remove the dead paths or define a re-hash/re-review flow with its budget effect.

### 9. Artifact mirror and offline provisioning cannot work as specified - Severity: Blocker
* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`
* **Affected Scope:** Lines 202-216, 602, 610-614, 627, 642, 646, 650-652, 684
* **Discrepancy Description:** No component serves the artifact mirror, and no address, port, bind rule, nftables allowance, or lifecycle before default-deny is defined. "Host route: none" conflicts with a host-local mirror. Hash-pinned setup scripts cannot embed the job-varying `10.<job-slot>` mirror address. `fetch-artifacts.sh` fetches only images, the GitLab `.deb`, and the kernel, so the PHP 8.4.26 source build and GitLab Omnibus install cannot obtain apt build dependencies offline. The Dirty Frag C PoC needs a compiler the target never provisions.
* **Rationale & Recommendation:** Define the mirror process, bind address, port, URL, nftables exception, and lifecycle. Fetch all offline dependencies or prebuild them into the images, and make the mirror reachable from static scripts via a fixed slot or DNS alias.

### 10. "Null actor fails" inverts the acceptance semantics - Severity: Blocker
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Lines 728 and 738; contrast line 289
* **Discrepancy Description:** "Null actor fails" is the opposite of the document's own closed code `null_actor_failed` (line 289), which means the job failed because the null actor did observe the nonce. In the verification text it reads as the null actor failing to observe the nonce, which can invert a core causal check.
* **Rationale & Recommendation:** Replace with "the null actor must not observe the nonce" or "the null-actor check passes."

### 11. Setup scripts have no actionable content - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** Lines 606, 641-652
* **Discrepancy Description:** These acceptance-critical deliverables are described in one line each: no mirror URL, package sources, readiness command, nonce path and permissions, reboot/wait handling, or `uname -r` mechanics.
* **Rationale & Recommendation:** Add per-script step outlines and the readiness contract (command, expected output, timeout) that `provisioning` and `ready_target` consume.

### 12. Budget enforcement and attempt accounting are unpinned - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 59-78, 251, 296, 308-329, 404-409, 613, 636, 658
* **Discrepancy Description:** The per-call token value, VM-cycle definition, `RunLimits` fields, memory admission headroom, disk accounting (overlays, ISOs, artifacts versus per-VM disk), pruning policy, and job-level timeout are undefined. G11 says caps live in packs, but the pack schema has no token or VM-cycle fields. "Line cap" has no value, unit, or config key, though the "Script under cap" guard depends on it. `retry_policy`, `attempt_no`, `previous_attempt_id`, and `fresh_vm_on_retry` imply multiple attempts, but no state edge or rule creates an attempt row; `RunLimits` is listed in `models.py` but never referenced.
* **Rationale & Recommendation:** Give each cap a value, owner (pack versus config), measurement point, and failure behavior. Define attempt creation, reuse, and cleanup rules.

### 13. HTTP API contract is incomplete - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 137, 394-403, 453-468
* **Discrepancy Description:** `check_id` is optional with no store, TTL, or reuse rule. `jobs.cve_id` is NOT NULL although submit accepts URLs only. CUJ6's "no model spend" is not reconcilable with extractor-based target identification. No error envelope or status codes are specified for any endpoint.
* **Rationale & Recommendation:** Define the check store and submission precondition, a deterministic target-identification step, and a single error schema with status codes.

### 14. SQLite DDL cannot express required outcomes - Severity: Major
* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** Lines 82-83, 396-448, 628, 654, 659
* **Discrepancy Description:** The DDL supplies no indexes, CHECKs, or enum values. There is no cancel flag despite the cancel API and queue cancel flag; no nonce value/hash or nonce id despite the acceptance gate "validation row tied to its nonce" and CUJ3's nonce id; no uniqueness on `(job_id, attempt_no)` or `(job_id, seq)`; and no timestamp format. `tool_calls` has no writer because the agent has no tools. Three owners (`db.py`, `scripts/migrate.py`, `migrations/`) run migrations with no split of responsibility.
* **Rationale & Recommendation:** Complete the DDL with constraints, indexes, nonce columns, timestamp format, and a single migration owner.

### 15. Closed codes and authority are ambiguous - Severity: Major
* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** Lines 270, 290-293, 326, 448
* **Discrepancy Description:** `nonce_not_observed` and `exploit_failed` share the same observable trigger with no discriminating rule. `validator_error` says "Park or record `inconclusive`," an unresolved choice, and no authority value is given for that case. `runner_observed` (line 448) is used but never defined alongside `runner_observed+llm_assessed`. `destroy_policy.failure_code` has no permitted value set.
* **Rationale & Recommendation:** Provide a decision table mapping observations to closed codes, define the authority enum, and enumerate permitted `failure_code` values.

### 16. Host prerequisites are infeasible and incomplete - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-style`
* **Affected Scope:** Lines 608-614
* **Discrepancy Description:** libvirt 12+/QEMU 10+ is not available on the Ubuntu 24.04 baseline used elsewhere, and the host OS is unpinned. There are no install/enable commands, AppArmor/SELinux policy, image-store layout, or broker runtime environment (the broker needs libvirt-python and YAML, but only the app's `uv` environment is specified). "GitLab peaks at 10 GB of guest memory" misstates the budget: 10 GB is the host allocation comprising an 8 GB target plus a 2 GB attacker (line 72). "40 GB of disk" is introduced without appearing in the binding budget (100 GB total, per-job cap in the pack).
* **Rationale & Recommendation:** Pin the host OS and component versions, add exact setup steps and broker dependencies/environment, and align the memory and disk figures with the measured budget basis.

### 17. Dependency list is incomplete and contradictory - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 600, 625-626, 629, 722
* **Discrepancy Description:** `uvicorn` is used by `run-dev.sh` but not declared. `uv sync --extra dev` has no defined dev group. `asyncssh` is declared but no component uses it, and SSH from the app contradicts broker-only execution and `host route: none`. `libvirt-python` in the app dependency set conflicts with the "app cannot open a libvirt connection" gate. The 14-dependency count rule is undefined.
* **Rationale & Recommendation:** Publish exact runtime and dev dependency lists, assign each dependency to its owning component, and define the counting rule.

### 18. Files, tooling, and tests for mandatory claims are missing - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** Lines 394-448, 553, 616-733
* **Discrepancy Description:** No rebuild command exists for the "rebuildable" index. No test covers the budget, migrations/rollback, preflight admission, API routes/errors, cancel/teardown failure, or host-evidence tampering. Fixture formats for the 20/20/5 gates and the libvirt-test gating mechanism are undefined; the budget gate and newer-schema refusal have no test files; `scripts/` is neither linted nor covered.
* **Rationale & Recommendation:** Enumerate the missing files and tests, define fixture layout and labels, specify skip markers and the `--extra dev` group, and include `scripts/` in lint/coverage scope.

### 19. Phases are not actionable checkpoints - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** Lines 618-718, 735-743
* **Discrepancy Description:** The phases are week buckets, not tasks. No file-to-phase mapping or per-phase checkpoint exists, so Phase 1 cannot be executed as a stable, testable increment. Phase 1 acceptance already requires PHP2Shell end to end with two VMs, while Phase 2 lists the attacker VM as new work, so the same component is both required and deferred.
* **Rationale & Recommendation:** Assign files and tests to each phase with explicit exit checks, and move the attacker VM into Phase 1 or defer the two-VM acceptance criterion.

### 20. Profile and entity terminology is ambiguous - Severity: Major
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Lines 70, 318, 354, 602, 612, 616, 633
* **Discrepancy Description:** "Two VM profiles: target and attacker" (line 602) conflicts with the budget's "one target profile per target; one lightweight attacker profile" (line 70) and reads as two literal profiles. `xentry` names both the host app user and the guest actor user (lines 612, 318, 354), which is risky in a document about privilege separation. The heading "Target files to create or modify" uses "Target" in its CVE/VM sense; a fresh reader can read it as files for the target VM.
* **Rationale & Recommendation:** Say "two profile types," qualify every occurrence as "host app user" or "guest actor," and use "Repository files to create or modify."

### 21. Help surface differs from the feature specification - Severity: Major
* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** Lines 465, 468, 694
* **Discrepancy Description:** The feature specification requires one help modal, but the plan creates a `GET /help` page and `templates/help.html`.
* **Rationale & Recommendation:** Choose one form (modal or page) and align the route, template, and acceptance test with the specification.

### 22. File-operation metadata is incomplete - Severity: Nit
* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** Lines 616-718
* **Discrepancy Description:** The file table marks `.env.example`, `.gitignore`, and `SITEMAP.md` as Modify, but does not state create-if-absent behavior, and no deletion list is given.
* **Rationale & Recommendation:** State whether scaffold files are created if absent and confirm that no deletions occur.

### 23. Dummy pack contradicts the generated-source rejection - Severity: Nit
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-style`
* **Affected Scope:** Line 653
* **Discrepancy Description:** `targets/_dummy/pack.yaml` is a generated-source pack in a V1 that rejects generated sources; loader behavior for `script_source: generated` is undefined, and "test-only generated pack" collides with "generated provisioning."
* **Rationale & Recommendation:** Drop the dummy pack or document an explicit test-only bypass and its `script_source`.

### 24. Undefined settings and shorthand - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Lines 623, 738
* **Discrepancy Description:** "Session-to-broker settings" and "attempt defaults" are undefined terms. "Engine" is not defined in the architecture vocabulary, and "token/SSRF" is compressed shorthand.
* **Rationale & Recommendation:** Name the actual settings being added or removed, use "runner and state machine," and name the token and SSRF guard.

### 25. Terminology drift from schema and specification - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Lines 614, 644, 685
* **Discrepancy Description:** "invocation" drifts from the schema field `invocation_template`; "tamper notes" differs from "tamper analysis" and "known-limits statement"; "monotonic durations" is ambiguous.
* **Rationale & Recommendation:** Use the schema field name, align the tamper terminology, and say "monotonic clock for all durations and timeouts."

### 26. Subjective and opaque phrasing - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** Lines 695, 706, 743
* **Discrepancy Description:** "Minimal accessible layout" has no accessibility criterion; "they do not become acceptance surprises" is colloquial; "no target-id branches" is opaque test intent.
* **Rationale & Recommendation:** State the accessibility criterion, write "Phase 0 failures revise the plan before Phase 1," and say "no target-specific branching; behavior is driven by pack fields."
