# Goldfish Review Report

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (`lines 1-595`, FeatureRange)
**Revision:** 2
**Stage:** 7 (Critic Review)

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-design` | completed |
| `egm-structural` | completed |
| `egm-style` | completed |

Note: `egm-design` and `egm-style` exceeded the output-token limit on their first attempt and completed on the single permitted retry. All findings apply only to lines 1-595; the Detailed Implementation Plan (lines 596-743) was excluded from review and was not used to resolve any gap below. Findings reported against the same defect by multiple lenses are merged; where reviewers disagreed on severity, the higher severity is retained.

## Prioritized Findings (Blockers -> Major -> Nits)

### Broker fixed-verb contract is incomplete and accepts unvalidated parameters - Severity: Blocker

* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 183-200, 206-218, 336, 354, 472-473, 480, 485-502`
* **Discrepancy Description**: The enumerated broker verbs (`ensure_network`, `start_target`, `start_attacker`, `exec`, `copy_in`, `copy_out`, `snapshot`, `restore`, `read_host_evidence`, `destroy_vm`, `destroy_network`, `list_managed`) contain no operation to apply the nftables default-deny rule, run the required egress test (216), or serve and authorize the host-local artifact mirror (216), even though the Components table assigns nftables to the broker (173) and `NetworkManager` exposes `allow_artifact_mirror`, `default_deny`, and `egress_test` as separate operations (499-500). Line 200 claims the broker rejects "arbitrary commands," but `exec(vm_id, user, argv, tty, timeout)` accepts arbitrary `argv` and any `user` - root included, which is how line 336 drives a "PTY root shell" - while `copy_in` accepts an arbitrary `guest_path` and `start_target`/`start_attacker` accept an arbitrary `image_id`. The stated validation set (200) covers only job id, profile id, and host path; it does not cover `image_id`, `vm_id`, `network_id`, `user`, `argv`, or `guest_path`. `list_managed()` has no defined managed-resource marking although CUJ 5 (131) requires destroying only "xentry-managed" domains. Guest transport (guest agent, SSH, serial) and the credential model are undefined, and line 480 excludes keys/passwords from guests. Socket path, socket owner/mode, and expected peer UID are never stated.
* **Rationale & Recommendation**: The broker is the only privileged boundary (G4, G7, acceptance gate at 88), so a verb set that cannot express the firewall, egress test, and mirror means either the security claim is false or the network design is unimplementable. Add explicit verbs for firewall application, egress verification, and mirror authorization; replace free-form `exec`/`copy_in`/`start_*` with step-bound calls validated against pack-declared command templates and a user allowlist (root permitted only for a declared Dirty Frag step); define `image_id`/`vm_id`/`network_id`/`guest_path` validation and the managed-resource tag; state the socket identity and expected peer UID; define the guest transport and credentials and add an exec-transport Phase 0 gate.

### Runner state machine is internally contradictory - Severity: Blocker

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 244-272` (state table and paragraph at 270)
* **Discrepancy Description**: Line 270 declares `completed`, `failed`, `cancelled`, and `interrupted` terminal, but the table routes `failed`, `cancelled`, and `interrupted` to `destroying` (266-268). `destroying` has Next "`validating` or `failed`" (263) with no guard distinguishing the two, so a failed, cancelled, or interrupted job can reach `validating`; `failed -> destroying -> failed` is an unguarded loop with no stop condition for repeated cleanup failure; `done` is a Next target of `completed` (265) and is called out at 270, but it has no row, trigger, guard, or cleanup and duplicates `completed` because cleanup already happened in `destroying`; `queued` has a "preflight pass" guard (248) although there is no `preflight` state and preflight is a user-triggered API call (463). The guard column sometimes records a property ("Idempotent") rather than a condition. No state represents nonce injection or Dirty Frag's reboot/fresh boot. The failed/cancelled/interrupted cleanup column destroys both VMs but omits the network, while `creating_network` cleans up only `destroy_network`.
* **Rationale & Recommendation**: G8 makes this table the contract for cancellation, recovery, and destroy-before-validate, and the acceptance gates at 82-88 depend on terminal behavior. Split lifecycle state from outcome (route `failed`/`cancelled`/`interrupted` to `destroying` and then to a single terminal state, never to `validating`); define or delete `done`; add guards for every branch; specify the full cleanup set per state including network, overlays, and ISOs; define the operator action when teardown repeatedly fails; model nonce injection and reboot/fresh boot explicitly.

### Typed target-pack schema cannot express the three V1 packs - Severity: Blocker

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 308-330` (manifest), `334-336` (packs), `340-350` (probe/evidence contract), `352-358` (nonce contract)
* **Discrepancy Description**: (a) `probe.kind` (321) is `http_get|response_parse|pty_session|host_serial` and omits `qmp`, although the probe contract (347) defines `qmp` and `evidence_channel.kind` (323) admits it. (b) `probe` is a single object with one `kind`, but PHP2Shell needs an HTTP fetch plus a nonce parse (334, 343-344) and Dirty Frag needs a PTY session plus a host-serial read (336, 345-346); the schema cannot express two primitives or designate which one decides `nonce_observed`. (c) `network: {profile: isolated, target_port: 8088}` (317) has one port, while the GitLab pack requires 80/443 (335) and the firewall rule is written for "the target service port" (216). (d) Line 355 says "The target pack declares the path, owner, and mode" for the nonce, but the manifest has no `nonce` block - only an undefined `nonce_placement` string inside `probe` (321). Additionally, `attacker_profile` is unmarked although Dirty Frag has no attacker, and the example uses YAML set-style `{name, url, sha256}` rather than typed fields.
* **Rationale & Recommendation**: The typed pack is the single source of truth for the pre-run plan (G10), the broker profile, and the probe, so a schema that cannot encode the three acceptance targets leaves the packs unvalidatable. Make `probe` an ordered list of typed primitives with one designated decisive primitive; add `qmp`; make the port field a list (`target_ports`); add an explicit `nonce: {path, owner, mode, value_source}` block; unify the three probe/evidence enumerations into one source of truth; mark optional fields; provide a concrete manifest plus a JSON Schema; require the null-actor user to match the actor user where applicable.

### V1 both requires and defers setup authoring and repair - Severity: Blocker

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 9, 27, 29, 55, 76, 176, 251-252, 287, 324, 355, 358, 382-390, 496-497, 537-541`
* **Discrepancy Description**: The Overview and G3 say the agent authors a setup script and PoC wrapper (9, 27), `AgentRuntime` exposes `author_setup`/`repair_setup` (382-390, 496-497), the `planning` state is triggered by "Setup author/repair" with a "Script under cap" guard (251-252), the budget allocates "One bounded repair per attempt" (76, repeated at 324), `provision_failed` retries with "One repair" (287), and the ADK gate measures repair success on 20 fixtures (390). Yet G5 (29), line 358, and Alternative 5 (537-541) state all three V1 targets use hash-pinned checked-in scripts and the generated path is V1.1, not used for V1. Repairing a hash-pinned, hand-reviewed script either changes the reviewed hash or cannot run, so the capability is unexercised by every acceptance target and contradicts the pin. A related leak: line 355 says the nonce path is kept out of the setup-author prompt and generator context, but `author_setup(facts, pack)` receives the pack, whose `probe.nonce_placement` and Dirty Frag channel path are that location.
* **Rationale & Recommendation**: Remove authoring/repair from the V1 path - states, retry policy, budget, and ADK metric - and make `provision_failed` non-retryable, or define repair as selecting a reviewed variant whose hash is in the pack and state whether the PoC wrapper is generated or a checked-in template. If authoring is retained, specify the redacted pack projection and the exact nonce-path fields removed from the model context.

## Major Findings

### Checked-in script and PoC hash pins are recorded but never verified - Severity: Major

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 29, 88, 253-254, 281, 319-321, 358, 537-541`
* **Discrepancy Description**: The security value of the checked-in-script decision is that "the reviewed hash describes what runs" (539). The state machine verifies an image hash at `creating_target` (253) and a PoC link pin at admission (`unsupported_poc`, 281), but no state, guard, interface, or reason code verifies `setup_script.sha256` before provisioning or `poc.sha256` against downloaded bytes. Line 358 promises to "record" the executed hash, not to compare it, and no failure code exists for a hash mismatch.
* **Rationale & Recommendation**: A recorded hash with no comparison is audit data, not a control, and Alternative 5's whole argument rests on it. Add a `planning` or `provisioning` guard that verifies script and PoC hashes, and an `artifact_hash_mismatch` reason code with no retry.

### Nonce identity is never persisted, so "tied to its nonce" cannot be evaluated - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 82-83, 119, 352-355, 396-446, 423-433`
* **Discrepancy Description**: Acceptance requires every completed job to have "a validation row tied to its nonce" (82-83), and CUJ 3 (119) displays a "nonce id." The schema stores only `runner_nonce_observed INTEGER`; there is no nonce table and no `nonce_id`, `nonce_sha256`, `nonce_path`, or creation timestamp in `attempts` or `validations`. Nothing identifies which nonce was placed, at which path, or when.
* **Rationale & Recommendation**: The nonce is the design's only causal anchor (G6), so an unidentifiable nonce makes the acceptance gate unmeasurable and the audit bundle unable to show which value was observed. Add a nonce identity (hash only, never the value) to `attempts`, reference it from `validations`, define "nonce id" as that hash, and record the nonce id in attempt evidence.

### Nonce injection conflicts with freeze/restore and restore has no readiness recheck - Severity: Major

* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 30, 226-238, 355`
* **Discrepancy Description**: The nonce is generated "after the freeze" and before the null actor, but freeze is a snapshot and the state table has no nonce step. The protocol is undefined if freeze is a pause. After restore the real actor runs with only a "Restore pass" guard; Dirty Frag's "restore or fresh boot" has no state either. A placement race, a reverted file, or an unready service makes `nonce_observed` unreliable.
* **Rationale & Recommendation**: The nonce is the causal evidence, so placement timing is load-bearing. Specify a live-snapshot or stop/snapshot/resume protocol; inject and record nonce ids while the guest runs; re-run readiness and version probes after restore; model reboot and fresh boot explicitly.

### `authority` has incompatible values and verdict/authority projection is undefined - Severity: Major

* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 11, 21, 34, 82, 107, 270, 378, 423-433, 448, 509`
* **Discrepancy Description**: The same field is described as `llm_assessed` (11, 21, 509, where it is called a verdict), `runner_observed` (448, for null-actor failure), and `runner_observed+llm_assessed` (82, 107, 270, 378, where it is written on every validation row and therefore carries no information). The verdict domain is separately given as `reproduced|not_reproduced|inconclusive|not_run` (270, 371); no authority domain is enumerated, and no rule maps Dirty Frag's guest-attested evidence (508) or `validator_error` to a value. Separately, `jobs.verdict`/`authority` are defined as the projection of the final attempt's validation (448), while a null-actor failure writes `verdict = not_run`, `authority = runner_observed` and never reaches the validator; `validations` makes authority, model, prompt hash, and nonce observation NOT NULL (423-433), so the main failure path has no defined projection source and a rebuild from attempt files cannot reproduce the job row.
* **Rationale & Recommendation**: G10's honesty guarantee is carried entirely by this field, so an undefined domain lets the UI, bundle, and acceptance gate disagree. Define `authority` as a closed enum with a stated outcome-to-value mapping, include a distinct Dirty Frag value, stop calling the verdict `llm_assessed` in the Overview and Overall prose, add a runner-owned outcome record for non-validated outcomes, and name the authoritative artifact for `not_run`.

### Reason-code coverage has gaps and overlaps, and the clamp target is underdetermined - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 77, 93, 124-125, 216, 248, 253-260, 266-272, 276-302, 357-358, 372, 378, 400, 407, 428`
* **Discrepancy Description**: Failure points with no code: egress-test failure (216), image/script/PoC hash mismatch (253), snapshot or restore failure (258-260), nonce placement failure, artifact-mirror failure, and preflight admission refusal (93, 248). `nonce_not_observed` (290) and `exploit_failed` (291) both mean "the real run produced no nonce," but they carry different retry policies (one rerun vs no retry) with no discriminator. `teardown_failed` (299) and `security_cleanup_failed` (300) overlap, and CUJ 4 (125) assigns the Dirty-Frag-specific code to every failed destroy. Line 357 says a negative nonce yields "`failed` or `inconclusive`," and line 378 says `reproduced` is "clamped to false" without naming the replacement verdict; the validator's `reason_code` ("closed code," 372) is not drawn from the table at all. Naming also diverges: `reason_code` in `jobs`/`validations` versus `failure_code` in `attempts` (400, 407, 428).
* **Rationale & Recommendation**: G11 promises a closed code with a next action for every failure, so uncovered points will collapse into `harness_error` (302), which is not actionable. Add the missing codes, define each overlap boundary with a discriminator (for example, a pre-run infrastructure health check) or merge the codes, fix the clamp to a single verdict, make one closed enum shared by runner and validator, and align naming.

### Attempt model is undefined while being load-bearing - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 33, 76, 394-448, especially 404-409, 415-440, 448`
* **Discrepancy Description**: `attempts` has `attempt_no` and `previous_attempt_id`, and `validations`, `artifacts`, and `tool_calls` all require `attempt_id NOT NULL`. But the state machine has no attempt concept, no trigger creates attempt 2, `jobs.attempt_dir` duplicates `attempts.attempt_dir`, and `attempts.state` duplicates `jobs.state`. It is unstated whether a fetch retry, PoC rerun, setup repair, or fresh-VM retry creates a new attempt, reuses a VM, or resets state. Line 448 refers to "the final attempt's validation," presupposing a policy that does not exist. `vms` also lacks `attempt_id` despite fresh-VM retries, and there is no network table or per-job disk-cap field.
* **Rationale & Recommendation**: Attempt identity governs artifact ownership, rebuild correctness, and the audit bundle, so the current ambiguity makes "SQLite is a rebuildable index" unimplementable. Define an attempt as a run segment, state exactly which retries start one, remove duplicated columns, add `attempt_id` to `vms`, and record network ids per attempt.

### `tool_calls` table has no defined writer in V1 - Severity: Major

* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 27, 380-390, 415-422, 485-502`
* **Discrepancy Description**: The model has three calls and no tools (382) and no fetch/execute/validate/destroy tools (27), yet the schema contains `tool_calls(tool, params_json, params_sha256, ...)`, which reads as model tool invocations. Broker calls are the only analogous operations, but the `BrokerClient` interface (489-491) says nothing about logging, and no component is assigned to write these rows.
* **Rationale & Recommendation**: A schema element with no producer cannot be part of a "defined schema" or of the audit contract. Rename and define it as broker/runner operations (for example, `broker_calls`, one row per verb) with an owning component, or remove it.

### Redaction-before-write contradicts raw-evidence storage and hash anchoring - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 33, 350, 448, 480`
* **Discrepancy Description**: Line 448 says the attempt directory contains "raw evidence" and also that "Redaction runs before any write." Both cannot hold for the same bytes. Line 350 says the runner resolves every evidence reference against transcript or artifact hashes, but the spec never says whether those hashes cover the observed bytes or the redacted copy. "Append-only JSONL" has no write-once or hash-chain mechanism.
* **Rationale & Recommendation**: The hashes are the audit anchor for the validator and the bundle; an unspecified redaction order means a hash may describe a redacted copy and the validator's cited evidence may no longer be verifiable. Write and hash raw bytes first, apply redaction only to derived copies (validator input, bundle, UI), record both hashes, and state how append-only is enforced.

### Network contract conflates traffic directions and contradicts the artifact mirror - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 92, 202-218, 342-348, 472-473, 497-500`
* **Discrepancy Description**: The block sets `forward mode: none` and `host route: none` (213), yet line 216 requires the target to reach a host-local artifact mirror during provisioning, and `http_get`/`response_parse` have the runner GET a target URL from the host. The post-provision rule "default-deny all egress from the network except the target service port used by the attacker and the runner's probe path" mixes three directions: intra-bridge guest-to-guest, host-to-guest probing, and guest-to-outside egress. The mirror's address, port, serving process, and firewall exception are never stated, and `host route: none` appears to forbid the very path the mirror needs. The required egress test (216) has no broker verb (see Blockers), no state, and no failure code.
* **Rationale & Recommendation**: The egress test is a Phase 0 gate (92), so an implementer must know which tables and chains are meant and how the mirror is reachable. Define the mirror as a host service on the bridge gateway with a stated address and port, state post-provision rules per direction, define transient firewall phases and mirror/egress tests, state whether probes run broker-side, attacker-side, or host-side, either define or delete "host route: none," and add the broker egress-test verb, state/guard, and failure code.

### Null-actor contract is defined two ways and is undefined for remote PoCs - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 30, 82, 227-228, 258-260, 289, 322, 356`
* **Discrepancy Description**: The lifecycle calls it "null actor (attacker no-op)" (228), while G6 and line 356 say it runs the same wrapper with the exploit removed or invalidated and exercises the same probe read path. For remote PoCs it is launched from the attacker VM, so "user" and "probe read path" refer to different hosts. The manifest's `null_actor` declares only `user` and `command_template` (322). Acceptance "the null actor must fail" (82) is ambiguous between "fails to observe the nonce" and "job fails," and `null_actor_failed` (289) means the null actor did observe the nonce - inverted from the acceptance wording. No artifacts are specified for the attacker-side no-op.
* **Rationale & Recommendation**: The null actor is the control that rules out a pre-existing nonce, so its execution location and evidence set are load-bearing. Add `null_actor.location` (target or attacker), profile reference, exact invocation, expected target-side observation, and retained artifacts for both topologies; rename the reason code so it states the observed condition; define "must fail" as nonce absence, not job failure.

### Component and interface inventories are incomplete and unmapped - Severity: Major

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 168-179, 215-216, 452-466, 483-502`
* **Discrepancy Description**: No component owns the artifact mirror (215-216), the preflight gate (`POST /api/preflight`, 463), the audit-bundle export (462), or the "plan" G3 assigns to the runner. `Fetcher` and `EvidenceStore` appear as two interfaces but one component row; `NetworkManager`, `GuestExec`, and `HttpProbe` appear only in Interfaces. `VmDriver` (486-488) and `BrokerClient` (489-491) overlap on seven operations with different creation granularity and different names (`host_evidence` vs `read_host_evidence`, `destroy` vs `destroy_vm`), and the spec never states whether one wraps the other or which the runner calls, although G12 (36) requires both a fake driver and a fake broker.
* **Rationale & Recommendation**: The Components table is the architecture's inventory and the 5,500-line budget (65) cannot be allocated without owners; duplicated abstractions let the two fakes diverge from the real broker, weakening the broker-contract test (88). Add the missing components, map each interface to an owner, and define `VmDriver` as the runner-facing port with `BrokerClient` as its only adapter (or delete one).

### Mandatory Risks and Mitigations area is missing, and headline residual risks have no mitigation or owner - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 40-57, 90-99, 470-481, 504-509, 573-579`
* **Discrepancy Description**: The standard requires the specification to state its constraints and identify failure modes, security implications, scalability limits, and mitigations. Content exists but is scattered across a threat-model bullet list (470-481), a "what each target proves" list (504-509), and Non-Goals (40-57); there is no risk register, no severity, and no owner. The principal residual risk - an LLM validator that can be fooled - appears only as "accepts the false-positive risk" (48) and "The LLM can still be fooled" (528), with no mitigation beyond the nonce clamp; Dirty Frag's guest-attestation risk (508) has no mitigation or named acceptor. KVM/QEMU/virtio isolation, nftables rule persistence, disk/retention exhaustion, DeepSeek data egress, and broker blast radius have no residual-risk statement; scalability limits appear only as Non-Goals.
* **Rationale & Recommendation**: A fresh reviewer cannot locate the risk set, and two accepted risks lack any mitigation or owner, which fails the standard's Risks and Limits requirement. Add an H2 "Risks and Mitigations" with one row per risk (risk, impact, likelihood, mitigation, residual, owner), reference it from Goals and Non-Goals, and tie high risks to Phase 0 gates.

### Alternatives section labels the chosen design as rejected and relies on preference - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 511-571`
* **Discrepancy Description**: Sections 1-9 are titled with the design that was chosen ("Runner-owned sequence instead of an agent-owned tool trajectory," "Target VM plus attacker VM," "Independent LLM validator," and so on), and each then gives a "Reason for Rejection" that rejects the other options. Section 10 alone is titled with a rejected option ("Docker as the remote-PoC boundary"). A reader scanning headings reads nine chosen designs as rejected alternatives. Two rejections (3 and 6, lines 529, 547) rest on "the owner chose" or "the owner asked" without a documented cost, complexity, or schedule trade-off, and at least one uses an unsupported absolute ("the only path"). No alternative is considered for guest exec transport, PoC retrieval, or the artifact mirror.
* **Rationale & Recommendation**: The standard requires rejected options with documented reasons, and the current form makes the decision record ambiguous. Make each H3 a rejected alternative with Pros, Cons, and Reason for Rejection; move the chosen path and stakeholder preference into a stated decision line with the engineering reason alongside it; label owner constraints as such; add the missing architecture alternatives or explain why they are not viable.

### A failed Phase 0 gate has no stated consequence, and preflight has no freshness rule - Severity: Major

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 38, 59-61, 80-99, 248, 463`
* **Discrepancy Description**: The Open Questions can fail (host capacity, the GitLab package, the Dirty Frag kernel, the host-evidence tamper analysis), and G14 states V1 is all three targets with a binding budget, but no section says whether a failed gate drops a target, forces a scope cut, or fails V1. The Open Questions section is placed after the binding budget it can invalidate. Preflight is a user-triggered call (463) used as a `queued` guard (248) with no freshness rule, so stale preflight can admit a job the host cannot run.
* **Rationale & Recommendation**: Binding acceptance gates cannot coexist with unresolved feasibility questions and no contingency. Add a per-gate consequence rule and decision owner, and state when preflight is re-evaluated.

### Source-shape detection and PoC admission/retrieval are undefined, and the PoC rule contradicts a Non-Goal - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 26, 43-44, 137, 281, 320, 450-466, 475, 494`
* **Discrepancy Description**: No section enumerates supported CVE-source shapes (NVD, vendor advisory, GitHub advisory) or PoC link shapes, or how detection maps a link to a pack, although "detects the source shape" and "rejects unsupported sources" are the first pipeline guarantees (G2). A Non-Goal permits "an alternate that matches the same invocation contract" (44), while `unsupported_poc` rejects any PoC that "does not match the pack pin" (281). Packs describe `repository`, `commit`, `files`, and `sha256`, but `Fetcher.fetch(url)` takes one URL (494) and the host stores the PoC as "opaque bytes"; no git/archive resolution, commit verification, source-shape detection, or post-extraction file-hash check is defined (320, 475).
* **Rationale & Recommendation**: The first pipeline stage and the "reject before spending a VM" guarantee (G2, CUJ 6) are unimplementable as written, and PoC identity is ambiguous for acceptance. Enumerate source shapes and the PoC match rule in one place and carry the rule in the pack schema; define supported archive URL forms; verify commit and per-file hashes after attacker extraction; add PoC retrieval to the Phase 0 gates.

### Binding budget is not fully quantified or enforceable - Severity: Major

* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 35, 59-88, 316, 326, 576-578`
* **Discrepancy Description**: G11 promises per-target time, memory, disk, token, and VM-cycle caps. The budget gives time and memory per target but no per-target disk figure (only "100 GB total; per-job cap in the pack," with `resources.disk_gb` left valueless), no definition or value for "VM-cycle," no per-call token value ("per-call cap enforced," 75), and no per-phase timeout values although the pack declares `timeouts` (326). "Dirty Frag 3 GB (2 + host evidence)" (72) does not sum and differs from line 576. The Effort row references Phases 0-4 (78) while only Phase 0 is defined in scope (90); tests appear as a line ceiling (67) with no allocation against the eight test categories G12 requires; the 100 GB ceiling coexists with retained failed jobs and an undefined pruning policy; the schema has no per-job disk-cap field.
* **Rationale & Recommendation**: A binding budget that cannot be checked at runtime is not a control, and the preflight admission refusal (93) needs the missing numbers. Add per-target disk, per-phase timeout, and per-call token values; define VM-cycle; fix the arithmetic; define phase scope and exit criteria or remove the effort row; allocate the line/module/dependency/token budget by component; define counting, retention, and pruning numbers.

### Check links and Start are not bound, so the reviewed plan can differ from what runs - Severity: Major

* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 26, 34, 106, 248, 396-403, 452-454`
* **Discrepancy Description**: `POST /api/links/check` returns `check_id` and `bundle_sha256`, and `POST /api/jobs` accepts `check_id?` optionally (453). Neither `check_id` nor `bundle_sha256` appears in the `jobs` schema, the state machine, or the plan rules. It is unstated whether Start reuses the checked bundle or re-fetches, whether `check_id` is single-use or has a TTL, and how a re-fetch is compared against what the user reviewed; the `queued` guard (248) does not mention the check at all.
* **Rationale & Recommendation**: G10 promises that the user reviews the plan before Start, and an unbound check lets the fetched content change between review and execution. Persist the checked bundle hash on the job, require an unexpired `check_id` for jobs, define single-use/TTL semantics and the re-fetch comparison, and fail the job with a reason code if the bundle differs.

### Pack schema permits violation of runner safety invariants - Severity: Major

* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 308-330, 316, 324, 358`
* **Discrepancy Description**: `destroy_policy.mandatory_before_validate` is pack-configurable although destroy-before-validation is a runner invariant; `failure_code` can inject codes outside the closed set; and `script_source: generated` remains legal for V1 packs despite G5.
* **Rationale & Recommendation**: A malformed or malicious pack could skip teardown before validation or select an unreviewed script, defeating the central honesty and safety claims. Remove the configurable destroy flag and the failure-code field from packs, enforce `script_source == checked_in` in the V1 registry, and validate packs against a JSON Schema with required fields and enums.

### "Documented rollback" is not documented - Severity: Major

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 37, 579`
* **Discrepancy Description**: Forward-only migrations are combined with a "documented rollback," while a newer schema refuses to start and an upgrade interrupts in-flight jobs; no rollback procedure or version-compatibility rule appears in scope.
* **Rationale & Recommendation**: Forward-only migrations cannot be rolled back in place, so the claim is either backup restoration or undefined. State the exact rollback steps (backup restoration, if that is the intent) and the supported version window, or drop the claim.

### Job-slot allocation is undefined - Severity: Major

* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 32, 71, 208`
* **Discrepancy Description**: The network block uses `10.<job-slot>.0.0/24` with static leases, but no slot range, allocator, persistence, or reuse rule is given. With concurrency fixed at one (32, 71), the value is effectively a constant, yet the rule still governs orphan cleanup and collision after restart.
* **Rationale & Recommendation**: State the allocation and recovery rule, or fix the subnet to a constant and delete the slot notation; either way, define collision handling against the host LAN.

## Nit Findings

### Title overstates the topology - Severity: Nit

* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** `Line 1`
* **Discrepancy Description**: "Two-VM CVE Reproduction" describes only remote targets; Dirty Frag uses one target VM with no attacker (9, 71, 336).
* **Rationale & Recommendation**: Retitle as one-or-two-VM, or "Target and Attacker VM."

### "Bundle" names two different artifacts - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 26, 242, 462`
* **Discrepancy Description**: The fetched evidence bundle (26) and the downloadable audit bundle (242, 462) share a term.
* **Rationale & Recommendation**: Use "evidence bundle" and "audit bundle" consistently.

### DDL does not encode the closed sets or index its foreign keys - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 396-446`
* **Discrepancy Description**: State, verdict, authority, reason code, `target_id`, and `vms.role` are plain `TEXT` with no CHECK constraints, so rebuild validation has nothing to validate against; `job_id` and `attempt_id` have no indexes and `PRAGMA foreign_keys` is unstated.
* **Rationale & Recommendation**: Add CHECK constraints or lookup tables for the closed enums, index the foreign keys, and state the foreign-key enforcement pragma.

### Token coverage and binding mode are stated inconsistently - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 25, 42, 453, 468`
* **Discrepancy Description**: The API shows the request-integrity token only on `POST /api/jobs`, while G1 requires it on every mutation; the bind is "127.0.0.1 by default" although LAN exposure is a Non-Goal; and token delivery is left as "an HttpOnly, SameSite cookie or a per-page endpoint," an unresolved choice for a security control.
* **Rationale & Recommendation**: State the token requirement for every mutating route, make the loopback bind mandatory, and choose one token-delivery mechanism.

### Identifier and polling interface inconsistencies - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 458, 460, 495`
* **Discrepancy Description**: Evidence is fetched by `artifact_id` while `EvidenceStore.get(hash)` is hash-keyed, with no stated relation, and `GET /api/jobs/{id}/events?since=` is shown as the same path with a query string rather than a defined parameter set.
* **Rationale & Recommendation**: State the artifact-id-to-hash relation and define the events endpoint parameters and response semantics.

### Additional Resources are not resolvable - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 583-586`
* **Discrepancy Description**: `concepts_brief.md` and `consolidated_review_report.md` have no paths, "the five stage reports" are unnamed, and the three CVEs have no advisory links although G2 is link-driven.
* **Rationale & Recommendation**: Give repository-relative paths for the briefs and reports and advisory URLs for the CVEs.

### G10 promises a plan that cannot exist for Dirty Frag - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 34, 468`
* **Discrepancy Description**: "The pre-run plan shows both VM profiles" is false for the one-VM target.
* **Rationale & Recommendation**: Make the plan show the profiles that exist for the selected pack.

### Actor terminology drifts - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 11, 27, 82, 176, 355, 362`
* **Discrepancy Description**: "The model," "the agent," "the LLM," "the generator," and "the session" are used for different actors, and acceptance says "the null actor must fail" where the defined condition is "no nonce observed."
* **Rationale & Recommendation**: Define one term per actor and use it consistently.

### Version casing is inconsistent - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 17, 48, 529`
* **Discrepancy Description**: "v2" is lowercase while "V1" and "V1.1" are uppercase, and the version scheme is never explained.
* **Rationale & Recommendation**: Use one casing and define the version scheme once.

### Line length makes review and diffing impractical - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 26-38, 468`
* **Discrepancy Description**: Most Goals and Non-Goals bullets are single unbroken lines of 300 to 600 characters.
* **Rationale & Recommendation**: Wrap at a fixed width.

### Retention and bundle reconstruction conflict - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 33, 53, 578`
* **Discrepancy Description**: G9 promises a downloadable bundle that "reconstructs the job" while overlays and archives are "pruned by policy" with no window, and indefinite retention is a Non-Goal.
* **Rationale & Recommendation**: State the retention window and whether pruning breaks reconstruction, or qualify the reconstruction promise.

### Probe types are under-specified - Severity: Nit

* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Line 350`
* **Discrepancy Description**: `ProbeContext` and `ProbeEvidence` have no field types or required/optional markers, and `ProbeEvidence` carries no job, target, or attempt key, so evidence references cannot be resolved to a probe without an external join.
* **Rationale & Recommendation**: Give both types field-level definitions and add the job/target/attempt keys.

### Prompt-injection gate has no detection oracle - Severity: Nit

* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 86, 297, 301`
* **Discrepancy Description**: The gate requires every hostile fixture to produce a failed job, but no rule maps detected injection to `policy_blocked`, and the validator is explicitly told to treat the narrative as data with no tools. A hostile transcript can therefore be ignored while the job still observes the nonce.
* **Rationale & Recommendation**: Define the detection/policy rule and expected reason code per fixture, or narrow the gate to "no host effect and no fabricated evidence."

### Attacker build dependencies are unpinned despite no egress - Severity: Nit

* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 216, 316, 334-335`
* **Discrepancy Description**: The attacker receives only the PoC archive and a "toolchain"; a Go-module or Python build that needs downloads will fail offline, and no vendored dependency cache or builder-image hash is required.
* **Rationale & Recommendation**: Require vendored dependencies or a hash-pinned builder image, and add build-dependency hashes to the pack.

### Subjective and personified framing - Severity: Nit

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 19, 21, 34, 61`
* **Discrepancy Description**: "The verdict is honest about its authority," "Honest UI," "the design does not silently grow," and the rhetorical "The hard problem is not whether an agent can write a setup script" are evaluative rather than descriptive.
* **Rationale & Recommendation**: Replace with measurable statements: authority is recorded as `llm_assessed`; budget changes require explicit owner approval.

### No-container rule is repeated - Severity: Nit

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 13, 28, 31, 46, 481, 523, 570`
* **Discrepancy Description**: The same constraint appears in the Overview, G4, G7, Non-Goals, Security, two Alternatives, and NFRs.
* **Rationale & Recommendation**: Keep one normative statement and cross-reference it.

## Verdict

The specification does not pass review as written: **4 Blockers, 20 Majors, 16 Nits**. Structural formatting is clean (heading levels, fences, and tables conform), and the problem, goals, architecture, and alternatives are substantively covered. The failures concentrate in the revision-2 additions: the broker verb contract, the runner state table, the typed target packs, the setup authoring/repair contradiction, the SQLite schema, and the budget. The Blockers must be resolved before approval for implementation.
