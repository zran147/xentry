# Critic Review Report — Stage 7

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (`Lines 1-519`, FeatureRange only)
**Excluded:** Detailed Implementation Plan (`Lines 520-712`), reserved for Stage 9.
**Consolidation:** 83 raw findings (6 Blocker, 38 Major, 39 Nit) were normalized and deduplicated to 46 findings (5 Blocker, 19 Major, 22 Nit).

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-design` | completed |
| `egm-structural` | completed |
| `egm-style` | completed |

## Prioritized Findings (Blockers -> Major -> Nits)

### Generated vs. prebuilt flow contradiction leaves the autonomous path untested on any real target - Severity: Blocker
* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 13, 29, 38, 43, 55, 164, 207, 226, 292, 394` (Overview, G5, G14, Non-Goals, Target packs, Alternative 5)
* **Discrepancy Description**: All three real targets use `provisioning: prebuilt` with setup scripts that are hand-reviewed once and hash-pinned (29, 207), and Non-Goal 43 rejects any other CVE before provisioning. The `generated` provisioning mode therefore cannot run for a supported target; only an undefined "dummy fourth pack" exercises it. Yet 29 calls `generated` "the normal flow," 38 (G14) says the pipeline is fully autonomous after the first three, and 207/394 repeat the claim. The specification never says whether a repeat job for PHP2Shell, GitLab, or Dirty Frag executes the checked-in script or a generated one. If checked in, the headline autonomous flow is never exercised end to end on a real target; if generated, the hash pin and one-time malicious-content review no longer describe what executed. Setup repair (164) also applies to prebuilt packs, producing an unreviewed root-privileged script while the pack still advertises a reviewed hash. Line 226 compounds this by saying the validator receives "the generated setup script" even for prebuilt packs. The value name `prebuilt` additionally collides with "prebuilt base image" (207, 442).
* **Rationale & Recommendation**: This is the product's central operating mode and it is undefined. Split the pack contract explicitly: `script_source: checked_in | generated`. For `checked_in`, execute byte-for-byte, record the executed hash in the validation row, and disable LLM repair or surface any repair as an unreviewed new hash. For `generated`, document authoring and bounded repair. Define what the dummy pack proves: a synthetic target exercises the mechanical pipeline but cannot yield a meaningful `reproduced` verdict. If V1 has no fourth real CVE, say plainly that G14 is demonstrated only on the dummy and that all three acceptance targets use the reviewed path. Do not leave the reader to infer the opposite.

### Dirty Frag evidence is guest-kernel-attested, defeating the stated VM trust boundary - Severity: Blocker
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 19-21, 113, 213, 219-226, 246, 341, 357-362` (The Problem, System shape, Verification path, Threat model, What each target proves)
* **Discrepancy Description**: The document's causal claim is that the VM is the trust boundary (113), with the nonce and null actor as the controls that establish causality (219-224). Dirty Frag is a guest-kernel local privilege escalation (213, 246). Once the exploit succeeds, the guest kernel is hostile, and every evidence channel used for that target is produced by that kernel: the SSH transcript, stdout/stderr, exit codes, `uname -r`, and the PTY root shell. The nonce proves that a root-only file was read somewhere inside the guest, not that the PoC's read occurred in the sequence the runner observed. A compromised kernel can forge the transcript, alter `uname -r`, or have its root shell read the nonce. The null actor cannot detect this because the compromise exists only in the real run. "What does not prove" (361) lists persistence, other kernels, and reliability, but omits that the evidence itself is guest-attested after a kernel compromise.
* **Rationale & Recommendation**: Collect the decisive Dirty Frag evidence out of band (host-side serial console or QMP state, virtio-serial with host-side arbitration, or a second VM) and state what the validator may conclude when the guest kernel is untrusted. Alternatively, state explicitly that Dirty Frag's verdict is "root observed in a guest-attested transcript" and cannot be `reproduced` without an out-of-band channel. Add this limit to both `what_proves` and `what_does_not_prove`, and revisit Open Question 62, whose framing (actor and target sharing a kernel) understates the risk.

### No testable definition of done, quantified budgets, or validator quality gate - Severity: Blocker
* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 23-38` (G11, G12, G14), `53, 61-67, 248, 283, 498-504` (Non-Goals, Open Questions, Verification path, NFRs)
* **Discrepancy Description**: G11 promises that per-target time, memory, disk, and token caps are enforced (35), and the non-goal rejects "a disk budget beyond the stated ceiling" (53), but no ceiling, token cap, memory value, disk value, retention period, or timeout appears anywhere in the FeatureRange. "Capped at roughly 20k tokens" (283) is prose, not an enforced cap, and the NFRs repeat "per-job token caps" and "the disk ceiling" without numbers (501-503). G1-G14 are properties, not pass/fail criteria: there is no validator accuracy threshold, no PHP2Shell or GitLab reproducibility requirement, and no per-job cost estimate. The only quantitative acceptance notion is Dirty Frag's "two consecutive clean runs" (65), which is undefined and buried inside an Open Question. The regression fixtures (248) are not required to classify correctly, and `llm_assessed` is never given an acceptance bar.
* **Rationale & Recommendation**: Add a "V1 acceptance" section with numbers: N/N consecutive `reproduced` verdicts per target, null actor always fails, fixture-classification threshold for the validator, kill-and-restart pass criterion, per-job token cap, per-VM disk cap, host free-disk stop threshold, retention days, and per-phase timeouts. Define "clean run." Add a per-job token/cost estimate even though currency display is a non-goal (57). Record fixture results per validator prompt hash and state that a prompt-hash or model change invalidates the gate. Enumerate the closed reason codes referenced by G11 and the validator schema (see the vocabulary finding below).

### Job lifecycle, verdict, authority, and storage projection are mutually inconsistent - Severity: Blocker
* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 30, 75, 147-167` (diagram 151-156), `222, 240, 267, 304-313` (G6, CUJs 1/3/4, state machine, Storage and audit)
* **Discrepancy Description**: G6 says "the job status is a projection of the validation row" (30), but that is false for link rejection, fetch failure, null-actor failure before the validator (222), cancellation, interruption, and validator provider failure. The schema stores `state`, `result`, and `reason_code` on `jobs` and `verdict`, `reason_code`, `validator_kind`, and related fields on `validations`, with no precedence and no explicit authority column; `jobs.result` is undefined and may be the merged status field that Alternative 19 (474-478) explicitly rejects. The state diagram reads `validating -> completed | failed | cancelled | interrupted -> destroying -> done`, which presents outcome states as predecessors of destruction and `done` as terminal for every outcome, while G3 (27), the system diagram (129), and CUJ 1 (75) put destroy before completion, and CUJ 3 (87) and CUJ 4 (93) mark the job `cancelled`/`interrupted` before cleanup. `security_cleanup_failed` (267) is neither a state in the graph nor a defined reason code. `not_run` (158) has no defined storage because no validation row exists when no validator ran. Line 160 says the validator is invoked "unconditionally after the PoC," contradicting 222 and the cancellation/infrastructure paths. CUJ 1's "a completed job always has a validation row" is false for these paths. G8's "database-enforced single worker and single VM slot" (32) has no claim, lease, or slot table or columns in the schema block.
* **Rationale & Recommendation**: Replace the inline chain with a state table (state, entry condition, exit, terminal, cleanup behavior), separating lifecycle state, verdict, verdict authority, and cleanup outcome. Define terminal-state semantics, validator invocation conditions (not cancelled, not interrupted, not null-actor-failed, PoC phase reached), and the validator-provider-failure state. Add a data-contract row per outcome (completed with each verdict, null-actor failure, cancelled, interrupted, validator error) stating the authoritative row, projected job fields, and where `not_run` is stored. Add `validations.authority` or document `validator_kind` as the authority enum; define or remove `jobs.result`; add the worker/VM-slot claim schema or describe the transaction that enforces it. Align CUJ 1, CUJ 3, and CUJ 4 wording with the chosen model.

### Nonce isolation is self-contradictory and the null-actor control is undefined - Severity: Blocker
* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 21, 30, 211-213, 219-226, 244-248, 261, 292, 311, 394` (Overview, G6, Target packs, Verification path, VM lifecycle, Model integration)
* **Discrepancy Description**: Line 220 requires the nonce to be placed "where the actor has no direct read access," but 211 says the runner writes a nonce file "readable by the web user," and 244 says the RCE reads it into the web root. For GitLab, 212 says the nonce is owned by the GitLab service user while 245 says the actor is not the GitLab service user; "actor" is never defined, so the intended separation cannot be evaluated. The null actor, which is the only control for the generated flow (394), is never defined operationally: it is unclear whether it runs no payload, a no-op payload, a different user, or the target without the exploit. The criterion for "passes" is unstated and no failure reason code is given. The sequence `nonce -> null actor -> probe -> restore` (261) tests only an unexploited actor plus the probe, not the setup script. Worse, the setup author receives the target pack (292), which contains the probe and nonce placement (29, 202-204), so a generated root-privileged setup script knows the exact path and read mechanism; a script conditioned on the PoC's process signature or on a marker the PoC sets can pass the null run and manufacture the real evidence. For PHP2Shell, the probe also depends on an unstated writable served document-root invariant: stock `/var/www/html` is typically root-owned, and if the actor can write the served path, the null actor can plant the nonce without an exploit. `null_actor_passed` lives in `validations` (311), yet a null-actor leak fails the job before the validator, so that row is absent.
* **Rationale & Recommendation**: Define "actor" on first use as the non-root account that runs the PoC, distinct from the service account the vulnerability compromises. Define the null actor per target in the pack: same wrapper and invocation contract with the exploit parameter removed or invalidated, exercising the exact probe read path, with the transcript recorded; state what it cannot catch. State the nonce path's ownership and mode, including the served writable path for PHP2Shell, and add an actor-write-denied precondition. Choose or randomize nonce placement inside the runner at run time and keep it out of model context. Add a deterministic check that the executed setup script and wrapper do not reference the nonce path, the probe endpoint, or runner credentials. Move or remove `null_actor_passed` consistently with whichever record can exist.

### Missing consolidated Risks & Mitigations section - Severity: Major
* **Reviewer Lens:** `egm-structural` (with supporting design observations)
* **Affected Scope:** `Lines 334-342 (Security and threat model), 344-355 (Deferred decisions), 357-362 (What each target proves), 59-67 (Open Questions), 498-504 (NFRs)`
* **Discrepancy Description**: The standard's Risks & Limits requirement is not met as a consolidated section. The document contains pieces of all five required areas but never forms a risk register: security sits as an H3 subordinate to Technical Plan, reliability and retention sit in the NFRs, uncertainties sit in Open Questions and Deferred decisions, and claim limits sit in a third H3. There is no risk -> impact -> mitigation -> residual/acceptance mapping, and "recorded risk acceptance" (28) and "records the risk" (339) name no record location or format. Several security implications are not addressed at all: the evidence bundle (PoC, setup script, transcript, nonce) is sent to DeepSeek (226, 283, 294), but the privacy NFR (500) covers only local controls and secrets in logs; there is no output-encoding or CSP control for agent- or PoC-derived text rendered in Job Detail (175, 193) while the request-integrity token is injected into the same-origin page (191); image/package provenance and WSL2 host dependence appear only as operational checks or open questions (64, 259, 269, 336). `egm-style` judged the risk material substantively present; `egm-structural` correctly notes that no dedicated section or register exists and that the mapping is incomplete.
* **Rationale & Recommendation**: Add an H2 "Risks & Mitigations" (after Architecture or Alternatives) with a table: risk ID, category (security/failure/scalability/supply chain/cost), trigger, impact, mitigation, residual risk, owner/status. Migrate or summarize the threat model, NFR risk material, and claim limits into it. Explicitly accept LLM false positives, third-party evidence egress, correlated validator failure, and provider dependency; add output-encoding/XSS and token-exfiltration controls; state where risk acceptances are recorded.

### Decision state is duplicated and partly contradictory across five sections - Severity: Major
* **Reviewer Lens:** `egm-structural` (with supporting design observations)
* **Affected Scope:** `Lines 59-67 (Open Questions), 344-355 (Deferred decisions)`; repeated at `28-38, 252, 296, 302, 408-412, 432-436, 456-460, 504, 515`
* **Discrepancy Description**: Six of the seven Open Questions have a near-duplicate in Deferred decisions (61/346, 62/347, 63/348, 64/350, 65/351, 66/353). Some deferred entries reopen decisions the document elsewhere presents as settled: 352 ("SQLite versus a manifest plus JSONL only") contradicts G9 (33) and Alternative 10 (424); 355 ("Deployment unit") contradicts G13 (37) and NFR 504; 349 ("LAN policy for a second user") is already specified in G1 (25) and CUJ 5 (95-99); 354 conflates "Web framework" (genuinely open) with "live-log transport," which G8 (32) and the API section (184) settle as SSE plus polling. The same conditional decisions are restated three to six times with drifting detail: system libvirt at 28, 61, 252, 339, 346, 408-412; second attacker VM at 31, 62, 376, 347, 515; worker split at 32, 63, 432-436, 348; ADK at 296, 66, 456-460, 353; SQLite at 33, 302, 420-424, 352. The two decision lists sit at different hierarchy levels and positions (H2 before the CUJs vs. H3 inside Technical Plan), so unresolved items appear before the architecture that explains them. Neither list has IDs, owners, or resolution gates.
* **Rationale & Recommendation**: Add a single Decision Register table (ID, decision, status Settled/Open/Deferred, current default, owner, gate/date, rationale link). Mark conditional revisits explicitly, delete duplicate prose or replace it with register references, and place the register after the architecture. Keep Open Questions and Deferred decisions only as filtered views of the register. Resolve the entries listed above as settled or genuinely open.

### Pipeline phase model is incomplete and cancellation is unbounded - Severity: Major
* **Reviewer Lens:** `egm-structural`, `egm-style`, `egm-design`
* **Affected Scope:** `Lines 27, 32, 74-75, 87, 111, 147-167, 484, 501-502` (G3, G8, CUJs 1/3, System shape, Runner state machine, pre-run plan, NFRs)
* **Discrepancy Description**: `planning` is the only state in the runner diagram with no definition anywhere in FeatureRange. It sits between `extracting` and `creating`; the model has exactly two calls, extraction and setup authoring (289-292), and repair is a retry behavior (164), so `planning` presumably hosts authoring/repair, but the document never says so. G3's canonical sequence (27) and the VM lifecycle (258-263) omit the authoring step entirely. The name also collides with the UI "pre-run plan" (34, 74, 484), which is computed before Start and is not a job state. The diagram collapses freeze, nonce injection, null actor, and real actor into `ready`/`running_poc` with no phase-to-state mapping. Separately, "the runner stops at the next phase boundary" (87) uses a term defined nowhere; the unit is called a state in the state machine, a stage in the UI (75), and a phase in the NFR (502). Provisioning is a single phase and GitLab provisioning is expected to take 20-40 minutes (501), so Cancel during provisioning can be unresponsive for the whole phase; inside `running_poc`, the PoC may block until its timeout. There is no in-flight command cancellation, per-phase cancellation checkpoint, or `cancelling` UI state.
* **Rationale & Recommendation**: Define `planning` as setup authoring/repair (inputs: typed facts, target pack, classified log; outputs: setup script and wrapper), add it to G3 and the lifecycle, or rename it `authoring`. Add a phase-to-state mapping table that includes freeze/nonce/null actor and distinguish the pre-run plan from the job state by name. Define cancellation as an interrupt of the current in-flight exec (kill the guest process, then tear down the domain) with a bounded grace period, add a `cancelling` state, and keep the phase-boundary rule only for phases that cannot be interrupted, naming them.

### Attempt and retry model is overloaded and not represented in storage - Severity: Major
* **Reviewer Lens:** `egm-design`, `egm-style`
* **Affected Scope:** `Lines 32-33, 93, 162-167, 306, 309, 316` (G8/G9, CUJ 4, Retry rules, Storage and audit)
* **Discrepancy Description**: "Attempt directory" means the per-job storage directory (33, 316); "one bounded repair per attempt" (164) means a per-run allowance; and "every retry gets a fresh attempt directory" (167) means retries produce new directories. `jobs.attempt_dir` is singular (306) while retries claim multiple, and `validations` links only to `job_id` (309). `tool_calls` and `artifacts` have no attempt key. The schema cannot say which attempt produced the verdict or which directory is authoritative, and line 167 does not say where "the previous failure" is recorded. With one setup repair plus one PoC rerun allowed per attempt, a job can have several attempts that the schema cannot distinguish.
* **Rationale & Recommendation**: Define job, attempt, retry, and repair as four distinct terms with a one-line relationship statement. Add an `attempts` table (job_id, attempt_no, attempt_dir, start/end, failure code, previous attempt) and scope `tool_calls`, `artifacts`, and `validations` to `attempt_id`. State that the job verdict comes from the final attempt. Alternatively, drop the fresh-directory-per-retry rule and make each retry a new job.

### Target pack manifest cannot express the contract the specification requires - Severity: Major
* **Reviewer Lens:** `egm-design`, `egm-style`, `egm-structural`
* **Affected Scope:** `Lines 29, 197-207, 216-218, 244-246, 285, 357-362` (G5, Target packs, Verification path, Per-target probes, What each target proves)
* **Discrepancy Description**: The manifest (200-204) has no field for the checked-in setup script path or hash, no SHA-256 for the PoC artifact (285 says "commit and hash"), no null-actor definition, and no typed probe that can express the three different interactions: host HTTP GET (PHP2Shell), response parsing (GitLab), and host-driven PTY root shell (Dirty Frag). The block `probe {nonce_placement, command_or_http_request, expected_evidence}` cannot encode the Dirty Frag PTY flow or the runner-performs-its-own-GET semantics. G5 promises "setup inputs, pinned PoC artifact, fixed validator probe, expected evidence," but `setup_inputs` has no schema and is absent from the manifest, and expected evidence is nested under `probe`. The "PoC wrapper" (9, 125, 202, 292, 448) is never defined and its relationship to the manifest's `invocation_template` (202) is unstated: it is unclear whether the wrapper is generated or pack-fixed, or which is authoritative. `what_proves` / `what_does_not_prove` have no type or consumer defined, while 357-362 restate the same content in prose for all three targets; whether the prose is normative or derived from the manifest is unstated. There is also no pack-level retry or destroy policy, so the runner hard-codes Dirty Frag behavior (166-167, 267).
* **Rationale & Recommendation**: Expand the manifest with `setup_script` plus `setup_sha256`, `poc_artifact_sha256`, a typed probe block per kind (`http_get`, `response_parse`, `pty_session`) with explicit nonce-placement preconditions and a null-actor spec, and pack-level `retry_policy` and `destroy_policy` so the runner does not hard-code targets. Add a pack schema version. Define the wrapper's responsibilities and its relationship to `invocation_template`. Define the `what_proves` fields or remove the prose duplication.

### LLM verdict is not anchored to the runner's deterministic observation - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 222-240, 244-248, 296, 496` (Verification path, Per-target probes, Regression fixtures, Model integration, Alternative 22)
* **Discrepancy Description**: The runner itself performs the HTTP GET, parses the leaked response, or drives the shell (244-246), so it knows deterministically whether the nonce appeared. Yet the pass condition is delegated to the LLM, and nothing forbids `reproduced` when the runner saw no nonce. `evidence_refs` are free-form ("transcript line or artifact hash," 234) and the runner is not required to resolve or verify them. The validator input mixes runner-attested facts (nonce, null actor, version checks) with untrusted narrative (PoC source, generated setup script, transcript) in one bundle (226), with no instruction that only runner facts are authoritative. Prompt injection through the PoC is assumed to succeed at the text level (298), and the validator reads the PoC.
* **Rationale & Recommendation**: Add a deterministic pre-check: the runner's own probe observing the nonce is a hard precondition for `reproduced`; absent it, clamp the verdict to `not_reproduced` or `inconclusive` regardless of the LLM. Have the runner resolve every `evidence_ref` against the transcript and artifact hashes and reject or strip unresolved refs. Structure the validator bundle into machine-readable "runner facts" and "untrusted narrative," and instruct the prompt that only runner facts may support `reproduced`. Store the deterministic observation and the LLM verdict separately.

### libvirt privilege and egress model is unresolved and deferred to an undefined Phase 0 - Severity: Major
* **Reviewer Lens:** `egm-design`, `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 28, 61, 252, 265, 339, 346, 408-412` (G4, Open Questions, VM harness, Threat model, Deferred decisions, Alternative 8)
* **Discrepancy Description**: The default is `qemu:///session` explicitly to avoid root (252, 408-412), but per-VM nftables requires host root, and a host-side allowlist proxy still requires forcing the guest through it, which the app does not control under slirp user-mode networking. Line 265 defers the choice to "the Phase 0 spike," but the answer determines whether the project must adopt the root-owned broker, which changes the threat model: a root-owned broker plus guest root is materially different from rootless session QEMU. "An egress test fails closed" is asserted without a mechanism or a definition of "fails closed." The system-libvirt fallback controls appear in four forms: broker plus recorded risk acceptance (28); broker plus fixed verbs plus peer-credential checks plus app outside the libvirt group (252); risk recorded (339); broker plus dedicated user plus recorded risk acceptance (412). The canonical control set is unclear, and the broker's fixed verbs, identity, QEMU process ownership, and image/overlay path ownership are never stated. "Phase 0 spike" is used as the resolver for session-vs-system libvirt and ADK survival but is never defined as a V1 task or as a precondition with exit criteria. Alternative 8's rationale overstates "a guest root shell then becomes host file access" (411).
* **Rationale & Recommendation**: Make egress a Phase 0 decision gate with both outcomes designed. For session mode, specify the proxy plus a guest route policy with no default route other than the proxy, pinned DNS, and an explicit egress test in preflight and per-job evidence. For the broker path, state the canonical control set once (dedicated user, fixed verbs, peer-credential checks, app outside the libvirt group, recorded risk acceptance) and the risk-acceptance owner and threat-model delta. State whether Phase 0 is a V1 task and list its exit criteria. Correct the Alternative 8 rationale to the actual risk (root QEMU process plus root-owned socket, QEMU escape).

### Closed reason codes and log-classification taxonomy are undefined - Severity: Major
* **Reviewer Lens:** `egm-structural`, `egm-design`, `egm-style`
* **Affected Scope:** `Lines 35-38, 164, 233, 265, 267, 311, 346` (G11, G14, Retry rules, validator schema, VM harness, Threat model, Storage)
* **Discrepancy Description**: G11 promises "a closed reason code and a next action" for every failure (35), but no enumeration exists. Only `cancelled` (87) and `security_cleanup_failed` (267) appear, and the validator JSON uses the placeholder `"closed reason code"` (233). "Classified log" is the sole repair input (38, 164), but no classification taxonomy exists: categories, producer, and what the repair model sees are all unstated. "Phase 0" (265, 346) is also undefined in FeatureRange. Without these definitions, "closed" is unverifiable and a fresh engineer cannot implement or test the failure paths.
* **Rationale & Recommendation**: Add a closed reason-code table (code, trigger, retryability, next action, phase/target) and a log-classification taxonomy (categories, producer, what the repair model sees). Cross-reference them from G11, G14, the verification path, and the schema. Define Phase 0 in the libvirt/egress finding above.

### User-supplied PoC link may not be the artifact that runs - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 9, 26, 29, 44, 173, 285, 447, 484` (Overview, G2, Target packs, Non-Goals, Web UI, Ingestion, Alternative 14, pre-run plan)
* **Discrepancy Description**: The user submits a CVE link and a PoC link (9, 173), while the pack pins the PoC by repository and commit (29, 285, 447). Line 44 says V1 runs "the pinned PoC or an alternate that matches the same invocation contract," with no definition of the contract check, while line 26 says unsupported PoCs are rejected before a VM. An engineer cannot tell whether the user's link is used, used only to locate the repository, or rejected when it differs. The pre-run plan (484) shows target, image, kernel, resources, probe, and caps, but not "your PoC link will be replaced by the pinned artifact."
* **Rationale & Recommendation**: Decide and state that the PoC link is a locator that must resolve to the pack's pinned repository and commit; anything else is rejected at Check links with a reason code. Show the resolved commit and hash in the pre-run plan so the user sees which artifact runs. Remove the "alternate invocation contract" sentence or define the contract test precisely.

### "Pipeline does not branch on target ids" is contradicted by target-specific runner rules - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 87, 166-167, 197, 207, 267, 406` (CUJ 3, Retry rules, Target packs, Threat model, Alternative 7)
* **Discrepancy Description**: Line 197 claims the pipeline does not branch on target ids, but the retry rules hard-code "Dirty Frag: any retry gets a fresh VM" (166), the destroy rule hard-codes "Dirty Frag's destroy is a security control" (267), and CUJ 3 has a Dirty Frag-specific cleanup code (87). The generic-pack claim is central to G5 and to the dummy-pack acceptance test (207).
* **Rationale & Recommendation**: Move these behaviors into pack data (`fresh_vm_on_retry`, `destroy_priority: security_control`, `cleanup_failure_code`) and state that the runner branches only on declared pack fields. Add a test that no target-id strings exist in the runner, in addition to the "no pipeline edits" requirement for the dummy pack.

### Dirty Frag root shell provenance is unspecified - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 213, 246, 321` (Target packs, Per-target probes, Interfaces)
* **Discrepancy Description**: The runner already has root access for provisioning and readiness (113, 259-260). The Dirty Frag probe then "drives a PTY root shell" (213, 246), and nothing states that the shell must be spawned by the PoC as the non-root actor rather than by the runner's own root SSH. If the runner uses its own root channel, the root-only nonce is readable trivially and the probe is vacuous. `VmDriver.exec(user, argv, tty)` permits either interpretation.
* **Rationale & Recommendation**: Specify the transport: the non-root actor starts the PoC, the PoC spawns the shell, and the runner attaches to that PTY as the actor. Reject any shell whose session was opened by runner root credentials. Record the session owner in the transcript and add a precondition check that the actor cannot read the nonce directly.

### Host-side handling of the untrusted PoC archive is unspecified - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 113, 202, 226, 281-285` (System shape, Target packs, Verification path, Ingestion and evidence)
* **Discrepancy Description**: The host fetches and pins the PoC and "nothing is built or run on the host" (285), but `poc.files` (202) and the validator bundle's "pinned PoC" (226) imply host-side unpacking and reading of an attacker-controlled archive. Tar or zip path traversal and decompression bombs are host-level risks not in the threat model, and "the VM is the trust boundary" (113) is false for that step.
* **Rationale & Recommendation**: State the rule: the host stores and hashes the archive as opaque bytes, and extraction or file selection happens inside the guest. If host extraction is required, mandate a path-safe, size-capped extractor and log the archive hash. Add this to the threat model.

### Model- and PoC-controlled text is rendered in the token-bearing UI without escaping or CSP - Severity: Major
* **Reviewer Lens:** `egm-design`, `egm-structural`
* **Affected Scope:** `Lines 138, 175, 191, 296-298, 334-342` (Components, Web UI and API, Model integration, Security and threat model)
* **Discrepancy Description**: The request-integrity token is injected into server-rendered pages (191), and every mutation requires it. Job Detail renders logs, the agent summary (model output), and validator evidence (175). Prompt injection is assumed to succeed at the text level (298). If any of that text reaches the DOM unescaped, a PoC README or model summary can execute script in the app origin, read the token, and start or cancel jobs. The specification states no autoescaping rule, no CSP, and no requirement that logs be rendered as inert text.
* **Rationale & Recommendation**: Require autoescaping for all model, PoC, and transcript content; render logs in inert text containers; add a strict CSP. Consider an HttpOnly, SameSite cookie for the token or a per-page token endpoint so script cannot read a token embedded in the DOM. Add stored XSS to the threat model.

### Snapshot and restore semantics are undefined, so null-run artifacts can survive - Severity: Major
* **Reviewer Lens:** `egm-design`, `egm-style`
* **Affected Scope:** `Lines 166, 219-223, 256-263, 341` (Retry rules, Verification path, VM lifecycle, Threat model)
* **Discrepancy Description**: The runner freezes the provisioned state with "a VM snapshot" (220) and restores "the frozen state" (223), but never says whether the snapshot is memory-inclusive (system checkpoint) or disk-only. If disk-only, the null run's guest writes remain on the overlay and the real run inherits them, reintroducing exactly the "leftover file" failure mode named at line 19. For Dirty Frag, a disk-only restore also leaves guest page-cache and kernel state from the null run, contradicting "the page cache is contaminated; destroy is mandatory" (166, 341). "Freeze" and "snapshot" are used interchangeably, and it is unstated whether nonce placement is inside the snapshot or recreated after restore.
* **Rationale & Recommendation**: Define the snapshot type. Use a memory-inclusive system checkpoint for freeze/restore, or a fresh VM per run, and say which. For Dirty Frag, require a fresh boot or memory-inclusive restore after any prior exploit execution. Add a leftover-artifact assertion to the real-run preconditions. Standardize on "snapshot" and "restore" and define or delete "freeze."

### Destroy is deferred until after the LLM call, keeping a contaminated VM alive - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 27, 129, 262, 267` (G3, System shape, VM lifecycle, Threat model)
* **Discrepancy Description**: The order is evidence, then validate, then destroy (27, 129, 262). Dirty Frag's destroy is described as a security control (267), yet the contaminated VM stays alive while a remote DeepSeek call runs, possibly with retries and timeouts. Destroy-on-every-path is promised, but a validator outage keeps the domain running.
* **Rationale & Recommendation**: Reorder to evidence, destroy, validate. The evidence bundle is immutable and self-contained (226), so validation does not need the VM. Record the destroy result before invoking the validator.

### Run-time package downloads undermine pinning and reproducibility - Severity: Major
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 29, 64, 200-204, 213, 265, 285` (G5, Open Question 4, Target packs, VM harness)
* **Discrepancy Description**: G5 requires a pinned image and pinned versions, and line 285 says "nothing is cloned at run time," but GitLab's Omnibus `.deb` and dependencies are fetched from mirrors during the logged build window (64, 265), and Dirty Frag's kernel package may be installed at provisioning time (213). The manifest has no package-hash field, and Open Question 4 admits the `.deb` URL and hash are unknown. A job can build a different environment from the pinned one, and nothing records the artifact actually installed.
* **Rationale & Recommendation**: Pin package artifacts on the host (URL and SHA-256 in the pack), serve them to the guest from a host-local repository during the build window, and record the executed hash in the attempt directory. Fail closed on a hash mismatch. Alternatively, bake packages into the per-target base image and state that provisioning is offline.

### "Validator" names both the V1 LLM session and the deferred deterministic validator - Severity: Major
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 11, 30, 48, 143-144, 226, 240, 294, 338, 347, 378-382, 514` (Overview, G6, Non-Goals, Components, Verification path, Model integration, Security, Deferred decisions, Alternative 3, Future Improvements)
* **Discrepancy Description**: Line 294 says "The validator is a direct LiteLLM call," while lines 48 and 382 use "deterministic human-authored validators" for the deferred v2 component and line 382 additionally says "a checked-in validator." Line 240's "the full harness-owned contract replaces it later" makes the replacement share its name with the thing being replaced.
* **Rationale & Recommendation**: Reserve "validator" for the V1 LLM component. Use "deterministic validator" or "harness probe" for the deferred component, or list the `validator_kind` values explicitly and use them consistently.

### "Writes" vs. "returns" misstates the runner-writes-files trust boundary - Severity: Major
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 9, 111, 142, 289-294, 327` (Overview, System shape, Components, Model integration, Interfaces)
* **Discrepancy Description**: Line 9 says the agent "writes a setup script plus a PoC wrapper," while lines 292 and 327 say it "returns" a script and "the runner writes the files." The document's central claim is that only the runner touches the filesystem, so "writes" misstates the boundary the design is built to protect.
* **Rationale & Recommendation**: Replace "writes" at line 9 with "authors (returns text)"; keep "writes" for runner filesystem actions only.

### "No self-reported output" invariant is stated only as per-target exceptions - Severity: Major
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 17-21, 242-246, 471` (The Problem, Per-target probes, Alternative 18)
* **Discrepancy Description**: Lines 17 and 471 explain that self-reported success was the old failure, and lines 244 and 246 state the rule as per-target exceptions ("The PoC's `--fetch` output is not the pass condition"; "The PoC's printed `uid 0` is not sufficient"). The global invariant that would force consistency for new packs is never stated, which matters because G5 requires a dummy fourth pack to work without pipeline edits.
* **Rationale & Recommendation**: State the invariant once — no self-reported output is admissible evidence; only runner-authored observations count — and present the per-target lines as applications of it.

### Residual terminology drift and glossary gaps - Severity: Nit
* **Reviewer Lens:** `egm-style`, `egm-structural`
* **Affected Scope:** `Lines 9, 30, 34, 99, 171, 218-226, 283, 311, 27, 111, 142, 207, 292, 394`
* **Discrepancy Description**: Terminology is stable at section-header level but drifts at concept level. "Evidence" names four different artifacts: "raw evidence," "the immutable evidence bundle," "the evidence store," and `evidence_sha256`; the bundle also contains generated scripts and a wrapper, so it is not purely evidence. Setup authoring/repair is named six different ways ("setup authoring or repair," "generated and repairs," "writes and repairs"). "Job status" (30) and "job state" (34) are used interchangeably, as are "help page" (99) and "one help modal" (171). No vocabulary table exists.
* **Rationale & Recommendation**: Add a short reference vocabulary or glossary near the state machine defining evidence vs. evidence bundle vs. evidence store, setup author vs. repair, job state vs. status, and page vs. modal. Standardize on "setup author (initial)" and "repair (bounded, one per attempt)."

### Interface inventory is asymmetric and defers contracts to the Implementation Plan - Severity: Nit
* **Reviewer Lens:** `egm-structural`, `egm-style`
* **Affected Scope:** `Lines 27, 29, 136-145, 164, 199-205, 292, 318-332`
* **Discrepancy Description**: Line 332 explicitly defers "detailed file list and function boundaries" to the Implementation Plan, so FeatureRange does not fully stand alone for interface contracts and this is its only such forward dependency. The inventory is not one-to-one with the Components table (136-145): there is no Target pack registry interface; `GuestExec` and `HttpProbe` are not components; `VmDriver.exec` and `GuestExec.run` duplicate exec responsibility. `AgentRuntime` exposes only `extract` and `author_setup`; the repair path (27, 164, 292) has no method or classified-log parameter. G5 promises pack fields "setup inputs" and "expected evidence" (29), but the manifest block (199-205) has no `setup_inputs` field and nests expected evidence under `probe`.
* **Rationale & Recommendation**: Make FeatureRange self-contained for the interface contract, or keep the deferral but state that the FeatureRange is intentionally partial. Add a component-to-interface traceability table, add `repair_setup(facts, classified_log, pack)` or document overloading, and reconcile manifest fields with G5.

### Architecture diagram contradicts the one-process model and misplaces storage and SSE edges - Severity: Nit
* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 109-132, 139, 145, 160, 184` (System shape, Components, Runner state machine, Web UI and API)
* **Discrepancy Description**: Line 111 says "one local process with a web server, a background job runner, and a libvirt/KVM VM backend," but the diagram labels a "Web/API process" box and a separate "Job runner" box connected by a downward arrow (119-122). Storage is attached only to the Web/API line (119), although the runner writes SQLite and JSONL events (33, 145, 160). The final line `destroy VM -> projection into jobs and validations v SSE or polling -> UI` (129-131) suggests SSE originates from the runner, while the API section defines the SSE endpoint under the web API (184).
* **Rationale & Recommendation**: Draw a single process boundary containing Web/API plus runner, show both reading and writing SQLite and the attempt directory, and show the browser/UI subscribing to SSE through Web/API.

### Viable sub-alternatives are buried inside other alternatives' rejection reasons - Severity: Nit
* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 370, 376, 382, 399, 423, 453` (Alternatives 1, 2, 3, 6, 10, 14)
* **Discrepancy Description**: Each main alternative has the symmetric Pros/Cons/Reason-for-Rejection format, but several viable designs are rejected in a single clause inside another alternative's Reason for Rejection: fully deterministic pipeline (370), second attacker VM (376), full v2 oracle (382), CLI-only product (399), no-database option (423), full user accounts (453). These have no dedicated Pros, no explicit impact statement, and no independent heading, so they are harder to audit and the section's symmetry is broken.
* **Rationale & Recommendation**: Give each its own numbered subsection with Pros/Cons/Reason, or add an "Also rejected" table (option, reason, revisit trigger). At minimum, add the option's own Pros and a rationale sentence.

### Additional Resources are unresolvable and two Future Improvements terms are dangling - Severity: Nit
* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 506-510, 512-518`
* **Discrepancy Description**: The three resources are backticked strings, not links. `concepts_brief.md` has no directory; `docs/adr/0001-v1-reset.md` has a partial path; the three pinned PoC repositories and CVE records have no URLs, commit hashes, or access dates, so a fresh session cannot resolve them from this document. Future Improvements uses "a corrected key" (517) and "stored recipes" (518) with no antecedent in FeatureRange; "recipes" appears only as prior-v2 history (17, 464).
* **Rationale & Recommendation**: Use relative Markdown links from `docs/designs/` or repo-root paths, add pinned commit URLs or point to the target-pack manifests, add access/version dates, and define or remove "corrected key" and "stored recipes."

### Heading case, standard-header naming, and section ID symmetry are inconsistent - Severity: Nit
* **Reviewer Lens:** `egm-structural`
* **Affected Scope:** `Lines 7, 15, 23, 40, 59, 69, 107, 134, 169, 318, 357, 364, 498, 506, 512; 99 vs. 171`
* **Discrepancy Description**: H2s are title case and H3s are mostly sentence case, but "Components" (134) and "Interfaces" (318) are capitalized while "System shape" (109), "Web UI and API" (169), "Target packs" (195), and others are not; CUJ headings are title case. "Technical Plan (Architecture)" (107) does not use the standard's "Proposed Architecture" name and merges architecture with planning; "The Problem" (15) differs from "Problem Statement." Goals are numbered G1-G14, but Non-Goals and Open Questions are unnumbered and cannot be cross-referenced by ID.
* **Rationale & Recommendation**: Adopt one heading-case rule, rename "Technical Plan (Architecture)" to "Architecture" or add a mapping table, and assign IDs to Non-Goals and Open Questions or move them into the decision register.

### `null_actor_passed` is vestigial in the validation row - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Line 311` (Storage and audit)
* **Discrepancy Description**: Because a failing null actor stops the job before the validator (222), every validation row has `null_actor_passed = true`; the column carries no discriminating information and its failure state has no storage.
* **Rationale & Recommendation**: Move the null-actor result to the attempt record, or remove the column and store the outcome in the job/attempt failure data.

### Validator self-reports `model` and `prompt_hash` - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 235-236, 296` (validator schema, Model integration)
* **Discrepancy Description**: The runner already knows the model and prompt hash (296), so trusting model output for these fields is spoofable and adds no information.
* **Rationale & Recommendation**: Stamp `model` and `prompt_hash` from the runner and validate the rest of the validator JSON against a schema.

### "No tools" conflicts with the ADK tool-call threshold and the "tool schemas" control - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 66, 124-125, 291-292, 298` (Open Questions, Components, Model integration, Prompt-injection controls)
* **Discrepancy Description**: The extractor and setup author are described as "no tools," but Open Question 6 asks about a "tool-call threshold," and the injection controls include "tool schemas." It is unclear whether the only tool is a side-effect-free structured-output function or whether JSON mode is used; the distinction matters to the prompt-injection argument.
* **Rationale & Recommendation**: State the exact tool configuration for both calls and reconcile it with the threshold question and the injection controls.

### Orphan domain identification has no tagging rule - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 93, 254` (CUJ 4, VM harness)
* **Discrepancy Description**: The startup sweep destroys "any xentry-managed domain" without saying how a domain is identified, so the sweep could touch unrelated session domains.
* **Rationale & Recommendation**: Specify a domain metadata tag or name prefix and require the sweep to match it exactly.

### Shared token gives two users no attribution or isolation - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 25, 32, 191` (G1, G8, Web UI and API)
* **Discrepancy Description**: One token shared by two users means either can cancel the other's job, and the log cannot say who started a job.
* **Rationale & Recommendation**: State this as accepted for a trusted pair, or add a self-declared user id in the event log.

### System page "target estimates" have no source - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Line 176` (Web UI and API)
* **Discrepancy Description**: The System page shows "target estimates," but the specification does not say whether they come from pack fields, historical runs, or a static table, nor that they are estimates.
* **Rationale & Recommendation**: Define the source and label the values as estimates.

### CUJ 3 conflates the security cleanup failure code with generic teardown failure - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Line 87` (CUJ 3)
* **Discrepancy Description**: "A failed destroy is visible as `security_cleanup_failed` for Dirty Frag or a teardown failure otherwise" merges the security code and the generic teardown failure, with no names or precedence for both codes.
* **Rationale & Recommendation**: Give both codes names and state their precedence and UI treatment.

### `/dev/kvm` access and WSL2 systemd requirements are missing from preflight and ops - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 187, 252, 269, 504` (Web UI and API, VM harness, NFRs)
* **Discrepancy Description**: Session-mode KVM access requires the app user to be in the `kvm` group (G4 only says the app stays out of the `libvirt` group), and a systemd user unit on WSL2 needs lingering. Both are absent from preflight and operational checks. "Monotonic durations" (269) is also unexplained.
* **Rationale & Recommendation**: Add both checks to preflight and operational documentation, and define "monotonic durations."

### `POST /api/jobs` has no idempotency key - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Line 181` (Web UI and API)
* **Discrepancy Description**: A double submit queues a second identical job.
* **Rationale & Recommendation**: Add an idempotency key or a per-page nonce.

### PHP2Shell and Dirty Frag are asserted to be "shorter" without justification - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Line 501` (NFR Performance)
* **Discrepancy Description**: A from-source PHP 8.4 build and a kernel-package install plus reboot are not obviously shorter than GitLab's package install.
* **Rationale & Recommendation**: Measure them in Phase 0 and replace the assertion with an estimate and a per-target time cap.

### Numeric and sizing statements are approximate or inconsistent - Severity: Nit
* **Reviewer Lens:** `egm-style`, `egm-design`
* **Affected Scope:** `Lines 17, 67, 200, 281-285, 429, 465, 501` (The Problem, Open Questions, Target packs, Ingestion, Alternatives 11/17, NFRs)
* **Discrepancy Description**: "Capped at roughly 20k tokens" is an approximation where a cap is intended (283, also 465); "roughly 12,000 lines" appears twice as a quality indictment, a proxy metric with no bearing on the argument; the 256 KB per-artifact ingestion cap is not reconciled with the pinned PoC repository tarball and `poc.files` selection; `var/base-images/catalog.yaml` and the pack's `image_sha256` both claim the image hash with no authoritative source or verification order; and "tens of minutes" (429) conflicts with "20-40 minutes" (501) for the same GitLab duration.
* **Rationale & Recommendation**: Use exact integers where caps are intended and state whether they cap input, output, or both. Declare whether the PoC artifact is exempt from the 256 KB cap or has a separate cap. Name the authoritative image-hash source and verification order. Use the NFR figure everywhere. Keep the line count only as background.

### Evaluative and non-verifiable claims are presented as requirements - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 19, 21, 34, 375, 380, 399, 410-412, 423, 447, 466` (The Problem, G10, Alternatives 2/3/6/8/10/14/17)
* **Discrepancy Description**: "honest about its authority" and the goal name "Honest UI" are value judgments, not measurable requirements; "broader device support" is comparative with no baseline; "painful," "weakens the link," "harder," and "stronger" assert subjective judgments without a metric. The "ground-up" claim is not a verifiable rule: V1 reuses the old LLM client "as references only," but copying versus reading is undefined.
* **Rationale & Recommendation**: Rename G10 to its measurable content ("verdict and authority are separately displayed; no UI string claims proof") and replace evaluative verbs with the property being measured. State the concrete reuse rule (no old code imported; references may be read but not copied) or drop "ground-up."

### Unenumerated prior-art counts are noise - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 48, 384-388` (Non-Goals, Alternative 4)
* **Discrepancy Description**: "The five-tool shape" and "the five CLI bank verbs" refer to prior artifacts the document does not name; a count the reader cannot resolve is noise.
* **Rationale & Recommendation**: Name the tools and verbs or delete the counts.

### Narrative voice and scenario formatting are inconsistent - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 15-21, 69-105, 364-496` (The Problem, CUJs, Alternatives)
* **Discrepancy Description**: The body is declarative present/future ("The app binds...", "The runner owns...") while The Problem and Alternatives use past-tense narrative ("It grew to roughly 12,000 lines," "The owner chose..."). "Revisit if..." appears in eight alternatives (370, 394, 406, 436, 448, 460, 466, 472), most without an owner, date, or measurable trigger. CUJ headings are not consistently scenario-shaped: CUJ 1 is outcome-framed ("...and get a verdict"), CUJ 3 is action-framed ("Cancel a long GitLab run"), and CUJ 6's Then is a negative non-UI outcome. CUJ 1's Given asserts "the target pack exists" without stating that only the three named packs exist in V1.
* **Rationale & Recommendation**: Keep past tense only for history; state rejection reasons in the present tense; replace each "Revisit if..." with a named trigger or delete it; use one scenario-style heading form, make each Then observable in the UI, and state the supported pack set in CUJ 1.

### "No container runtime" is restated six times with drifting scope - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 13, 31, 37, 46, 342, 500` (Overview, G7, G13, Non-Goals, Security, NFRs)
* **Discrepancy Description**: The constraint appears six times, one of which scopes the ban to "execution or deployment" (13), a different claim from "in xentry or target provisioning" (31, 342). Deployment (systemd/venv) and target provisioning are separate scopes merged inconsistently.
* **Rationale & Recommendation**: Fix the exact scope once and reference it elsewhere.

### Dirty Frag kernel activation and reboot are absent from the lifecycle - Severity: Nit
* **Reviewer Lens:** `egm-design`
* **Affected Scope:** `Lines 213, 259-263, 321` (Target packs, VM lifecycle, Interfaces)
* **Discrepancy Description**: The target requires the pinned vulnerable kernel, and `reboot` exists in `VmDriver` (321), but the VM lifecycle (259-263) never includes a reboot or `uname -r` gate after a kernel change.
* **Rationale & Recommendation**: State whether the base image already boots the pinned kernel; if not, add the reboot and version gate to the lifecycle.
