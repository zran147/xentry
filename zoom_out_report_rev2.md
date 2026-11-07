# Goldfish Review Report

**Stage:** 5 - Initial Zoom Out Review (Revision 2)
**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (lines 1-743; FeatureRange 1-595, DetailedRange 596-743)
**Standard:** `/home/zran/.claude/plugins/cache/egm/egm/0.1.0/resources/document_standards/zoom-out-standard.md`
**Mode:** REVIEW

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-zoom-out` | completed |

## Verdict

The revision fixes the central same-VM causality problem for remote targets and adds real contracts (state table, DDL, interfaces, nonce precondition, checked-in scripts). It is still not a narrow reset: the binding budget is contradicted by its own plan, the checked-in provisioning contract still has a repair escape hatch, and Dirty Frag's decisive evidence is not established. The reviewer judges the design not implementation-ready.

What the reviewer judged to work: the two-VM attacker for remote PoCs; the runner-owned nonce, null actor, and destroy-before-validate ordering; the honest `llm_assessed` authority; loopback plus SSH tunnel; the host storing the PoC archive as opaque bytes with the SSRF guard connecting to the validated IP; the isolated-network and nftables direction.

## Prior Review Resolution

- **Substantially resolved:** B-05 (broker/network/egress), B-06 (acceptance numbers, budgets, reason codes), M-07 (loopback), M-14 (host archive/SSRF).
- **Partly resolved:** B-01, B-02, B-03, B-04, B-07, B-08, B-09, M-01, M-04, M-05, M-08, M-09, M-10.
- **Not resolved:** M-02 (ADK), M-03 (reuse), M-11 (snapshot), M-13 (PoC link), M-15 (risk register).

## Prioritized Findings (Blockers -> Major -> Nits)

### Binding budget is already exceeded by the plan - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `V1 Scope and Budget` (lines 59-88); `Target files to create or modify` (lines 616-718); `Phases` (lines 735-743)
* **Discrepancy Description**: The table says "at most 5,500 lines across at most 26 modules." The file table lists 30 non-package Python modules under `src/` and `broker/` (33 including package markers) plus three Python scripts under `scripts/` - that is 30-33 before tests. The "module" unit is undefined. Phase 0 is one week for eight gates (root broker, isolated network, two-VM smoke, PHP2Shell build, Dirty Frag kernel, GitLab package, ADK gate, artifact hashes). The 10-week effort has no slack or cut line. The design says the budget is binding and "does not silently grow," but the plan has already grown past it.
* **Rationale & Recommendation**: The budget is the only control on the prior B-01 scope finding; if it is not derived from the plan, it cannot constrain it. Do a bottom-up estimate per file, define "module," cut speculative surfaces (ADK author/repair and fallback, SSE/backfill, four source adapters, four screens, migrations/rebuild, dummy pack) to get under 26, or raise the cap explicitly and add a CI count gate. Split Phase 0 or add a cut line (Dirty Frag to V1.1) with a date.

### Checked-in provisioning still has a live repair path - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** G3 (line 27); G5 (line 29); budget (line 77); state table (line 251); `provision_failed` (line 287); Agent runtime (lines 382-388); `Reactive setup` (line 358); Non-Goals (line 55)
* **Discrepancy Description**: All three V1 targets are `script_source: checked_in` and the generated path is V1.1. Yet the runner's `planning` trigger is "Setup author/repair"; the budget reserves "One bounded repair per attempt"; `provision_failed` retries with "One repair"; `AgentRuntime` exposes `author_setup`/`repair_setup`; V1 includes `prompts/setup.md`, `prompts/repair.md`, `test_agent_contract.py`, and the dummy generated pack. If a checked-in script is repaired, the executed script is not the reviewed hash, but the pack still advertises the reviewed hash. This is the exact B-02 contradiction: an unreviewed root script can run while the pack claims a reviewed hash, and the null actor cannot catch a setup script that reacts to the PoC.
* **Rationale & Recommendation**: The checked-in script is the V1 trust anchor; a live repair path defeats it. For `checked_in`, execute byte-for-byte and disable repair; record the executed hash in the validation row; change `provision_failed` to no repair; move author/repair, prompts, fixtures, and the dummy pack to V1.1 (or gate them on `script_source: generated`); add a test that a checked-in pack cannot be repaired.

### Dirty Frag's decisive evidence is not established - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** G6 (line 30); Dirty Frag pack (line 336); probe contract (line 346); broker `exec` (line 189); `What each target proves` (line 508); Open Questions (line 96); acceptance (line 82)
* **Discrepancy Description**: The design says the runner "drives the PTY root shell through the broker" and reads the root-only nonce from the host-side channel. The only PTY primitive is `pty_session`, defined as "runner opens a PTY as the actor" (non-root). The design never says the root shell is the one spawned by the non-root actor/PoC, nor that the runner rejects a root shell opened by its own broker `exec`. The broker's `exec(vm_id, user, argv, tty, timeout)` accepts `user=root` and arbitrary argv, so the runner can satisfy the nonce check without the exploit. The host-side serial is guest-writable; the design lists "without the guest kernel being able to forge the entire channel" as an open Phase 0 question. Yet acceptance requires `nonce_observed = true`, null actor fails, and verdict `reproduced` with authority `runner_observed+llm_assessed` for Dirty Frag. The "guest-attested limit" is a prose note, not a machine-readable authority.
* **Rationale & Recommendation**: The nonce is the causal proof; if the runner can read it as root or the guest can forge the channel, the proof is vacuous. Define provenance (actor starts the PoC; PoC spawns the shell; runner attaches as the actor; reject broker-root shells); restrict or remove root `exec` for target probes (see Major 2); add a distinct authority (`guest_attested+llm_assessed`) or allow `inconclusive` until the Phase 0 tamper analysis shows a non-forgeable channel; make the gate a precondition for the acceptance claim.

### Snapshot/restore semantics are undefined - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Two-VM lifecycle (lines 220-243); state table (lines 258-261); broker verbs (lines 192-193); VmDriver (line 487)
* **Discrepancy Description**: "freeze," "snapshot," and "restore" are used interchangeably; the design never says whether the snapshot includes memory or only disk. A disk-only restore after the null actor leaves guest writes and page-cache state, so the real run inherits the null run's state. There is no fresh-VM signal or leftover-artifact assertion. The prior M-11 remains unresolved.
* **Rationale & Recommendation**: The causal claim requires the real run to start from the same state as the null run. Require a memory-inclusive system checkpoint or a fresh VM per run; define a fresh-VM signal (domain UUID, boot id, overlay creation time); add a leftover-artifact assertion; standardize "snapshot"/"restore" and delete "freeze."

### Broker/network/reboot/transport interfaces are incomplete and partly duplicate - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Broker (lines 181-200); Isolated network (lines 202-218); Interfaces (lines 483-502); Dirty Frag lifecycle (line 236)
* **Discrepancy Description**: `NetworkManager` exposes `create_isolated`, `allow_artifact_mirror`, `default_deny`, `egress_test`, and `destroy`; the broker exposes only `ensure_network`/`destroy_network`. The design says the broker runs the egress test, but the app-side module owns it. `VmDriver` and the broker have no `reboot`; Dirty Frag requires a reboot and a reboot wait. `asyncssh` is in the dependency list, but no guest transport module exists (rev1 had `src/xentry/vm/guest.py`); the broker's `exec`/`copy_in`/`copy_out` do not say whether they use SSH, the guest agent, or libvirt. The broker's `exec` accepts arbitrary argv and `user=root`; "fixed verbs" does not constrain guest commands. (The single-`target_port` gap is addressed under Major 5.)
* **Rationale & Recommendation**: Two owners for network policy is a boundary leak; Dirty Frag cannot be implemented with the published interfaces; the broker is a root-in-guest exec proxy, not a narrow capability. Make the broker own all network/nftables operations with explicit verbs; remove the app-side duplicate; add `reboot` and a reboot-wait state; define the transport; restrict `exec` to typed commands or record the root-in-guest risk; use `target_ports`.

### The state machine loops, and pre-validation outcomes have no projection - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** state table (lines 244-272); DDL (lines 396-446); Storage and audit (line 448); acceptance (line 83)
* **Discrepancy Description**: `failed`, `cancelled`, and `interrupted` are both terminal outcomes and predecessors of `destroying`; `destroying` goes to `validating` or `failed`; only `completed` goes to `done`. A cancelled/interrupted job that cleans up successfully has no terminal post-cleanup state other than `failed` or a loop. The text says "A null-actor failure writes verdict = not_run, authority = runner_observed," but a null-actor failure does not reach the validator and `validations` has no row; `jobs.verdict` is defined as "the latest projection from the final attempt's validation." `jobs` has no `final_attempt_id` (the attempt-model fix is covered under Major 4). The state table has no timeout column.
* **Rationale & Recommendation**: The runner's state is load-bearing for cleanup and audit. Separate `outcome` (completed/failed/cancelled/interrupted) from `cleanup_state`; add a `done` transition for every outcome; add `final_attempt_id`; publish a projection table for every outcome, including null-actor failure and validator error; add per-state timeouts.

### The attempt/retry model is ambiguous and the DDL cannot record pre-attempt calls - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** DDL (lines 404-422); jobs (line 401); budget (line 77); reason codes (lines 290-291); state table (lines 248-267)
* **Discrepancy Description**: `tool_calls.attempt_id` is NOT NULL, but fetch/extract/plan happen before any VM attempt; the design does not create an attempt at job start. `jobs.attempt_dir` is singular while `attempts` can have many; `jobs` has no `final_attempt_id`; `attempts.state` duplicates the job state. A "one rerun" for `nonce_not_observed` is not mapped to a new attempt or a state transition.
* **Rationale & Recommendation**: The audit trail must tell which attempt produced the verdict and where the bytes are. Create an attempt row at job start (attempt 0 for fetch/extract/plan) or make `attempt_id` nullable for pre-attempt calls; add `final_attempt_id`; define retry/rerun as a new attempt; remove `attempts.state` or define it as a sub-state; add a test that every tool call and artifact points to an attempt.

### The target-pack and probe contracts are still untyped sketches - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Target packs (lines 304-336); Probe contract (lines 338-350); `test_packs` (line 706)
* **Discrepancy Description**: The design says "The manifest is a typed schema," but the YAML is a field-name sketch (`base_image: {name, url, sha256}` etc.) with no types, required/optional flags, defaults, or validation errors. `probe.kind` omits `qmp`, while `evidence_channel.kind` and the probe contract include it. `attacker_profile` looks required but must be absent for Dirty Frag; `kernel` is optional but required for Dirty Frag; `null_actor.expected` is a constant. The pack inline `poc` duplicates `poc.pin.yaml`; the pack `base_image`/`kernel` duplicate `config/artifacts.yaml`; the pack `attacker_profile` duplicates `profiles/attacker.yaml`; there is no precedence rule. The single `target_port` does not cover GitLab's 80/443.
* **Rationale & Recommendation**: The pack is the boundary for three heterogeneous targets; an untyped sketch will reproduce target-id branches and ambiguous behavior. Publish exact Pydantic models or a versioned JSON Schema with required/optional, defaults, enums, validation errors, and conditional fields; make `qmp` consistent; choose one source of truth for each image/kernel/PoC/attacker pin; add tests that all packs validate, that the runner has no target-id strings, and that no pack can declare PoC stdout as the pass condition.

### The design reinvents the VM harness and utility layers without assessing the prior tree - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Alternative 4 (lines 531-535); `src/xentry/vm/*`, `src/xentry/evidence.py`, `src/xentry/agent.py`; prior tree `/home/zran/ambitious_projects/xentry/src/xentry/verify/vm.py`, `/home/zran/ambitious_projects/xentry/src/xentry/evidence/store.py`, `/home/zran/ambitious_projects/xentry/src/xentry/llm.py`, `/home/zran/ambitious_projects/xentry/src/xentry/generate/modules/`
* **Discrepancy Description**: The design says "direct QEMU was rejected for V1 because it re-buys the harness and still needs host root for nftables." The old tree already has a ~995-line direct-QEMU harness (`verify/vm.py`) with overlay creation, `savevm pre-poc`/`loadvm` snapshots, SSH exec, provisioning, PoC attempts, and a pre-PoC cache; a ~113-line content-addressed store (`evidence/store.py`); an 80-line DeepSeek/OpenAI-compatible client (`llm.py`); and typed provisioning modules (`generate/modules/`). The design never evaluates porting the harness behind `VmDriver`, reusing the store shape, or reusing the LLM client; it proposes new `vm/*`, `evidence.py`, and `agent.py`. The "re-buys the harness" claim is the opposite of the code reality.
* **Rationale & Recommendation**: The VM/broker stack is the largest new surface; ignoring a working harness is a reinvention risk. Run a Phase 0 reuse spike; port the old target-side QEMU harness behind `VmDriver` (do not reuse its Docker attacker path or `http_poc`); reuse the evidence-store shape and the DeepSeek client; evaluate the typed modules for the V1.1 generated path; cite the old files in Additional Resources.

### The validator's authority and decision rule are undefined - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Validator (lines 360-378); acceptance numbers (line 84); `validator_disagreed` (line 294); `ValidatorClient` (line 498)
* **Discrepancy Description**: The runner deterministically knows `nonce_observed`; the validator returns the product's verdict and can return `not_reproduced` even when the runner observed the nonce. The design defines a one-way clamp (`reproduced` to false when the nonce is false), not the causal criterion the LLM applies, nor a rule for the reverse case. The 18/20 fixture gate is an accuracy proxy, not a decision rule. The prior M-01 recommended limiting the LLM to a reason code/explanation or defining the precise criterion.
* **Rationale & Recommendation**: An authority label is only honest if the authority's decision rule is defined and testable. Define the rule (for example, runner facts are authoritative for the positive; the LLM may only downgrade with a declared reason and evidence ref, and every downgrade is recorded as `validator_disagreed`); or limit the LLM to a reason code/explanation and keep the verdict deterministic. Add false-negative and downgrade fixtures; state provider retention and whether PoC source may be sent (M-06).

### The request-integrity token is not applied to every mutation - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** G1 (line 25); API (lines 452-466); UI (line 468); `static/app.js` (line 696)
* **Discrepancy Description**: G1 says "Every mutation requires a startup-generated request-integrity token," but only `POST /api/jobs` is marked `+ token`; `POST /api/links/check`, `POST /api/jobs/{id}/cancel`, and `POST /api/preflight` are unmarked. `POST /api/links/check` triggers an SSRF-guarded fetch. The token is "HttpOnly, SameSite cookie or a per-page endpoint," but `static/app.js` is "Token-aware fetch," which requires a readable token.
* **Rationale & Recommendation**: The token is the only mutation control. Apply the token middleware to every non-GET route and mark each route; choose one delivery (HttpOnly cookie + double-submit CSRF, or per-page token), and align `app.js`; state the local-process/WSL2 limitation.

### The PoC-link contract is ambiguous and the alternate-invocation language contradicts the pin - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Non-Goals (line 44); `unsupported_poc` (line 281); pack `poc` (line 320); pre-run plan
* **Discrepancy Description**: The Non-Goals say "V1 runs the pinned PoC or an alternate that matches the same invocation contract," while `unsupported_poc` says the PoC link must match the pack pin; the contract test is undefined and the pre-run plan does not show the resolved commit and hash. The prior M-13 remains unresolved.
* **Rationale & Recommendation**: The PoC pin is the "what ran" control. State that the link is a locator that must resolve to the pack's repository and commit; anything else is `unsupported_poc`; remove the alternate sentence or define the exact contract and hash check; show the resolved commit and SHA-256 in the plan; reuse the Check links bundle hash for the job.

### The offline provisioning mirror/catalog does not cover the setup scripts' package needs - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Isolated network (lines 202-218); `scripts/fetch-artifacts.sh` (line 627); `config/artifacts.yaml` (line 632); `targets/php2shell/setup.sh` (line 642); `targets/gitlab/setup.sh` (line 646); `targets/dirtyfrag/setup.sh` (line 650)
* **Discrepancy Description**: The design says the target may reach only a host-local artifact mirror during provisioning and "does not reach the internet." The setup scripts need Ubuntu build/runtime packages (PHP build deps, GitLab deps, kernel modules). The catalog/fetch script lists the base images, attacker image, GitLab `.deb`, and Dirty Frag kernel package, not the apt packages. The result is either a provisioning failure or a mirror that fetches unpinned packages on demand, which undermines the pinned, offline claim.
* **Rationale & Recommendation**: The setup script's hash describes the script, not the packages it installs. Prebuild the target images with all deps and pin the image, or extend the catalog to every package/version, or run a host-side apt proxy with a pinned allowlist and record the fetched package set; add a provisioning-offline test that fails on any non-mirror egress.

### The risk acceptance is claimed but not recorded - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** G7 (line 31); broker (line 200); security (line 472); Alternative 4 (line 534); Additional Resources (line 585)
* **Discrepancy Description**: The design repeatedly says "The risk acceptance is recorded" (broker, guest egress, Dirty Frag, LLM false positive), but no location, format, owner, or status is given. The threat model is a future file (`docs/security/threat-model.md`, Create). There is no risk -> impact -> mitigation -> residual table. The new root broker is the largest new trust surface, and its acceptance is a sentence.
* **Rationale & Recommendation**: An unrecorded acceptance is not an acceptance; the prior M-15 remains unresolved. Add an H2 Risks & Mitigations table with risk ID, trigger, impact, mitigation, residual risk, owner, and status for the broker, egress, Dirty Frag guest attestation, LLM false positive, reactive setup, prompt injection, SSRF, DeepSeek egress, and host PoC archive; record it in the ADR/threat model and cite it.

### `validations` has no nonce id/hash; `null_actor_passed` is vestigial - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** DDL (lines 423-433); acceptance (line 83); text (line 448)
* **Discrepancy Description**: The validation row has no nonce identifier or hash, and `null_actor_passed` is not tied to a defined owner in the schema.
* **Rationale & Recommendation**: Add `nonce_sha256` (not the value); move `null_actor_passed` to `attempts` or drop it; add a check that a completed job has exactly one validation row per nonce.

### `nonce_not_observed` and `exploit_failed` overlap - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** reason codes (lines 290-291)
* **Discrepancy Description**: The two reason codes do not have a clear boundary, so the same outcome can be classified either way.
* **Rationale & Recommendation**: Define `nonce_not_observed` as a probe/infrastructure failure and `exploit_failed` as probe-executed-no-nonce, or merge them.

### `job-slot` is undefined and speculative - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Isolated network (lines 206-214)
* **Discrepancy Description**: `job-slot` has no definition and appears to anticipate concurrency that V1 does not have.
* **Rationale & Recommendation**: Use a fixed isolated subnet per job or a job-id hash; delete `job-slot` until concurrency exists.

### The Overview's "decisive evidence" overclaims Dirty Frag - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Overview (line 9); Open Questions (line 96); `What each target proves` (line 508)
* **Discrepancy Description**: The Overview presents Dirty Frag's evidence as decisive while the channel's forgery resistance is still an open question (see Blocker 3).
* **Rationale & Recommendation**: Say "host-side evidence channel" and state the guest-attested limit.

### The source-aware fetcher keeps four adapters for three fixed CVEs - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** G2 (line 26); `sources.py` (line 667); `test_sources.py` (line 704)
* **Discrepancy Description**: The fetcher carries four source adapters even though V1 has three fixed CVE targets.
* **Rationale & Recommendation**: Accept the three fixed CVE records and three PoC repositories; add a single generic HTML fallback only if a real input requires it; defer NVD/cve.org/GitHub adapters.

### Small hygiene inconsistencies - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Additional Resources/Create (lines 585, 715); attacker image (line 602); GitLab lifecycle (line 227); `tests/test_ui_vocabulary.py` (line 710)
* **Discrepancy Description**: The ADR is listed as an existing Additional Resource and as Create; the attacker image says "no compiler needed" while the GitLab PoC is built with Go in the attacker; `tests/test_ui_vocabulary.py` does not say it scans rendered HTML/JSON/static/bundle.
* **Rationale & Recommendation**: Fix the ADR status, correct the toolchain wording, and scope the vocabulary test to rendered output. (The Non-Goals "normal flow" wording and `static/app.js` token wording are covered under Blocker 2 and the request-integrity Major, respectively.)
