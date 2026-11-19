# Goldfish Review Report

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (`Lines 520-712`, Detailed Implementation Plan; lines 1-519 read as context)
**Stage:** 9 - Implementation Readiness Test
**Mode:** REVIEW

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-implementation-readiness` | completed |
| `egm-codebase-details` | completed |
| `egm-style` | completed (retry) |

Review note: the first `egm-style` run returned an implementation-readiness-style technical report instead of an editorial review, so it was retried once with the style lens scoped. Unique technical findings from the first run (snapshot/restore semantics, acceptance-gate reproduction, the missing help route) are retained below under the `egm-style` lens; the editorial findings come from the retry.

## Prioritized Findings (Blockers -> Major -> Nits)

### B1. Target-pack contract is not implementable as written - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 195-207, 576-594, 609, 619`; pack rows `581, 585, 589`
* **Discrepancy Description**: The manifest is a field-name sketch. There are no types, required/optional flags, defaults, validation errors, or field definitions for `TargetPack`, `PocPin`, `ProbeEvidence`, or `RunLimits`. The per-pack `probe.py` hook has no callable name, signature, context object, or return contract, yet `packs.py` (619) is expected to import and execute it. `poc.pin.yaml` is listed but it is unclear whether `pack.yaml` embeds or references it, and `setup hash` has no algorithm or normalized input list. `destroy_policy` values are never mapped to runner behavior. The three target rows (581, 585, 589) use different field sets and omit values (e.g. actor and `what_proves` are missing in some rows), so the schema cannot be derived from them.
* **Rationale & Recommendation**: The three real packs, the dummy pack, the pre-run plan, the validator bundle, and G5's no-pipeline-edit test all depend on this contract. Publish a versioned JSON Schema or exact Pydantic models, a probe protocol (for example `def run(ctx: ProbeContext) -> ProbeEvidence`), the `ProbeContext` and `ProbeEvidence` fields, pin and setup-hash rules, allowed `destroy_policy` values, and one fixed field order for every pack row.

### B2. Runner state machine has no transition table or projection rules - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 147-168, 219-226, 258-263, 614, 667`
* **Discrepancy Description**: The document gives a state sequence, not a transition specification. It does not define guards, terminal states, or how `completed`, `destroying`, and `done` relate. `completed` is called a job state but the diagram continues to `destroying -> done`. Freeze and snapshot have no state; null actor and real actor both map to `running_poc`. The ordering of `cancelled` and `interrupted` relative to `destroying` is undefined, as are retry transitions, the "next phase boundary" for cancellation, and the representation of `security_cleanup_failed`. The projection from `validations` into job list/detail fields (state, verdict, authority) is unspecified. `tests/test_state_machine.py` is asked to test "allowed transitions" that are never enumerated.
* **Rationale & Recommendation**: The runner is the product's core and the standard requires predetermined state transitions. Add a transition table with current state, trigger, guard, next state, emitted events, and timeout; define terminal and display states; define retry entry points, cancellation and interruption edges, and the SQL projection for job state, verdict, and authority; add matching tests.

### B3. Plan is a file inventory, not a set of interfaces and function boundaries - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 318-332, 548-697, 605-647`
* **Discrepancy Description**: Every row is a one-sentence responsibility summary. No signatures, parameter types, return types, error modes, or value-object fields are given for `VmDriver`, `GuestExec`, `HttpProbe`, `Fetcher`, `EvidenceStore`, `AgentRuntime`, `ValidatorClient`, or `JobRunner`. `VmProfile`, `CommandResult`, `SnapshotRef`, `EvidenceBundle`, the SSE event record, and `outcome.json` have no schemas. Line 332 claims the function boundaries are fixed in the Implementation Plan, but they are not. `author_setup` returning a script (context line 327) conflicts with the script-plus-wrapper requirement at 571, and repair is absent from the declared interface.
* **Rationale & Recommendation**: An implementer must design the public API and data model, which the zero-decision rule forbids. Add a signature and schema appendix covering every interface and value object, including the repair method and the error taxonomy.

### B4. Agent runtime, typed facts, repair loop, and ADK decision gate are undefined - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 289-296, 320-330, 536, 566-574, 620, 673, 710`; context `Lines 66, 124, 291`
* **Discrepancy Description**: `AgentRuntime` declares only `extract` and `author_setup`, but `agent.py` must implement extraction, setup, and repair (620), and a repair path exists at 164 and 572. No `Facts` model, field list, type set, citation format, or `evidence_insufficient` variant exists. Prompt input/output schemas, model parameters, malformed-JSON behavior, and prompt-hash canonicalization are unspecified. The ADK spike tests "20 scripted scenarios with two tools" (710) while the agent is repeatedly described as tool-less (291-292, 536, 673). The switch threshold is only "the agreed threshold," with no metric, number, or owner; the step budget at 296 has no value or enforcement point.
* **Rationale & Recommendation**: These choices determine whether the ADK-to-LiteLLM fallback and the agent tests are meaningful. Define the complete `AgentRuntime` protocol including `repair`, a versioned `Facts` model, every prompt's input/output contract and model settings, a numeric spike metric and threshold, and the exact tool set, or move the ADK-versus-LiteLLM choice into a Phase 0 gate with explicit pass/fail criteria.

### B5. SQLite schema, authority, concurrency, attempts, and migration ownership are not implementable - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 240, 296, 300-316, 560, 600, 610, 613`
* **Discrepancy Description**: Only column names are given: no types, nullability, defaults, primary keys, foreign keys, unique constraints, index names, or JSON column semantics. The validation write at 240 stores `authority: llm`, but the `validations` DDL (309-311) has `validator_kind` and no `authority` column. `jobs.result` versus `validations.verdict` is undefined, including which is authoritative. G8 requires a database-enforced single worker and single VM slot, but `jobs` has no `claimed_by`, lease, or lock columns and no lock table is listed; `queue.py` claims a "cancellation flag" (613) but there is no cancel column. Retries get a fresh attempt directory (167) while `jobs` stores one `attempt_dir` (305) and `validations`/`artifacts` have no attempt identifier. Model request/response logging (296) has no table or file. Both `src/xentry/db.py` (610) and `scripts/migrate.py` (560) are described as owning migrations, and the startup path (app lifespan, 630) does not state whether migrations run, whether backup happens first, or how a newer schema is refused. No rebuild function supports G9's "SQLite is a rebuildable index."
* **Rationale & Recommendation**: Publish the complete `001_initial.sql` DDL and the migration/startup sequence; add `authority`, cancel, lease/claim, and attempt identifier fields or an attempts table; define the claim and projection queries; add a model-call audit table or file; and specify the rebuild/reindex function and its test.

### B6. Null actor, nonce ownership, and probe causal path are undefined - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 219-226, 242-246, 584-592, 614, 675, 685, 708`
* **Discrepancy Description**: The runner is said to generate and place the nonce (221), but the pack probe is described as placing it (584, 588, 592) and the manifest also declares `nonce_placement` (203); ownership is contradictory. The null actor is never defined: its identity, command, how it differs from the real actor, and what "produces the nonce" means are absent. The acceptance wording "the null actor fails" (708) is ambiguous and can be read as requiring the null-actor step itself to fail, the opposite of the intended check. `validations.null_actor_passed` exists (311) although a null-actor failure aborts before the validator (222). Dirty Frag's "verifies the VM was fresh" (592) has no observable signal, and the runner step list omits the restore-plus-fresh-nonce step before the real actor.
* **Rationale & Recommendation**: The null-actor run and runner-owned nonce are the primary controls against self-reported success. Specify nonce placement and ownership, a pack-level null-actor command/mode and its expected no-nonce result, where evidence and pass/fail are recorded, the abort code, the fresh-VM signal, and tests that the real-actor nonce differs from the null-actor nonce.

### B7. Host prerequisites and preflight coverage are missing - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 269, 555, 559, 623, 647, 699-711`
* **Discrepancy Description**: The plan lists no required host packages or versions: QEMU/KVM, the libvirt daemon and session mode, `qemu-img`, `cloud-localds`/cloud-image-utils, libvirt development headers for `libvirt-python`, SSH, systemd user lingering, or a supported Python 3.12 environment. It does not state `/dev/kvm` permissions, host memory and disk headroom (GitLab is sized at 8 GB guest RAM and 40 GB disk at 585), image and package acquisition, or port availability. `preflight.py` (623) checks libvirt, KVM, images, DeepSeek, database, bind mode, and orphan domains, but not `cloud-localds`, `qemu-img`, free disk, free memory, egress, or SSH key permissions. The WSL2 operational checks at 269 have no implementation task or verification gate.
* **Rationale & Recommendation**: The plan cannot be executed on a fresh host without the implementer choosing and documenting system dependencies, and preflight can pass while the first real VM creation fails. Add a host-prerequisites section with exact packages and versions, a bootstrap/check script, preflight checks for every external tool and resource, and a WSL2 verification gate.

### B8. Phase 0 and open decisions are not integrated into the implementation order - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 61-67, 344-355, 522-531, 533-546, 563, 645, 711`
* **Discrepancy Description**: The implementation order starts at steps 1-8, but Phase 0 gates are cited as prerequisites at 538, 544, and 711 with no Phase 0 task list, deliverable, or checkpoint. The gates cover session libvirt, the PHP2Shell build, and the Dirty Frag kernel, but omit GitLab package availability and host sizing, the ADK spike, and base-image hashes from the open questions. `scripts/run_target_e2e.py` refers to "Phase 2/3 acceptance runs" (563), which does not match the 1-8 order. No phase has build/test exit criteria, and step 3 creates packs that import `probe.py` before the interfaces delivered in step 6 exist. The deferred-decisions list (344-355) still includes SQLite versus manifest-only, web framework and live-log transport, deployment unit, GitLab version, Dirty Frag kernel source, session versus system libvirt, and the LAN policy, while the plan fixes most of them. System libvirt is simultaneously "out of scope," "used only if a target requires it," and "decided after the spike." "A failed gate changes the plan" (711) has no decision procedure.
* **Rationale & Recommendation**: The largest architectural unknowns are not scheduled or owned. Add a numbered Phase 0 with tasks, artifacts, pass/fail criteria, and decision records; map every file and every deferred/open question to a phase and exit gate; reorder or stub dependencies so each phase leaves the codebase buildable and testable; and align all phase references.

### B9. Verdict, authority, and failure-reason taxonomy is not closed - Severity: Blocker
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 35, 75, 81, 158, 230-240, 609, 674, 708`
* **Discrepancy Description**: `FailureReason` is named as a model but no values exist, and "closed reason code" (233, 240) is never closed. The validator's reason vocabulary and the runner's failure vocabulary are not separated, and the required "next action" for every failure (G11, 35) has no field, column, or UI mapping. `not_run` is listed as a verdict (158) although the validator returns only three values (230-238), and a completed job must have a validation row tied to its nonce (75, 708); where `not_run` is stored and when it occurs are undefined. Line 708 says "the verdict is `llm_assessed`," conflating the authority label with the verdict field, and line 674 is ambiguous between stored authority and UI label. Validator behavior for malformed JSON, refusal, timeout, rate limiting, unknown reason codes, and nonexistent evidence references is unspecified.
* **Rationale & Recommendation**: The runner, database, UI, tests, and bundle all need the same closed vocabulary. Enumerate `FailureReason` and validator reason codes with category, owning phase, job state, next-action text, and whether the validator may return each; define `not_run` storage and semantics; add an `authority` field and one writer; and specify fail-closed validator behavior with tests.

### M1. HTTP, SSE, pre-run plan, and help contracts are missing - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 178-189, 181, 186, 625-634, 653-660`
* **Discrepancy Description**: There is no route table with methods, paths, status codes, request/response bodies, or an error envelope. The pre-run plan required by G10 has no endpoint: `schemas.py` mentions plan models (633) and `new_job.html` renders a plan, but `routes.py` (631) and the API list (180-189) contain no plan route. There is no polling-fallback endpoint despite G8. `POST /api/jobs` accepts only `{cve_url, poc_url}` with no reference to the evidence pinned by the link check, so whether Start re-fetches or reuses bytes is undefined and creates a TOCTOU gap. `/api/links/check` returns an unspecified "summary." There is no read endpoint for the validation row, evidence references, nonce id, or version evidence required by Job Detail. SSE event names, payloads, `Last-Event-ID`/cursor backfill, heartbeat interval, and terminal close are unspecified, as are cancel idempotency, bundle content type, token requirements for `POST /api/preflight`, and the help route despite `help.html`.
* **Rationale & Recommendation**: The UI and browser client cannot be implemented without independently designing the API. Publish an endpoint table with Pydantic request/response models, error and status mapping, a plan or check-id response, evidence-reuse semantics, polling fallback, the SSE event schema, and the missing help route.

### M2. Event, outcome, manifest, bundle, and rebuild formats are undefined - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 160, 296, 302-316, 612, 622, 678`
* **Discrepancy Description**: `events.py` is to define an "event schema," but no fields, event types, sequence source, timestamps, IDs, terminal event, or payloads are specified. It is unclear which actions become `tool_calls` rows, what their status values mean, or how `result_path`/`result_sha256` are produced; `artifacts.kind` is not enumerated. `outcome.json` has no schema or writer. The attempt directory is listed by contents only, with no filenames or layout. `manifest_hash` has no defined manifest, and `evidence_sha256`, `manifest_hash`, and `validator_prompt_hash` have no canonical serialization. The bundle layout, archive format, hash-manifest format, and redaction boundary are unspecified. No `rebuild_index` path supports G9's claim that SQLite is rebuildable and a bundle reconstructs the job.
* **Rationale & Recommendation**: The append-only event log and attempt directory are declared authoritative; without schemas, the UI, bundle, recovery, and audit tests will diverge. Define versioned JSON schemas and canonical hashing for events, transcript lines, tool calls, outcome, manifest, and bundle; specify the directory tree and rebuild/reindex function with round-trip tests.

### M3. Configuration surface and `.env.example` contradict the plan's fixed defaults - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 533-546, 556, 608`; `/home/zran/ambitious_projects/xentry_claude/.env.example:19,23,29-32`
* **Discrepancy Description**: The plan says to add six variables but does not reconcile existing values. `.env.example` sets `XENTRY_LIBVIRT_URI=qemu:///system` while the plan fixes session mode first (538). It sets `XENTRY_MAX_SETUP_ATTEMPTS=3` and `XENTRY_MAX_POC_ATTEMPTS=3` while the retry rules allow one setup repair and one PoC rerun (164-165). It sets global VM memory/vCPU/disk values while resources are declared per target pack (200, 581, 585, 589) with no precedence rule. `XENTRY_DB_URL=sqlite:///./var/xentry.db` is relative while `config.py` must reject relative SQLite URLs (608). New variables such as `XENTRY_TOKEN_FILE`, `XENTRY_SSH_KEY_DIR`, `XENTRY_EGRESS_MODE`, `XENTRY_MAX_TOKENS_PER_JOB`, `XENTRY_MODEL_TIMEOUT_SECONDS`, and `XENTRY_VALIDATOR_MODEL` have no defaults or allowed values, `XENTRY_AGENT_MODEL` is not mentioned, and other required settings (data dir, bind host/port, Host allowlist, catalog path, disk ceiling, prompt directory) are absent.
* **Rationale & Recommendation**: The shipped example would either be rejected at startup or select the risky system-libvirt path, and the implementer would have to decide precedence and defaults. Publish a complete settings table (name, type, default, required, validation), state the global-versus-pack precedence, rewrite `.env.example`, and verify that the app starts from the example with only secrets filled in.

### M4. Dependency pinning, build, and deployment reproducibility are unresolved - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 554, 558, 561, 630, 699-703`
* **Discrepancy Description**: The plan says "Pin exact versions in the lockfile," but the target file list contains no lockfile, names no lockfile tool, and the build command `pip install -e '.[dev]'` does not consume one. `libvirt-python` is an unconditional runtime dependency, so the fake-driver unit-test path (643) still requires libvirt headers and libraries. `python-multipart` is included although mutations require JSON (191). There is no package-data rule for `targets/` and `prompts/`, and no console entry point, uvicorn module path, or systemd `ExecStart` is given.
* **Rationale & Recommendation**: The fake-VM testability goal (G12) and Phase 1 buildability fail on a host without libvirt development packages. Choose a lockfile tool and file, install from it in the build step, make the VM backend an optional extra or lazy import, state package-data inclusion, and specify the deployment entry point.

### M5. Egress control remains an open design decision - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 265, 538, 556, 646, 711`
* **Discrepancy Description**: The plan explicitly leaves "a host-side allowlist proxy or per-VM nftables" to the Phase 0 spike, and `network.py` repeats "egress allowlist or nftables rules" (646). `XENTRY_EGRESS_MODE` is added to `.env.example` without values, semantics, or a default. The Phase 0 gates do not include the egress test, and the test's target, expected failure behavior, and logging format are unspecified. How nftables rules are applied under `qemu:///session` is unaddressed.
* **Rationale & Recommendation**: Egress control is a security boundary, and the two mechanisms differ substantially in privilege and viability. Select one mechanism for V1 (or specify both and the exact selection rule), define the config values and fail-closed behavior, add the negative egress test, and gate it in Phase 0.

### M6. Verification gates and test plan are not executable, and acceptance can pass without reproduction - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 563, 664-688, 699-712`
* **Discrepancy Description**: Test files have topic lists, not concrete cases or assertions. There is no test file or case for web routes, SSE/backfill, polling fallback, migrations/backup/newer-schema refusal, config validation, preflight, cancellation, or cleanup destroy failure, and coverage excludes `scripts/`. "Two consecutive clean runs per target" (708) does not define "clean"; setup repair and PoC rerun are normal paths, and the run is not required to produce a `reproduced` verdict, only a `llm_assessed` label. "No completed job lacks a validation row" is a double negative. `scripts/run_target_e2e.py` does not specify its CLI, authentication, wait/timeout behavior, real-VM opt-in, or output format. Implementation phases have no exit criteria, and the WSL2 checks at 269 are absent from the gates.
* **Rationale & Recommendation**: Add a per-file test-case table with inputs and expected assertions, add the missing test files, define "clean run" as no stage failure and no retry/repair, require the expected verdict and `authority: llm`, specify the acceptance script, and define each phase's exit gate.

### M7. Dummy generated pack and the no-pipeline-edit gate are incomplete - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 207, 580, 593-594, 672, 688, 709`
* **Discrepancy Description**: Only `pack.yaml` and `probe.py` are listed for the dummy pack. A `provisioning: generated` pack still needs setup inputs, a PoC pin or synthetic PoC, and a defined path for a synthetic CVE through link checking and job creation. `tests/test_packs.py` proves manifest loading and probe import only, not that the runner executes a generated pack without pipeline edits. `targets/_dummy/` and `tests/fixtures/packs/dummy/` duplicate each other with no stated relationship. The "no human review" and "no edits outside its directory" claims are not testable, and the property is restated four times under three names.
* **Rationale & Recommendation**: G5's no-pipeline-edit claim is a product acceptance criterion, not a loader test. Define the complete dummy-pack contract, add a fake-VM end-to-end test that runs the generated target through the runner with no edits outside its directory, define one canonical fixture, and state the property once with a test cross-reference.

### M8. Image, kernel, and PoC pins have duplicate sources and the catalog is git-ignored - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 557, 559, 564, 581-591, 619`; `/home/zran/ambitious_projects/xentry_claude/.gitignore:5`; context `Lines 64, 543`
* **Discrepancy Description**: The plan creates `var/base-images/catalog.yaml` and `scripts/fetch-base-images.sh` verifies downloads against it, but `var/` is already git-ignored, so a fresh clone cannot verify images and G5's checked-in digest is unmet. The Dirty Frag kernel URL/SHA-256 appears in both the catalog and `targets/dirtyfrag/pack.yaml`. `poc.pin.yaml` fields omit SHA-256 for PoC files or tarballs even though `packs.py` verifies "PoC hashes." The base image is named "Ubuntu 24.04" (581, 585), "Ubuntu 24.04.4" (589), and "Ubuntu 24.04 cloud image" (559), while one catalog entry is described. The GitLab `.deb` URL and hash remain unresolved.
* **Rationale & Recommendation**: Move the catalog to a tracked path (for example `config/base-images.yaml`), declare one source of truth for each image, kernel, and PoC pin, add the PoC hashes, use one stable image id and version throughout, and gate resolution of the GitLab and Dirty Frag pins in Phase 0.

### M9. Security implementation details are missing - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 191, 334-342, 611, 616, 644, 647`
* **Discrepancy Description**: The token length, default file path, rotation behavior, Host allowlist values, Origin handling for missing or opaque origins, and CSRF helper behavior are unspecified. Guest SSH host-key verification, key type, permissions, and `known_hosts` handling are absent. Secret-redaction patterns, scope, and by-value matching are undefined, including whether the nonce (which must reach the validator) is preserved. Token generation and storage are not described.
* **Rationale & Recommendation**: These are security controls whose details are policy choices. Specify token generation/storage/rotation, the exact allowlist and origin rules, SSH host-key verification and key handling, and the redaction pattern list with fixtures; add the SSRF connect-to-resolved-IP requirement (see N7).

### M10. VM driver, domain XML, port forwarding, and guest addressing are unspecified - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 250-254, 320-330, 641-647`
* **Discrepancy Description**: `VmDriver.exec(tty)` versus `GuestExec.run(timeout)` ownership is unresolved, and the fixed domain XML is not checked in or enumerated. User-mode `hostfwd` setup and port allocation are undefined. `VmDriver.get_ip` is asserted for `qemu:///session` user-mode networking, where no routable guest IP exists. The domain-name prefix used by cleanup and the overlay/ISO naming scheme are not specified.
* **Rationale & Recommendation**: These choices affect destroy safety and SSH connectivity. Define the driver/exec protocols, check in the domain XML template, specify the forwarding and port-range strategy, define what `get_ip` returns under user-mode networking, and standardize domain, overlay, and ISO naming.

### M11. Snapshot, restore, freshness, and Dirty Frag mechanics are underspecified - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 213, 220-223, 246, 267, 341, 589-592, 614, 642, 707`
* **Discrepancy Description**: The snapshot type (disk-only versus memory), offline/live behavior, and post-restore boot state are undefined. Dirty Frag page-cache contamination and the no-restore/fresh-VM retry rule are not encoded. The probe's "verifies the VM was fresh" states an outcome, not an observable signal (domain UUID, boot id, overlay creation time, or attempt id), and the failure behavior is unstated. How the PTY root shell is driven (expect, asyncssh PTY, prompt detection), how the root-only nonce is placed, how the kernel package is installed and the boot entry selected, and how `security_cleanup_failed` maps to job state and UI are all absent. The Dirty Frag kernel and PTY reliability remain open questions.
* **Rationale & Recommendation**: This is the cut-line target with the most fragile mechanics. Specify restore semantics, the fresh-VM signal and comparison, the Dirty Frag no-restore rule, the PTY state machine and timeouts, nonce placement, kernel install/reboot verification, and the teardown-failure representation.

### M12. Cancellation, cleanup, and orphan identification are undefined - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 83-87, 155-168, 267, 613-615, 632, 675-676`
* **Discrepancy Description**: "Next phase boundary" is not defined. Behavior while a guest command, model call, or validator call is in flight is unspecified. The cancel flag's persistence across restart is unstated, and no test file covers cancellation. The domain-name prefix used by the orphan sweep, the overlay and ISO naming paths, and the interrupted-job path through destroy are undefined. The difference between `security_cleanup_failed` and generic teardown failure is not stated, including the Dirty Frag interaction.
* **Rationale & Recommendation**: Cancellation and recovery are core CUJs. Specify cancel checkpoints, in-flight operation handling, persistence across restart, domain/overlay/ISO naming, the cleanup result state machine, and tests for cancellation and destroy failure.

### M13. Retry and attempt-directory semantics contradict each other - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 162-167, 305, 316, 613-614, 666, 675`
* **Discrepancy Description**: Every retry is said to get a fresh attempt directory (167), but `jobs` has a single `attempt_dir` (305) and storage calls a per-job attempt directory authoritative (316). There is no attempts table and no attempt identifier on `validations` or `artifacts`. Retry counters, the transient-versus-exploit classifier, the Dirty Frag fresh-VM rule, and the relationship between the `.env` attempt limits (3) and the one-repair/one-rerun rule are unspecified.
* **Rationale & Recommendation**: The audit directory and database reference would disagree across retries. Choose per-job versus per-attempt directories, add an attempts table with counters and a current-attempt pointer, define the failure classifier and Dirty Frag re-entry rule, and align the environment limits.

### M14. Timeout, token, disk, and retention budgets have no values or enforcement points - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 29, 201, 204, 283, 501, 503, 609, 615, 618, 671`
* **Discrepancy Description**: `RunLimits` is named but has no fields, and pack `timeouts` have no keys or values. Phase, boot, provisioning, model, and validator timeouts are not enumerated. `XENTRY_MAX_TOKENS_PER_JOB` has no counting method or per-call cap, and "roughly 20k-token evidence bundle" (618) contradicts the word "cap." The NFR's disk ceiling has no check in `preflight.py` or the runner, and overlays/archives are said to be "pruned by policy" (316) with no module, threshold, accounting method, or admission check.
* **Rationale & Recommendation**: Budget enforcement is a stated goal and cannot be implemented or tested without values and enforcement points. Define the limits model, every timeout key and default, the tokenizer and hard cap behavior, the disk accounting and admission/prune policy, and tests that each budget is enforced.

### M15. Setup execution, hash pinning, review provenance, and log classification are undefined - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 164, 546, 571-572, 581-582, 589-590, 619`
* **Discrepancy Description**: The plan does not specify how the runner copies and executes `setup.sh` (shell, root, timeout, environment, logging), what exactly is hashed, or how line endings and generated files are normalized. The one-time hand review has no recorded reviewer, date, or procedure, and the plan's restatement at 546 drops the binding qualifiers "for malicious content" and "hash-pinned for V1 acceptance." The generated setup "line cap" has no value. "Classified log" (164, 572) is never defined: no classifier, class labels, selection rule, or size bound, so "one repair" and "required concrete log line" are not implementable.
* **Rationale & Recommendation**: Setup scripts run as root in the guest, and the hash pin and review claim are audit controls. Define the setup execution contract, the hash manifest and normalization rules, the review record, the line cap value, the classifier schema and repair prompt contract.

### M16. PHP2Shell pack mechanics are underspecified - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** `Lines 211, 244, 581-584`
* **Discrepancy Description**: The web user identity, nonce file path, owner, and mode are not given. The PoC `--cmd` argument contract and quoting rules are undefined. The runner's HTTP GET URL, port, and expected response are not specified. The exact form of version evidence (`php -v` output and loaded Apache module) is not defined, and the readiness check is only named.
* **Rationale & Recommendation**: The probe is the pass condition. Specify the nonce path/owner/mode, the PoC CLI contract, the HTTP probe URL/status/body check, and the exact version-evidence fields.

### M17. GitLab pack mechanics and pin are unresolved - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-style`
* **Affected Scope:** `Lines 64, 212, 245, 543, 585-588`
* **Discrepancy Description**: "git-owned nonce" does not name the GitLab service user or the file path outside the document root; the earlier specification says the service user. The "GitLab version endpoint" is not named and its authentication requirement is unspecified. The Omnibus `.deb` URL and SHA-256 are still open. Service readiness and dependency installation are only named. The 4 vCPU/8 GB/40 GB values are guest estimates with no host sizing, and the pack row drops the `CE` edition. GitLab version and sizing appear as fixed defaults (543, 585) but remain deferred (64, 350).
* **Rationale & Recommendation**: The GitLab probe depends on filesystem ownership and an endpoint contract the implementer would otherwise invent. Specify the service user (`git`), nonce path and ownership, version endpoint and auth, exact package URL/hash resolution, readiness check, host resource estimate, and align the fixed/deferred statements.

### M18. References and file-operation markers are dangling or contradictory - Severity: Major
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 509, 563, 694, 696-697`; context `Line 67`
* **Discrepancy Description**: `docs/adr/0001-v1-reset.md` is listed as an existing Additional Resource at 509 but as "Create" at 694, and the file does not exist; the plan also references an old "ADR 0007" that is not present. `design_draft.md` at 696 has no path, is not in Additional Resources, and a root-level file exists. `docs/designs/SITEMAP.md` is "Create or modify" at 697 but already exists. `docs/designs/xentry-v1.md` is marked "Create at finalization" although it exists and is this document. The Type column has no controlled vocabulary ("Create at finalization", "Create or modify"), and "Modify" rows do not name the baseline being modified.
* **Rationale & Recommendation**: A fresh implementer cannot resolve these references. Fix the ADR reference and add the file to the create list, give the design-draft path or remove the row, mark existing files as Modify with a baseline, restrict Type to `Create | Modify | Copy from old tree`, and align phase references.

### N1. Undefined and overloaded vocabulary, and unverifiable quality claims - Severity: Nit
* **Reviewer Lens:** `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 562, 593, 608, 659-660, 674, 709`
* **Discrepancy Description**: "v2-shaped data directory" (608) is never defined, so the check and its test cannot be written. "Disagreement copy" (674) is ambiguous between UI text and a copy operation. "Token-aware fetch helper" (660) overloads "token," which also names the request-integrity token, the nonce, model tokens, the token file, and the mutation token. "Minimal accessible," "Thin," and "Proves" (562, 593, 709) are unverifiable quality claims or overstate what a test demonstrates.
* **Rationale & Recommendation**: Define the exact paths, terms, and UI strings; replace quality adjectives with testable criteria (for example WCAG 2.2 AA checks, "wrapper around `src/xentry/preflight.py`"), and name the header in the fetch helper.

### N2. Banned-vocabulary rule and its tests disagree on scope and case - Severity: Nit
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** `Lines 34, 193, 677, 712`
* **Discrepancy Description**: The rule is stated with inconsistent capitalization ("Succeeded" versus "succeeded"), and both tests scan template source only. Rendered HTML, JSON responses, `static/app.js`, and bundle text can contain the banned words while the test passes.
* **Rationale & Recommendation**: State the ban once as case-insensitive, word-boundary matching, and test rendered responses, static assets, and bundle text rather than templates alone.

### N3. `python-multipart` conflicts with the JSON-only mutation rule - Severity: Nit
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 191, 554`
* **Discrepancy Description**: The dependency supports form bodies, but the API requires a JSON content type for mutations, and no form endpoint is planned.
* **Rationale & Recommendation**: Remove the dependency or document the form endpoints that justify it.

### N4. Per-pack `probe.py` imports conflict with the no-plugin-loader non-goal - Severity: Nit
* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** `Lines 56, 197, 619`
* **Discrepancy Description**: Non-Goals reject "dynamic target packs or a plugin loader," while the plan imports checked-in Python hooks from each pack directory. Checked-in hooks are not a dynamic loader, but the distinction is not stated.
* **Rationale & Recommendation**: Clarify that packs are static, checked-in code imports, not dynamically discovered plugins.

### N5. Terminology and hyphenation drift - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 470, 472, 530, 541, 570, 656`
* **Discrepancy Description**: "PHP2Shell end to end" versus "end-to-end"; "Tool-less extractor prompt" versus "no tools" elsewhere; "per-job directories" (541) versus "per-job attempt directory" (33, 316); "cancel" versus "Start" and "Check links" in adjacent UI rows; "cloud image" versus "base image."
* **Rationale & Recommendation**: Standardize hyphenation, use "per-job attempt directory," capitalize UI control names consistently, and choose one term for the base image.

### N6. Table column and voice do not match the required content - Severity: Nit
* **Reviewer Lens:** `egm-style`
* **Affected Scope:** `Lines 552-554` through `692`
* **Discrepancy Description**: The column header "Proposed changes and rationale" promises rationale, but almost no cell contains one, and Create rows describe required contents rather than a change. Voice is mixed across imperative, descriptive passive, and third-person present, so a reader cannot tell whether a cell is a requirement, a note, or a suggestion. Line 554 combines metadata, two dependency lists, a pinning rule, tool configuration, and a sourcing constraint in one long cell.
* **Rationale & Recommendation**: Rename the column "Required contents," write every cell as a parallel noun phrase, split the long cell, and add a rationale clause only where a choice is non-obvious.

### N7. SSRF guard leaves a resolve/connect gap - Severity: Nit
* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** `Lines 281, 616, 669`
* **Discrepancy Description**: The plan checks DNS resolution and re-checks redirects but does not require the HTTP client to connect to the validated address, disable environment proxies, or handle DNS rebinding; IPv6/ULA and metadata-address enumeration are omitted.
* **Rationale & Recommendation**: Require connecting to the validated IP (or use a custom transport), set `trust_env=False`, re-resolve on every redirect, and add a rebinding test.

## Overall Assessment

The Detailed Implementation Plan names a plausible file set and build order but is not implementation-ready under the standard. Four central contracts are absent or internally inconsistent: the target-pack plug-in contract, the runner state machine, the interface/value-object signatures, and the SQLite DDL. An implementer would still have to invent the pack schema, probe API, state transitions, retry/attempt model, concurrency enforcement, reason-code set, API schemas, and egress mechanism. The most urgent fixes are B1-B9, followed by the configuration and pin-source contradictions (M3, M8) and the verification/phasing gaps (M6, B8), which would otherwise let a build pass its own gates without proving the required behavior.
