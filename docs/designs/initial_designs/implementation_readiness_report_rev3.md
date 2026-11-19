# Goldfish Review Report

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (`DetailedRange 572–714`)

**Stage:** 9 — Implementation Readiness Test (revision 3)

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-implementation-readiness` | completed |
| `egm-codebase-details` | completed |
| `egm-style` | completed |

**Assessment:** Revision 3 structurally resolves the revision-2 Stage 9 budget, state-machine, and author/repair Blockers. It does not resolve either revision-3 Stage 5 Blocker: the broker still has no broker-owned target/step registry or trusted `http_probe` verb, and provisioning root is not separated from the guest actor. The DetailedRange remains a file/topic manifest rather than an executable plan: core typed contracts, target/artifact values, and the runner step contract are absent, so the Zero-Decision Rule is not met.

## Prioritized Findings (Blockers -> Major -> Nits)

### Broker-owned target/step registry and trusted `http_probe` verb are missing — Severity: Blocker

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 613, 620, 639, 646; feature spec 204–232, 322–335
* **Discrepancy Description**: `exec(vm_id, step_id, ...)` still resolves `step_id` against "the target definition" in app-side `src/xentry/targets.py`; `start_target`/`start_attacker` accept app-chosen ids, `copy_in` an app artifact id, and `start_artifact_mirror` a manifest id. No file defines a broker-owned catalog of targets, steps, images, profiles, or artifacts with hashes, typed parameters, and allowed users; `broker/profiles.py` is only "Domain XML, image resolution, guest IP." `HttpProbe` remains broker-internal in the feature contract, but the 19-verb set has no `http_probe`, and `VmDriver` exposes only 13 verbs, so the trusted target-side nonce observation has no call path while app-side `vm/probes.py` duplicates it. `test_broker_contract.py` does not test rejection of unknown ids. This is the unresolved revision-3 Stage 5 Blocker 1 and the open part of revision-2 Stage 9 Blocker 4.
* **Rationale & Recommendation**: Either the broker accepts app-chosen templates/ids (making it an arbitrary-command proxy) or the implementer must invent the trust boundary; both violate the Zero-Decision Rule and the former is a trust gap. Add one broker-owned registry (fold it into `broker/profiles.py` or raise the 40-module cap), resolve and reject unknown target/step/image/profile/artifact ids server-side, and add `http_probe(network_id, target_ip, port, method, path, timeout, max_bytes) -> HttpResult` to the fixed verbs, `VmDriver`, the broker client, and the contract test. Demote `vm/probes.py` to a plan builder or delete it.

### Provisioning root is not separated from the guest actor — Severity: Blocker

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 578, 604–606, 685; feature spec 228, 304–310; Gate B 114
* **Discrepancy Description**: PHP2Shell builds PHP and configures Apache, GitLab installs Omnibus, and Dirty Frag installs a kernel; all three setup scripts need root in the guest. The plan allows root only for Dirty Frag setup/probe steps, names `xentry` as the guest actor, and never states the provisioning user, sudo policy, or actor restrictions. It also reuses the literal `xentry` for both the host app user and the guest actor. If setup runs as `xentry` with sudo, the actor can read `/root/xentry-nonce` without the exploit, making the Dirty Frag null-actor check non-probative. No test asserts that `xentry` cannot run `sudo -n true`, read the nonce, or write a service binary. This is the unresolved revision-3 Stage 5 Blocker 2.
* **Rationale & Recommendation**: The implementer must choose between a false broker rule and a sudo-enabled actor. Define `provision_user: root` for all three hash-pinned setup scripts allowlisted by step id; define `actor_user` as non-sudo with no writable root-owned paths, no setuid/sudo/pkexec, and no shared SSH key; add explicit denial tests (`test_actor_separation.py`) and the Gate B check; disambiguate the app-user and guest-actor names.

### Typed models, method signatures, and validation rules are names only — Severity: Blocker

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 612, 619–627, 630–645; feature spec 312–335
* **Discrepancy Description**: `models.py` claims "Field-complete" models but lists only type names. `CommandResult`, `HttpResult`, `Manifest`, `Artifact`, `ClassifiedLog`, `LlmVerdict`, `VmProfile`, and `RunLimits` are consumed by broker verbs, the fake driver, tests, and the budget, but no field names, types, required/default flags, or validation errors are given. `RunnerContext`, `AttackerContext`, and `ProbeEvidence` in the feature contract are field-name lists without types or requiredness and are omitted from the models row. `web/schemas.py` is a name only. This is revision-2 Stage 9 Blocker 5: resolved structurally, still open in substance.
* **Rationale & Recommendation**: The implementer must design every wire and persistence type, which is a direct Zero-Decision Rule violation. Add one field table per model (name, type, required, default, validation error) and full method signatures with parameter and return types for the broker client, `VmDriver`, validator, extractor, and API schemas; replace "Field-complete" with a pointer to the authoritative schema.

### Target instances, artifact/package pins, and setup-script contents have no values — Severity: Blocker

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 583–606, 613, 643; feature spec 239–246, 281–310
* **Discrepancy Description**: `src/xentry/targets.py` is "Three `Target` instances" (250 lines) with no per-target image/kernel artifact id, vCPU/memory/disk, PoC repository/commit/files/SHA-256, build/invocation step, nonce path/owner/mode, probe kind/parameters/timeout, null-actor step id, or `what_proves`. `config/artifacts.yaml` and `config/packages.yaml` have no values, key schema, or provenance format; the PoC repositories and commits are named nowhere. `Target.poc` and `config/artifacts.yaml` both pin the PoC with no precedence rule. The three setup scripts are one-line deliverables ("Hand-reviewed PHP 8.4.26/Apache build," "Pinned GitLab 19.2.5 Omnibus install," "Pinned kernel, reboot, `uname -r`, gcc/make") with no package sources, mirror URL parameter, build steps, readiness command/output/timeout, reboot wait logic, nonce path/mode actions, or `setup_sha256` source.
* **Rationale & Recommendation**: A fresh implementer must invent the acceptance-critical configuration for all three targets, violating the Zero-Decision Rule. Add per-target field tables with exact values, publish both YAML schemas and the PoC-pin precedence rule, and add a step outline per setup script plus the readiness contract consumed by the `provision` and `readiness` steps. Keep the mirror URL a typed step parameter so the script hash stays stable.

### The runner step contract is missing — Severity: Blocker

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** DetailedRange 613–614, 619, 623, 639, 657; feature spec 248–279, 286–304
* **Discrepancy Description**: `runner.py` is budgeted at 450 lines but described only as "Ordered steps, attempts, timeouts, cleanup, validator call." The text says each step has a guard, timeout, and cleanup action, but none is enumerated. There is no mapping of step to command template, typed parameters, allowed user, retry classification, emitted evidence, or failure routing. `Target.timeouts` is literally `{...}`, "classified infrastructure failure" has no classifier, and no rule says when an attempt row is created or what it copies. The cleanup transition ("goes from the current step to cleanup") does not define which destroys run, in what order, with what timeout, or what happens when `cleanup_state=failed`.
* **Rationale & Recommendation**: The implementer must invent the pipeline core. Add a step table (seq, name, guard, timeout, cleanup, retries, failure code, evidence) for all three targets, a retry classification table with closed reason codes, a cleanup step sequence with timeouts and terminal states, and attempt-creation/reuse rules; align `test_steps.py` with the enumerated outcome set.

### No closed failure/reason-code contract (G11) — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** DetailedRange 619, 626–627, 656–672; DDL 363, 372, 381, 406; CUJ 4
* **Discrepancy Description**: G11 requires a closed code and next action for every failure, but the plan contains no code list; `null_actor_failed` is the only named code. `security_cleanup_failed` is named in CUJ 4 but absent from the code set. The three DB columns (`reason_code`, `failure_code`) have no aligned enum.
* **Rationale & Recommendation**: Add one shared enum with trigger, discriminator, retryable flag, next action, and outcome/verdict projection, covering egress, hash mismatch, snapshot/restore, mirror, nonce placement, preflight, validator error, teardown, cancellation, and cleanup failure; align the DB columns.

### Test plan lists areas, not executable test cases; fixtures and gating are undefined — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 655–674, 690–704; Gate F 118
* **Discrepancy Description**: Each test row is a category ("Step order, guards, outcomes"; "Nonce clamp, authority, evidence refs") with no setup, action, or expected assertion. The fixture directory has no schema or label format for the 20 validator, 20 extractor, and 5 known-fail fixtures; `tests/fixtures/` is a 300-line budget for 40-plus fixtures. The `test_vm_libvirt.py` gating marker/environment variable and `run_target_e2e.py` behavior are undefined. Missing tests include migration/backup-restore/newer-schema refusal, API route/error-envelope/status-code, preflight admission, host-evidence tamper, and broker unknown-id rejection. The verification plan mixes five runnable commands with eight comma-separated noun lists that have no pass condition or owning test. Gate F says 20 fixtures while acceptance says 19/20 plus 100% citation.
* **Rationale & Recommendation**: Enumerate test cases per file (happy path and edge cases), define fixture JSON schemas and labels, state the skip marker and command, specify the real-VM acceptance runner's inputs/evidence/pass-fail checks, and map each verification bullet to a test.

### API, token, check-store, and error-envelope contracts are explicitly deferred — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 616, 630–634, 654; feature spec 431–451
* **Discrepancy Description**: Feature-spec line 449 says the token delivery mechanism "is chosen in implementation," a direct Zero-Decision violation. `check_id` has a TTL and single-use rule but no value, store, or persistence; `POST /api/links/check` returns it and `POST /api/jobs` consumes it, with no restart behavior. The "single error envelope" has no schema or HTTP status map; `web/schemas.py` is a name only. Token delivery appears in five rows while none chooses a mechanism.
* **Rationale & Recommendation**: Choose one token mechanism and specify cookie/header names, entropy, rotation, and CSRF binding; define the error envelope JSON and status table; define check TTL, single-use enforcement, storage, and restart behavior; give request/response models.

### The binding budget gate cannot be computed or enforced — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 585–587, 656, 680, 693; budget rules 63–84
* **Discrepancy Description**: The headline fits (40/40 modules, 5,390 of 8,000 lines, 14 weeks), but line 83 says each component's allocation is recorded in the file table while the table has no component column or file-to-component map. The allocations sum to exactly 8,000 while file estimates sum to 5,390; the approximately 1,740 non-Python lines have no named budget dimension, and "templates and static 1,500" is either 710 or about 2,450 depending on interpretation. `test_budget.py` is described inconsistently (modules and lines at line 82; modules, lines, and dependencies at 656 and 693), the dependency-count rule is undefined, the module cap is consumed exactly (40/40) with no headroom for the registry fix, and no test checks per-component totals.
* **Rationale & Recommendation**: Add a component column or file-to-component map consumed by `test_budget.py`, define line/dependency/non-Python counting rules, and state an exact-cap or headroom policy.

### Mirror/offline provisioning and the attacker image are not implementable as specified — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** DetailedRange 577, 594, 599–600, 604–606; feature spec 234–246
* **Discrepancy Description**: The mirror address is `10.<slot>.0.1:8081` with `<slot>` undefined while the setup scripts are hash-pinned; a script cannot embed a varying address without changing its hash, and no typed `mirror_url` parameter is defined. A directory of `.deb` files is not an apt repository: no `Packages.gz`/`Release` generation, guest trust (`trusted=yes` or key), or dependency closure is specified, and `apt-get download <pkg>` does not resolve dependencies, so the PHP and GitLab dependency sets cannot be populated. The attacker image "preinstalls Go and Python `requests`," but the file table has only download/hash steps and no image-build script; a stock Ubuntu cloud image has neither. `fetch-artifacts.sh` has no CLI, inputs, vendor-seed source, or refusal/exit behavior for a missing out-of-band hash.
* **Rationale & Recommendation**: Fix a subnet/mirror address or make it a typed `mirror_url` step parameter; specify apt index generation, trust, and dependency closure; add an attacker image-build step or hashed prebuilt images; publish the fetch-script CLI and exit codes.

### Dirty Frag's null actor is non-probative; host-evidence semantics and fresh-boot checks are missing — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** DetailedRange 645, 701; feature spec 88, 259–268, 308–310, 341
* **Discrepancy Description**: The nonce is `/root/xentry-nonce` mode 0600 owned by root; the null actor runs as `xentry`, so it cannot read the nonce regardless of the exploit. Acceptance still counts "the null actor does not observe the nonce" as a causal check, and the null-actor record has only a target-side observation, not a host-channel one. `read_host_evidence` has no channel enum, serial/QMP mechanism, capture timing, or null-run observation. Step 13 fresh-boots for the real run, but steps 14–15 place the fresh nonce and run the real actor without a post-boot `uname -r`/readiness check; the real-run kernel evidence is from the pre-null boot. Gate C's tamper analysis has no file or step in the plan.
* **Rationale & Recommendation**: Define the null actor as "the same wrapper without the exploit must not produce a host-channel root shell or a root nonce read," record that host-channel observation, add a post-fresh-boot readiness/version check, specify the channel mechanism and timing, and add the tamper-analysis deliverable.

### Cleanup and orphan identification are undefined — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** DetailedRange 621; `list_managed` 225; CUJ 5 153
* **Discrepancy Description**: There is no domain/network naming rule, overlay/ISO path layout, `list_managed` result schema, sweep ordering, or idempotency rule for the startup orphan sweep.
* **Rationale & Recommendation**: Specify naming prefixes or metadata tags, storage paths, `list_managed` fields, sweep order, and the interrupted-job transaction.

### Database schema and migration contract is incomplete — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`
* **Affected Scope:** DetailedRange 595, 608–611, 615; DDL 358–427, 429, 437; feature spec 82, 355
* **Discrepancy Description**: `db.py`, `scripts/migrate.py`, and `migrations/` all claim migration responsibility with no split. SQLite is called rebuildable, but no rebuild command or file exists. `jobs` has no `verdict` or `authority` column, yet line 429 says a null-actor failure writes `verdict=not_run`, `authority=runner_observed`, and no validation row, and `GET /api/jobs/{id}` promises both; `validations` is the only source and requires a nonce and a row. `validations.authority` includes `runner_observed`, but no validation row can carry it. `job_steps.state`, `broker_calls.status`, and `artifacts.kind` have no CHECKs, foreign keys are unindexed, `PRAGMA foreign_keys` is unstated, and `jobs.final_attempt_id` has no FK.
* **Rationale & Recommendation**: Name one migration owner and the others' roles, add a rebuild-index command, add `job_outcomes` or `jobs.verdict`/`jobs.authority` plus projections for completed/failed/cancelled/interrupted/null-actor/validator-error, and publish indexes, CHECKs, and the pragma in `001_initial.sql`.

### Two nonce placements share one nonce slot — Severity: Major

* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** DetailedRange 259–268 (steps 10 and 14), 373–375, 407, 429
* **Discrepancy Description**: The step list places an initial nonce after the freeze and a fresh nonce after restore/reboot, but `attempts` has a single `nonce_id/nonce_sha256/nonce_path/nonce_owner/nonce_mode/nonce_created_at`. There is no rule for whether the fresh nonce overwrites the initial one, how the null-actor probe stays tied to the nonce it tested, or which nonce `validations.nonce_id` references; the initial nonce identity would be absent from the audit index.
* **Rationale & Recommendation**: Add a `nonces` table keyed by `(attempt_id, phase)` or nonce ids on `job_steps`/`ProbeEvidence`, and state the overwrite/reference rule.

### Security implementation details and AppArmor/seccomp ownership are absent — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** DetailedRange 616, 630, 592–593; Gate B 114
* **Discrepancy Description**: Token format/entropy, cookie and header names, Origin/Host allowlist, CSP string, redaction patterns and targets, and SSH key lifecycle are unspecified. Gate B requires AppArmor/seccomp active, but no file in the plan creates or installs the AppArmor profile or seccomp policy.
* **Rationale & Recommendation**: Specify each item and add the policy file and install step to the file table.

### Host and broker deployment ownership is unstated — Severity: Major

* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** DetailedRange 228, 578, 592–593, 621, 682–688
* **Discrepancy Description**: The broker runs as root and the app as `xentry`, but the plan does not state who owns the broker code, `.venv`, config, job directories, overlays, ISOs, or the artifact/evidence store. `uv sync --extra app --extra broker` creates one app-owned environment, so a root broker executing `broker/main.py` from it is a root-escalation path. The broker contract says every verb writes a `broker_calls` row, but the broker package has no DB layer and SQLite is app-owned, so the writer and DB permissions are undefined. `deploy/xentry-broker.service` is only "Root broker unit, restricted filesystem/caps"; its `User`, `ExecStart`, `EnvironmentFile`, `ReadWritePaths`, `ProtectSystem`, and capability set are unspecified. WSL2 prerequisites omit AppArmor although Gate B requires it; the "tested on libvirt 12/QEMU 10.2.1" versions are not in Ubuntu 24.04.4; the 10/6/3 GB figures are guest memory with no host headroom.
* **Rationale & Recommendation**: Specify root-owned broker code/venv/config with app read-only, job-dir/overlay/ISO ownership and cleanup, the `broker_calls` writer and DB permissions, systemd hardening, and AppArmor/version/headroom requirements.

### Phases and gates are not executable or internally consistent — Severity: Major

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 706–714; Gates A–G 109–121
* **Discrepancy Description**: No file or test is mapped to a phase, and no phase exit check is given. Phase 0 packs broker, network, mirror, two-VM smoke, AppArmor, three target builds, extractor gate, provenance, and host evidence into two weeks. Gate A (PHP2Shell and GitLab pass the nonce/null-actor test on one target VM) requires Phase 1 runner/nonce/null-actor code and cannot run in Phase 0. Phase 2 lists "attacker VM reuse" as new work although Phase 1 already requires PHP2Shell end to end with an attacker VM, and "reuse" is undefined against "every path destroys both VMs." Phase 3 repeats Phase 0's Dirty Frag builds/host evidence, and Phase 4's "upgrade/restore" has no migration test or restore tooling. Gate A/C are non-gates (the attacker VM and `guest_attested` authority remain regardless), Gate F says 20 fixtures while acceptance says 19/20, and Gate E offers a no-op. Acceptance shorthand drops qualifiers: "two clean runs" loses "consecutive" and the four conditions at line 88; "null actor no nonce" can mean the nonce was not placed rather than not observed; "no orphan" does not name domains/networks/overlays/ISOs; "the stated limit" has no antecedent.
* **Rationale & Recommendation**: Map every file/test to a phase, define exit checks, move Gate A to Phase 1 or define the Phase 0 harness that executes it, make Gates A/C true gates or label them measurements, align Gate F, define or delete "attacker VM reuse," and restore the dropped qualifiers in acceptance criteria.

### Reuse of existing QEMU/evidence/LLM code is not evaluated; ADK has no load-bearing V1 consumer — Severity: Major

* **Reviewer Lens:** `egm-codebase-details`, `egm-implementation-readiness`
* **Affected Scope:** DetailedRange 583–680, 706–714; feature spec 98–107, 349–351, 508–512, 558–563
* **Discrepancy Description**: The prior tree has `/home/zran/ambitious_projects/xentry/src/xentry/verify/vm.py` (~995 lines with overlay creation, `savevm`/`loadvm`, SSH exec, provisioning, and PoC attempts), `/home/zran/ambitious_projects/xentry/src/xentry/evidence/store.py` (content-addressed, ~114 lines), and `/home/zran/ambitious_projects/xentry/src/xentry/llm.py` (~80 lines, OpenAI-compatible). The plan adds about 1,900 lines of broker/VM code and ADK/LiteLLM, but Phase 0 has no reuse spike and the file table and Additional Resources cite none of these. All three targets are fixed typed instances with `expected_version`, `version_probe_command`, probes, and pinned PoCs, so the extractor's facts are fixed or redundant and its only V1 output is the non-authoritative agent summary, yet the plan budgets `agent.py`, `prompts/extract.md`, 20 fixtures, Gate F, the token cap, and DeepSeek egress. The Decision Record and `docs/adr/0001-v1-reset.md` do not mention ADK or the prior ADR 0007 reversal (explicit Python, no model tools). `agent.py` promises a "direct LiteLLM fallback" with no config key or runtime condition selecting it.
* **Rationale & Recommendation**: Add a Phase 0 reuse spike behind `VmDriver`/`FakeDriver`; either delete the extractor/ADK path or record the reversal in ADR 0001 and name the V1 decision the extractor feeds; align Gate F; state the LiteLLM fallback switch, default, and equivalence test.

### Closed-set values and field names drift — Severity: Major

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** DetailedRange 649, 670, 701, 711; feature spec 88, 343, 361, 366, 380, 411, 437
* **Discrepancy Description**: The job-level field is "state" in the UI and vocabulary rows but `outcome` in storage and the API, while `job_steps.state` is a different field; no mapping is given. The verification bullet writes `guest_attested` for a value the CHECK constrains to `guest_attested+llm_assessed`; the hyphenated "guest-attested authority" at line 711 repeats the drift.
* **Rationale & Recommendation**: Publish one field-name mapping (UI/API/storage) and use the exact CHECK value `guest_attested+llm_assessed` everywhere.

### "Fixed defaults" and "Host prerequisites" duplicate with drift — Severity: Major

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** DetailedRange 576–578, 587, 596, 684–686, 692
* **Discrepancy Description**: The two sections restate the same host, users, and dependencies with drift: line 577 gives libvirt 10+ and ssh-keygen, line 684 gives libvirt-daemon-system and openssh-client with no version; line 686 lists uvicorn in both App env and Dev, line 576 omits it from the app list; line 587 defines app/broker extras, while line 692 syncs `--extra dev`. No precedence rule is given. The same section uses semicolon fragments ("target + attacker for remote"), and line 580 mixes a product version, a kernel string, and a language version without labels.
* **Rationale & Recommendation**: Consolidate into one authoritative prerequisites section, remove the duplicate, and label version pins by component.

### `sources.py` "generic fallback" is undefined and may contradict scope — Severity: Major

* **Reviewer Lens:** `egm-style`, `egm-codebase-details`
* **Affected Scope:** DetailedRange 623, 664; feature spec 28, 42–46, 155–159
* **Discrepancy Description**: `sources.py` requires "Three fixed CVE inputs ... generic fallback," but G2 rejects unsupported sources/CVEs/PoCs and the Non-Goals exclude general CVE coverage. "Generic fallback" is undefined: it could be a source-shape adapter for the same three CVEs or a general path that violates scope.
* **Rationale & Recommendation**: Define the fallback as a parser/shape adapter for the three fixed sources with explicit rejection behavior, or remove it.

### Duplicate ownership between file rows — Severity: Nit

* **Reviewer Lens:** `egm-implementation-readiness`, `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 616–621, 632, 637
* **Discrepancy Description**: Two rows claim CSP (`security.py`, `base.html`), two claim SSE backfill (`events.py`, `web/sse.py`), and `src/xentry/broker.py` ("Fixed-verb broker client") and `src/xentry/vm/broker_driver.py` ("Broker-backed driver") both implement the socket client while the feature contract says `BrokerClient` is the only `VmDriver` implementation. `queue.py` (recovery) and `cleanup.py` (interrupted jobs/orphans) overlap. No precedence or transport/adapter split is stated.
* **Rationale & Recommendation**: Name the owning module for each concern and state which layer owns framing/peer checks versus `VmDriver` adaptation.

### Event and audit-bundle schemas are unspecified — Severity: Nit

* **Reviewer Lens:** `egm-implementation-readiness`
* **Affected Scope:** DetailedRange 617, 627
* **Discrepancy Description**: The JSONL event schema, SSE event names/id semantics, heartbeat interval, and audit-bundle contents/hash-manifest format are undefined.
* **Rationale & Recommendation**: Give the event type table and the bundle file list with hashes.

### `.env.example` retains obsolete app-side libvirt and setup-attempt settings — Severity: Nit

* **Reviewer Lens:** `egm-codebase-details`
* **Affected Scope:** DetailedRange 590; existing `/home/zran/ambitious_projects/xentry_claude/.env.example` lines 22–30
* **Discrepancy Description**: The existing file sets `XENTRY_LIBVIRT_URI=qemu:///system`, `XENTRY_VM_MEMORY_MB`, `XENTRY_VM_VCPUS`, `XENTRY_VM_DISK_GB`, `XENTRY_MAX_SETUP_ATTEMPTS=3`, and `XENTRY_MAX_POC_ATTEMPTS=3`. The plan's Modify row says "Broker socket, artifact catalog, caps, absolute paths" but does not say to remove these; they contradict "the app never joins libvirt," "resources live in `Target` instances," and "no setup repair in V1."
* **Rationale & Recommendation**: Add the deletions to the required contents.

### Undefined shorthand and overloaded terms — Severity: Nit

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** DetailedRange 590, 593, 611, 615, 628, 651, 663, 672, 687
* **Discrepancy Description**: "Caps" means budget/limit caps in `.env.example`, `config.py`, `system.html`, and the SSRF test, but Linux capabilities in `deploy/xentry-broker.service`. "Modes" (611), "projections" (615), "bind" (628), and "gated" (672) have no definition. "Per-job caps above" (687) has no antecedent in this section; the per-job values are at lines 73–74.
* **Rationale & Recommendation**: Define or rename each term and add the missing antecedent.

### Unverifiable quality adjectives — Severity: Nit

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** DetailedRange 604, 612, 653
* **Discrepancy Description**: "Hand-reviewed" (604) and "Accessible layout" (653) are unverifiable: the plan has no review record or gate, and no accessibility standard or test. "Field-complete" (612) is the same pattern; its substantive gap is covered as a Blocker above.
* **Rationale & Recommendation**: Replace with a named review artifact and a measurable accessibility criterion, or drop the claims.

### File-operation metadata and self-referential cells — Severity: Nit

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** DetailedRange 590–591, 597, 677–678
* **Discrepancy Description**: `.env.example` and `.gitignore` are marked "Modify" with no create-if-absent rule for a repository the plan otherwise creates. The `docs/designs/xentry-v1.md` row's required contents is "This revision." (a self-reference), `SITEMAP.md` says "Register revision 3" without defining "register," and `scripts/preflight.py` is "CLI preflight wrapper" (circular).
* **Rationale & Recommendation**: State create/modify semantics explicitly and replace self-referential content descriptions with concrete deliverables.

### Change-control rule is not actionable — Severity: Nit

* **Reviewer Lens:** `egm-style`
* **Affected Scope:** DetailedRange 714
* **Discrepancy Description**: "Phase 0 failures revise the plan" has no actor or artifact; "any further growth" is unquantified (lines, modules, weeks, scope?); "an ADR entry" does not say whether it means a new ADR or an amendment to ADR 0001.
* **Rationale & Recommendation**: Name the owner, artifact, thresholds, and whether ADR 0001 is amended.

### Residual deliberative prose and unit ambiguity — Severity: Nit

* **Reviewer Lens:** `egm-codebase-details`, `egm-style`
* **Affected Scope:** DetailedRange 72–75, 117, 279
* **Discrepancy Description**: Line 279 still contains "one attempt may have one setup repair? No."; Gate E offers "Reduce concurrency (already one)"; "Dirty Frag 3 GB (2 + host evidence)" mixes units. The per-call token cap has no value.
* **Rationale & Recommendation**: Replace with declarative statements and give the values and units.
