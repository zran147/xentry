# Goldfish Review Report — Initial Zoom Out Review (Revision 3)

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (lines 1–714; FeatureRange 1–571, DetailedRange 572–714)
**Mode:** REVIEW
**Standard:** `/home/zran/.claude/plugins/cache/egm/egm/0.1.0/resources/document_standards/zoom-out-standard.md`

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm:egm-zoom-out` | completed |

## Summary

One reviewer instance ran; its findings are reported below with no cross-reviewer deduplication required.

- **Context sufficiency:** Pass. The document defines the objective, root problem, three targets, two-VM topology, owner decisions, budget, CUJs, architecture, alternatives, and implementation plan.
- **Root-problem focus:** Pass with one divergence. The runner-owned nonce, null actor, destroy-before-validate ordering, fresh boot, and independent validator serve the causal question directly; the ADK extractor does not.
- **Simplicity/YAGNI:** Partial. The ordered step list, typed Python `Target` instances, and extractor-only ADK are genuine simplifications, but the ADK extractor and artifact mirror remain avoidable surfaces, and the broker is now the largest trust surface.
- **Anti-weeds:** Pass. The feature range stays at architecture, interfaces, data flow, and contracts; per-file budgets, DDL, and routes sit in the detailed range.
- **Leverage of existing infrastructure:** Fail at Major level. A working direct-QEMU harness, content-addressed evidence store, and DeepSeek client exist in the prior tree but are not evaluated or cited; revision 3 adds a new broker/VM stack and ADK/LiteLLM instead.
- **Budget:** The headline plan now fits — 40/40 modules, 5,390 of 8,000 handwritten Python lines, 14 weeks — but coverage and enforcement are incomplete (Major 1).
- **Revision-2 scope/budget Blockers:** B-01 and B-02 are resolved. Contract Blockers B-03 and B-07 retain residual blockers (broker registry/probe verb; privilege separation and Dirty Frag null actor).

**Totals: 2 Blockers, 9 Majors, 8 Nits.**

### Revision-2 Blocker Disposition

| Rev2 Blocker | Status in revision 3 | Evidence |
| --- | --- | --- |
| B-01 Budget exceeded | Resolved for Python/modules/weeks | 40/40 modules, 5,390/8,000 lines, 14 weeks; per-component allocations fit. Residual coverage gap is Major 1. |
| B-02 Two-VM/broker gates, ADR, budget | Resolved | Decision Record at lines 98–107; Phase 0 Gates A–G at 109–121; broker and VM budget lines at 66; Gate B at 114; ADR deliverable at 675. Residual non-gates are Major 7. |
| B-03 Broker verb/privilege/transport | Mostly resolved | Fixed verbs at 206–226, socket identity at 204, QEMU user at 230, SSH transport at 232, typed step ids at 228, `VmDriver`/`BrokerClient` at 322–335. Residual registry and probe-verb gap is Blocker 1. |
| B-04 State machine | Resolved | Ordered steps at 248–279; `jobs.outcome` and `cleanup_state` at 277; destroy-before-validate at 273–277. |
| B-05 Pack/probe/types | Resolved in structure | Typed Python `Target` instances at 283–310; `target_ports`, decisive probe, `nonce` spec, optional attacker/kernel. Residual field-completeness nit. |
| B-06 Checked-in scripts/hash/null actor | Resolved | No setup repair at 76 and 279; hash-checked at 304; null actor "must not observe" at 341 and 88. Residual `null_actor_failed` naming is Nit 2. |
| B-07 Dirty Frag flow/evidence | Mostly resolved | PoC-spawned root shell at 310; fresh boot at 265; `guest_attested+llm_assessed` at 11, 310, 343. Residual privilege/sudo gap is Blocker 2; null-actor/post-boot gap is Major 6. |
| B-08 Network/mirror/offline | Mostly resolved | Mirror address/port at 239; provisioning/default-deny phases at 244; package catalog at 246; vendor provenance at 119 and 594. Residual mirror/prebuild and slot/hash-pinned-script issues are Majors 4 and 8. |
| B-09 Nonce identity/boundary | Resolved | `attempts` nonce columns at 373–375; `validations.nonce_id` at 407; `place_nonce` at 218; split contexts at 314–315; value never stored at 339–342; `test_noncode_secret.py` at 661. |

## Prioritized Findings (Blockers -> Major -> Nits)

### 1. Broker has no broker-owned target/step registry and no trusted HTTP-probe verb — Severity: Blocker

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Broker contract (204–232); Interfaces (322–335); Probe evidence contract (312–318); Isolated network (234–246); file table entries `src/xentry/targets.py` (613), `src/xentry/vm/probes.py` (639), `broker/profiles.py` (646).
* **Discrepancy Description:** `exec(vm_id, step_id, params, tty, timeout)` maps `step_id` to a command template "in the target definition," but target definitions live in app-side `src/xentry/targets.py`; the broker has no target/step registry. If the app sends the template in `params`, the broker is an arbitrary-command proxy again; if the broker keeps a copy, steps, users, resources, and images have two sources of truth. `start_target(...)` and `start_attacker(...)` accept app-chosen ids, and `broker/profiles.py` is described only as "Domain XML, image resolution, guest IP," not as a validated broker-owned catalog. Separately, `HttpProbe` is listed as broker-internal, but the fixed verbs and `VmDriver` expose no `http_probe` method, host-route is none, and `exec` is guest SSH: the only trusted target-side observation path for remote nonces has no call path, while app-side `vm/probes.py` duplicates it.
* **Rationale & Recommendation:** This is both a trust gap (unvalidated command/id resolution) and a two-source-of-truth design. Define one broker-owned registry for target/profile/step/image/artifact ids with hashes, typed parameters, and allowed users; resolve every id server-side and reject unknown ids. Add `http_probe(network_id, target_ip, port, method, path, timeout, max_bytes) -> HttpResult` to the fixed verbs and `VmDriver`. Delete the app-side probe duplicate or define it as the plan builder only. Add a broker-contract test that unknown step/image/profile ids are rejected and that the app cannot send a raw command.

### 2. Privilege model does not separate provisioning root from the actor, and "root only Dirty Frag" contradicts target setup — Severity: Blocker

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** G7 (33); broker contract (228); Target definitions (304–310); Dirty Frag (310); Security and threat model (455–459); Gate B (114); host prerequisites (685).
* **Discrepancy Description:** PHP2Shell and GitLab setup (apt installs, PHP build, GitLab Omnibus) need root in the target, but the broker allows root only for Dirty Frag setup/probe steps. If the setup scripts run as `xentry` with passwordless sudo, the PoC can escalate without the exploit, making Dirty Frag's root shell and the null-actor check non-probative. If they run as root, the broker rule is false. The design never states the provisioning user, the sudo policy, or whether `xentry` can write root-owned paths.
* **Rationale & Recommendation:** One privilege model is simpler and safer than a per-target exception. Add a `provision_user=root` path for all three hash-pinned setup scripts, allowlisted by step id rather than by target. Define `actor_user` as a non-sudo user with no writable root-owned paths, no setuid/sudo/pkexec, and no shared SSH key. Add a test that `xentry` cannot run `sudo -n true`, read `/root/xentry-nonce`, or write the service binary, and add the sudo/actor-separation checks to Gate B.

### 3. Budget clears the Python plan but is not a complete or enforceable match — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** V1 Scope and Budget (59–95, especially 66–67 and 80–84); file table (585–680).
* **Discrepancy Description:** The headline numbers fit, but the module cap is consumed exactly (40/40), leaving no headroom. About 1,890 non-Python, non-test lines (`config/` 240, `prompts/` 230, `targets/*/setup.sh` 390, `migrations/` 180, `docs/` 290, `deploy/` 70, `README.md` 200, `pyproject.toml` 40, `.env.example`/`.gitignore` 60) are either outside the named dimensions or push "templates and static" to about 2,600 against its 1,500 cap. The per-component allocations are not recorded in the file table as line 83 claims (`broker/network_ops.py`, `broker/exec_ops.py`, `broker/host_evidence.py`, and `broker/profiles.py` fit multiple components), and the 8,000 cap is 2,610 lines above the per-file estimate (3,945 + 1,225 + 220 = 5,390). Several allocations are roughly twice their mapped files (Web/API/UI 1,200 vs about 595; extractor/validator 650 vs about 270).
* **Rationale & Recommendation:** A budget that cannot be mapped to files is not a binding control, and a 33 percent contingency invites the growth it is meant to bound. Add a component column or a file-to-component map consumed by `tests/test_budget.py`. Add a non-Python budget line and state whether "templates and static" includes config, prompts, setup scripts, migrations, and docs. Set the module cap to 44–46 or state the exact-cap rule. Derive the cap from the 5,390 sum plus a stated contingency rather than an 8,000 ceiling.

### 4. ADK extractor has no load-bearing V1 consumer, and the ADR 0007 reversal is not recorded — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Overview (9); Extractor (349–351); budget (66, 69); file table (601–603, 625, 667); Gate F (118); Alternatives 6 (520–524); Decision Record (98–107); ADR (675).
* **Discrepancy Description:** All three targets are typed instances with `expected_version`, `version_probe_command`, ordered probe steps, and a pinned PoC. The extractor's facts (product, range, version evidence, ports, auth, build strategy) are fixed or redundant with the `Target`; the only V1 output is the non-authoritative agent summary. V1 still pays for `google-adk` + `litellm`, extract prompts, 20 fixtures, a Phase 0 gate, the 150k token cap, DeepSeek egress, and the prompt-injection surface. The prior tree's ADR 0007 (`/home/zran/ambitious_projects/xentry/docs/decisions/0007-llm-orchestration.md`) chose explicit Python and said "do not give the model tools"; the brief required a new ADR for a reversal, but the Decision Record does not mention ADK.
* **Rationale & Recommendation:** For V1, delete `agent.py`, the extract prompts and fixtures, the extractor gate, and the ADK dependency; derive target/CVE/PoC identity deterministically from the three fixed source shapes and `Target` instances, and keep the direct-LiteLLM validator. If ADK is retained, record the reversal in ADR 0001, name the V1 decision the extractor feeds, and add a test that the pipeline is identical with a deterministic stub.

### 5. Existing QEMU harness, evidence store, and DeepSeek client are still not evaluated or cited — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Alternatives 4 (508–512); Additional Resources (558–563); file table (620, 624–625, 635–646).
* **Discrepancy Description:** The prior tree has `/home/zran/ambitious_projects/xentry/src/xentry/verify/vm.py` (about 995 lines with overlay creation, `savevm pre-poc`/`loadvm`, SSH exec, provisioning, PoC attempts, and a pre-PoC cache), `/home/zran/ambitious_projects/xentry/src/xentry/evidence/store.py` (about 114 lines, content-addressed), and `/home/zran/ambitious_projects/xentry/src/xentry/llm.py` (80 lines, DeepSeek-compatible). Revision 3 adds about 1,900 lines of broker/VM code (broker 1,225 + vm 525 + broker client 150) and ADK/LiteLLM, but Alternative 4 only says "Direct QEMU remains a reuse candidate if the broker gate fails." There is no Phase 0 reuse spike and no citation. The prior harness's Docker provision proxy conflicts with the no-container rule, but its QEMU, overlay, snapshot, and SSH pieces do not.
* **Rationale & Recommendation:** Add a Phase 0 reuse spike: run the prior `vm.py` behind `VmDriver`/`FakeDriver`, compare it to the broker for the two-VM network case, reuse the `evidence/store.py` shape, and evaluate the 80-line client against ADK/LiteLLM. Cite the prior files in Additional Resources. If the broker is kept, record why the harness cannot be ported.

### 6. Artifact mirror is the largest new host service, and prebuilt target images are never compared — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Isolated network and artifact mirror (234–246); budget (66, 73); broker verbs (210–211); `config/packages.yaml` (600); `scripts/fetch-artifacts.sh` (594); Gate B (114); risk table (468–477).
* **Discrepancy Description:** The mirror adds a broker-managed HTTP service on the bridge gateway, a package catalog, an apt snapshot, two broker verbs, a provisioning-vs-default-deny phase, and an egress test. The targets are fixed. Prebuilding one image per target (or a base plus package layer) at image-build time would remove the mirror, `config/packages.yaml`, the mirror lifecycle, and the runtime apt path, and would fold the package set into the image hash. The design already has hash-pinned setup scripts and a base-image artifact id. The revision-2 report offered prebuild as the first option; revision 3 chooses the more complex mirror without comparing it.
* **Rationale & Recommendation:** Add a "prebuilt target image" alternative: build the packages into each target image, pin the image hash, and keep the setup script for runtime configuration. If the mirror stays, state why prebuild fails (GitLab Omnibus size, kernel install, image build time), and add the mirror to the component and risk tables.

### 7. Authority/verdict projection for failed, cancelled, interrupted, and null-actor jobs is undefined and unstorable — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** DDL `jobs` (358–368), `validations` (402–414); Storage and audit (429); API `GET /api/jobs/{id}` (437); CUJs 3–5 (137–153); G10 (36).
* **Discrepancy Description:** `jobs` has no `verdict` or `authority` column. `validations` is the only verdict/authority source and requires a nonce id. A null-actor failure "writes outcome = failed, verdict = not_run, authority = runner_observed … and no validation row," but there is nowhere to write verdict/authority, and the API promises them for every job. `validations.authority` includes `runner_observed`, but no row can carry it. The design defines only the null-actor failure; cancelled, interrupted, and other failures have no projection. Revision-2 M-01 remains partly unresolved.
* **Rationale & Recommendation:** Add `jobs.verdict` and `jobs.authority` (nullable), or a `job_outcomes` table with `(job_id, attempt_id, outcome, verdict, authority, reason_code, ts)` written for every terminal outcome. Define a projection table for completed, failed, cancelled, interrupted, null-actor, and validator-error. Remove `runner_observed` from `validations.authority` if it is only for no-row outcomes.

### 8. Dirty Frag null actor is vacuous, and the real run after fresh boot does not re-check the kernel — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Dirty Frag (310); Nonce and null actor (339–343); acceptance (88); CUJ 2 (131–135); steps 7/13/14/15 (259–268); Probe evidence contract (312–318).
* **Discrepancy Description:** The nonce is `/root/xentry-nonce` mode 0600; the null actor runs as `xentry`; it cannot read the nonce regardless of the exploit. "Null actor does not observe the nonce" is guaranteed by file permissions, not by the absence of the exploit, yet acceptance still counts it as a causal check. Separately, step 7 does the version/precondition check before the null actor; step 13 fresh-boots for Dirty Frag; steps 14 and 15 place a fresh nonce and run the real actor without a post-boot `uname -r` or readiness check. The real-run kernel evidence is from the pre-null boot.
* **Rationale & Recommendation:** Define the Dirty Frag null actor as "the same wrapper without the exploit, run as `xentry`, must not produce a host-channel root shell or a nonce read." Do not use the root-only nonce as the null-actor check. Add a post-fresh-boot readiness + version/precondition step (or fold it into step 13), record the post-boot `uname -r` in the attempt, and make the null-actor evidence include the host-channel observation, not only the target-side boolean.

### 9. Phase 0 gates are partly non-gates, and gate/acceptance numbers disagree — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Decision Record and Phase 0 Gates (109–121); acceptance (86–94); Extractor (351); Phases (706–714).
* **Discrepancy Description:** Gate A's failure action ("The attacker VM remains an isolation choice; record the weaker causal claim, or re-scope") does not change the plan; the attacker VM stays whether the one-VM test passes or fails, so it is a measurement, not a gate. Gate C's exit criterion is only "tamper analysis states whether the guest can forge it"; the design already uses `guest_attested+llm_assessed`, so the gate cannot fail or change acceptance. Gate F says "passes 20 fixtures" while the acceptance/extractor says "at least 19 of 20" and 100 percent citation.
* **Rationale & Recommendation:** Either make Gate A a true gate (if the one-VM test passes, drop the attacker VM or state that the owner decision overrides it; if it fails, keep the attacker VM and state the causal role) or label it "Phase 0 measurement, no plan effect." Make Gate C a precondition for Dirty Frag `reproduced`, or delete it and rely on the declared `guest_attested` authority. Align Gate F to 19/20 plus 100 percent citation.

### 10. Job slot is still undefined, and hash-pinned setup scripts cannot use a varying mirror address — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** Isolated network (236–246); Target definitions (286–304); setup scripts (604–606); budget (70).
* **Discrepancy Description:** `10.<slot>.0.0/24`, target `10.<slot>.0.10`, attacker `10.<slot>.0.20`, mirror `10.<slot>.0.1:8081`. One job runs at a time, so the slot is effectively a constant, but the placeholder remains. The setup scripts are hash-pinned and checked in; if they embed `10.<slot>.0.1`, the hash changes per slot; if they take the mirror URL as a parameter, the design does not define that parameter. This is the revision-2 N-07/M-16 residual.
* **Rationale & Recommendation:** Fix the subnet and mirror address to constants, for example `10.42.0.0/24` and `10.42.0.1:8081`, and delete `<slot>` until concurrency exists. Or add a typed `mirror_url` step parameter and state which setup-script lines consume it while the script hash stays stable.

### 11. Failure-code contract is gone, and `null_actor_failed` inverts the acceptance wording — Severity: Major

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** G11 (37); Retries (279); null-actor failure (429); DDL `reason_code`/`failure_code` (363, 372, 381, 406); acceptance (88–94).
* **Discrepancy Description:** G11 says every failure has a closed code and a next action, but the detailed plan no longer enumerates any codes. `null_actor_failed` is the only named code, and its name means the null actor observed the nonce — the opposite of the acceptance sentence "the null actor does not observe the nonce." `jobs.reason_code`, `attempts.failure_code`, and `validations.reason_code` have no shared enum. Revision-2 M-03 is not resolved; the simplification removed the only code list.
* **Rationale & Recommendation:** Publish one closed reason-code table with a discriminator and next action for each. Rename `null_actor_failed` to `null_actor_observed_nonce` or define it explicitly. Align `reason_code` and `failure_code`. Add the missing codes for egress, hash mismatch, mirror, snapshot, nonce placement, preflight, and validator error.

### 12. Target PoC pin duplicates the artifact catalog — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 246, 286–304, 599.
* **Discrepancy Description:** `config/artifacts.yaml` is called the single source of truth for PoC pins, but `Target.poc` carries repository, commit, files, and sha256. Two pins can disagree.
* **Rationale & Recommendation:** Keep the URL/hash/provenance in the catalog and make `Target.poc` reference an artifact id plus build and invocation steps; state the precedence.

### 13. Terminology calls the verdict `llm_assessed`, reuses `xentry` for two trust domains, and keeps `freeze` — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 11, 343, 347, 578, 685, 265.
* **Discrepancy Description:** The verdict is runner-owned; `llm_assessed` is an authority component. Reusing `xentry` for both the host app user and the guest actor is risky in a privilege-separation document. "Freeze" and "snapshot" remain interchangeable.
* **Rationale & Recommendation:** Say "the authority is `...llm_assessed`; the verdict is runner-owned." Rename the guest actor to `xentry-guest`. Use "snapshot" for the memory checkpoint and state the per-target restore/fresh-boot choice.

### 14. Component table and Additional Resources have orphan entries — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 187–200, 558–563, 627–628.
* **Discrepancy Description:** Preflight and the audit bundle are not in the component table; the artifact mirror appears only inside the broker row. Additional Resources has no repository-relative paths, no CVE/PoC URLs, and no prior-tree files.
* **Rationale & Recommendation:** Add rows for preflight, bundle, and the mirror; use repository-relative paths and advisory/PoC URLs; cite the prior harness, store, and client.

### 15. `script_source` is a single-value field, and `validations.authority` includes an unreachable value — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 286–304, 411.
* **Discrepancy Description:** All three targets are `checked_in`; `script_source` anticipates V1.1. `runner_observed` is in the validation CHECK, but no validation row can carry it.
* **Rationale & Recommendation:** Drop `script_source` until V1.1 or keep it as a literal. Remove `runner_observed` from the validation CHECK or use it in a real row.

### 16. Host/guest memory arithmetic and the per-call token cap are unstated — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 72, 75.
* **Discrepancy Description:** "Dirty Frag 3 GB (2 + host evidence)" mixes guest and host memory. "Per-call cap enforced" has no value, although G11 promises a token cap.
* **Rationale & Recommendation:** State what the third gigabyte is and the per-call token value, or drop the per-call claim.

### 17. Retry paragraph contains a self-answered question and a no-op gate option — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 279, 117.
* **Discrepancy Description:** "one attempt may have one setup repair? No." is deliberative prose. Gate E offers "Reduce concurrency (already one)" as a no-op.
* **Rationale & Recommendation:** Write declarative sentences and remove the no-op option.

### 18. DDL lacks indexes, CHECKs for `job_steps`/`broker_calls`/`artifacts`, and the foreign-key pragma — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 378–427.
* **Discrepancy Description:** The revision adds CHECKs to the main tables but leaves step state, broker-call status, and artifact kind unconstrained, and does not state `PRAGMA foreign_keys`.
* **Rationale & Recommendation:** Add the CHECKs and indexes and state the pragma, or note that `migrations/001_initial.sql` supplies them.

### 19. Auditability claim at 8,000 lines and 40 modules is not explained — Severity: Nit

* **Reviewer Lens:** `egm:egm-zoom-out`
* **Affected Scope:** 17–23, 61–78.
* **Discrepancy Description:** The failed v2 was 12,000 lines across about 20 subsystems; V1 is two-thirds the lines but twice the module count. The reset's auditability goal is asserted rather than shown.
* **Rationale & Recommendation:** State how the owner audits the 40 modules and the broker — for example, one owner per component, a review checklist, the ADR/threat model, and the budget gate — or set a smaller acceptance target.

## Review Limitations

Document-based review only. The reviewer read the revision-3 design, the Zoom-Out Standard, the revision-2 consolidated and stage reports, the approved brief, and the cited prior-tree source files. No VM was booted, no broker was created, and no PoC was executed. Code search was read-only.
