# Focused Review Report — xentry V1, Revision 3

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (714 lines; FeatureRange 1–571, DetailedRange 572–714)
**Review mode:** Focused re-review: Stage 5 (scope and budget) plus Stage 9 (implementation readiness)
**Date:** 2026-11-06

**Stage reports:**
- [Stage 5 — Initial Zoom Out, revision 3](zoom_out_report_rev3.md)
- [Stage 9 — Implementation Readiness, revision 3](implementation_readiness_report_rev3.md)

## Reviewer status and counts

| Stage | Reviewers | Status | Findings |
| --- | --- | --- | --- |
| 5. Initial Zoom Out | `egm-zoom-out` | completed | 2 Blocker, 9 Major, 8 Nit |
| 9. Implementation Readiness | `egm-implementation-readiness`, `egm-codebase-details`, `egm-style` | all completed | 5 Blocker, 16 Major, 8 Nit |

## Overall verdict

Revision 3 is a real improvement. Stage 5 confirms that the revision-2 scope/budget Blockers are resolved: the headline plan fits at 40/40 modules, 5,390 of 8,000 handwritten Python lines, and 14 weeks; the decision record, Phase 0 gates, and broker/VM budget lines exist. Stage 9 confirms that the revision-2 budget, state-machine, and author/repair Blockers are structurally resolved.

The design is still not implementation-ready. The two Stage 5 Blockers and three Stage 9 Blockers remain, and the DetailedRange is still a file/topic manifest rather than an executable plan. A fresh implementer would have to invent the broker registry, the provisioning/actor privilege split, the typed wire and persistence models, the three targets' values and setup contents, and the runner step contract. That is a direct violation of the implementation-readiness Zero-Decision Rule.

## What revision 3 resolved

- **Budget versus plan:** the 8,000-line / 40-module / 14-week budget now matches the headline plan; the two-VM and broker work have budget lines.
- **State machine:** the 22-state table is replaced by an ordered step list with `outcome` and `cleanup_state`; failed, cancelled, and interrupted jobs no longer route to validation.
- **Setup authoring/repair:** V1 uses checked-in, hash-verified scripts; there is no live author/repair path.
- **Nonce identity:** nonce id/hash/path/owner/mode are recorded; the value is runner-only; the attacker sees only the path; the validator sees observation and hash.
- **Broker basics:** fixed verbs, socket identity, QEMU as `xentry-vm`, SSH transport, snapshots, reboot, mirror, egress, and host evidence are present.
- **Targets:** three typed Python `Target` instances replace the YAML pack layer; Dirty Frag's authority is explicitly `guest_attested+llm_assessed`.
- **Network/mirror:** a mirror address, provisioning/default-deny phases, a package catalog, and vendor provenance are specified.

## Remaining Blockers

### FR3-B1. The broker has no broker-owned target/step registry and no trusted `http_probe` verb

`exec(vm_id, step_id, ...)` resolves `step_id` against app-side `src/xentry/targets.py`. If the app sends the template in `params`, the broker is an arbitrary-command proxy again; if the broker keeps a copy, there are two sources of truth. `start_target`/`start_attacker` accept app-chosen ids, `copy_in` an app artifact id, and `start_artifact_mirror` a manifest id. `broker/profiles.py` is only "Domain XML, image resolution, guest IP," not a validated catalog. `HttpProbe` is described as broker-internal, but the fixed verbs and `VmDriver` expose no `http_probe`, so the trusted target-side nonce observation for remote targets has no call path while app-side `vm/probes.py` duplicates it.

**Required action:** add one broker-owned registry for target, profile, step, image, and artifact ids with hashes, typed parameters, and allowed users. Resolve and reject unknown ids server-side. Add `http_probe(network_id, target_ip, port, method, path, timeout, max_bytes) -> HttpResult` to the fixed verbs, `VmDriver`, the broker client, and the contract test. Demote `vm/probes.py` to a plan builder or delete it.

**Sources:** Stage 5 Blocker 1; Stage 9 Blocker 1.

### FR3-B2. Provisioning root is not separated from the guest actor

PHP2Shell builds PHP and configures Apache, GitLab installs Omnibus, and Dirty Frag installs a kernel; all three setup scripts need root in the guest. The design allows root only for Dirty Frag setup/probe steps, names `xentry` as the guest actor, and never states the provisioning user, sudo policy, or actor restrictions. If setup runs as `xentry` with sudo, the actor can read `/root/xentry-nonce` without the exploit, making the Dirty Frag null-actor check non-probative. The literal `xentry` names both the host app user and the guest actor. No test asserts that the actor cannot run `sudo -n true`, read the nonce, or write a service binary.

**Required action:** define `provision_user: root` for all three hash-pinned setup scripts, allowlisted by step id rather than by target. Define `actor_user` as a non-sudo user with no writable root-owned paths, no setuid/sudo/pkexec, and no shared SSH key. Add `tests/test_actor_separation.py` and the Gate B check. Rename the guest actor to `xentry-guest` to separate it from the host app user.

**Sources:** Stage 5 Blocker 2; Stage 9 Blocker 2.

### FR3-B3. Typed models, method signatures, and validation rules are names only

`models.py` lists type names but no fields. `CommandResult`, `HttpResult`, `Manifest`, `Artifact`, `ClassifiedLog`, `LlmVerdict`, `VmProfile`, and `RunLimits` are consumed by broker verbs, the fake driver, tests, and the budget, but no field names, types, required/default flags, or validation errors are given. `RunnerContext`, `AttackerContext`, and `ProbeEvidence` are field-name lists without types or requiredness and are omitted from the models row. `web/schemas.py` is a name only.

**Required action:** add one field table per model (name, type, required, default, validation error) and full method signatures with parameter and return types for the broker client, `VmDriver`, validator, extractor, and API schemas. Replace "Field-complete" with a pointer to the authoritative schema.

**Sources:** Stage 9 Blocker 3.

### FR3-B4. Target instances, artifact/package pins, and setup-script contents have no values

`src/xentry/targets.py` is "Three `Target` instances" (250 lines) with no per-target image/kernel artifact id, vCPU/memory/disk, PoC repository/commit/files/SHA-256, build/invocation step, nonce path/owner/mode, probe kind/parameters/timeout, null-actor step id, or `what_proves`. `config/artifacts.yaml` and `config/packages.yaml` have no values, key schema, or provenance format; the PoC repositories and commits are named nowhere. `Target.poc` and `config/artifacts.yaml` both pin the PoC with no precedence rule. The three setup scripts are one-line deliverables with no package sources, mirror URL parameter, build steps, readiness command/output/timeout, reboot wait logic, nonce path/mode actions, or `setup_sha256` source.

**Required action:** add per-target field tables with exact values; publish both YAML schemas and the PoC-pin precedence rule; add a step outline per setup script plus the readiness contract consumed by the `provision` and `readiness` steps. Keep the mirror URL a typed step parameter so the script hash stays stable.

**Sources:** Stage 9 Blocker 4.

### FR3-B5. The runner step contract is missing

`runner.py` is budgeted at 450 lines but described only as "Ordered steps, attempts, timeouts, cleanup, validator call." The text says each step has a guard, timeout, and cleanup action, but none is enumerated. There is no mapping of step to command template, typed parameters, allowed user, retry classification, emitted evidence, or failure routing. `Target.timeouts` is literally `{...}`; "classified infrastructure failure" has no classifier; no rule says when an attempt row is created or what it copies. The cleanup transition does not define which destroys run, in what order, with what timeout, or what happens when `cleanup_state=failed`.

**Required action:** add a step table (seq, name, guard, timeout, cleanup, retries, failure code, evidence) for all three targets; a retry classification table with closed reason codes; a cleanup step sequence with timeouts and terminal states; and attempt-creation/reuse rules. Align `test_steps.py` with the enumerated outcome set.

**Sources:** Stage 9 Blocker 5.

## Key Majors to fix with the Blockers

* **Closed failure/reason codes.** G11 requires a closed code and next action; the plan has no list. `null_actor_failed` is the only code and its name inverts the acceptance sentence. Add one shared enum with trigger, discriminator, retryable flag, next action, and outcome projection; rename `null_actor_failed` to `null_actor_observed_nonce`.
* **Test plan.** The test rows are categories, not cases. Add per-file happy-path and edge cases, fixture schemas and labels, skip markers, and the real-VM acceptance runner's inputs/evidence/pass-fail checks.
* **API, token, check store, error envelope.** Choose one token mechanism; define cookie/header names, entropy, rotation, CSRF binding, the error envelope, status codes, `check_id` TTL/single-use/storage, and request/response models.
* **Budget mapping.** Add a component column or file-to-component map; define line, dependency, and non-Python counting; set a module cap with headroom (the broker registry adds a module); make `test_budget.py` enforce the map.
* **Mirror/offline provisioning.** Fix the mirror address or make it a typed `mirror_url` parameter; generate apt `Packages.gz`/`Release` and trust; resolve dependency closure; add an attacker image-build step or hashed prebuilt image; publish the fetch-script CLI and exit codes.
* **Dirty Frag null actor and host evidence.** The root-only nonce makes the null actor non-probative; define the null actor as "same wrapper without the exploit must not produce a host-channel root shell or a root nonce read"; record the host-channel observation; add a post-fresh-boot `uname -r`/readiness check; specify the channel mechanism and the tamper-analysis deliverable.
* **Cleanup and orphan identification.** Define domain/network naming, overlay/ISO paths, `list_managed` result schema, sweep ordering, idempotency, and the interrupted-job transaction.
* **Database/migrations.** Name one migration owner; add a rebuild command; add `job_outcomes` or `jobs.verdict`/`jobs.authority` for failed/cancelled/interrupted/null-actor/validator-error; add indexes, CHECKs, and `PRAGMA foreign_keys`.
* **Two nonce placements.** Add a `nonces` table keyed by `(attempt_id, phase)` or nonce ids on `job_steps`/`ProbeEvidence`; define the overwrite/reference rule for the initial and fresh nonces.
* **Security and deployment ownership.** Specify token, CSP, redaction, SSH key lifecycle, AppArmor/seccomp files, broker code/venv/config ownership, job-dir/overlay/ISO ownership, the `broker_calls` writer and DB permissions, systemd hardening, and host memory headroom.
* **Phases and gates.** Map every file/test to a phase; define exit checks; move Gate A to Phase 1 or define the Phase 0 harness that executes it; make Gates A/C true gates or label them measurements; align Gate F (19/20 plus 100% citation); define or delete "attacker VM reuse"; restore the dropped acceptance qualifiers.
* **Reuse and ADK.** Add a Phase 0 reuse spike behind `VmDriver`/`FakeDriver` for the prior QEMU harness, evidence store, and DeepSeek client; cite the prior files. Either delete the extractor/ADK path or record the ADR 0007 reversal in ADR 0001 and name the V1 decision the extractor feeds; state the LiteLLM fallback switch and equivalence test.
* **Authority/verdict projection.** `jobs` has no verdict/authority column; a null-actor failure writes values that cannot be stored. Add `job_outcomes` or `jobs.verdict`/`jobs.authority`, and a projection table for completed, failed, cancelled, interrupted, null-actor, and validator-error.
* **Terminology and host prerequisites.** Unify `state`/`outcome`, `guest_attested`/`guest_attested+llm_assessed`, `xentry`/`xentry-guest`, `freeze`/`snapshot`; consolidate the duplicated host prerequisites and pin the versions.

## Recommended next decision

The five Blockers are concrete and fixable. The next revision should:

1. Add the broker-owned registry and `http_probe` verb.
2. Separate provisioning root from the actor and add the denial tests.
3. Publish field-complete models and signatures.
4. Fill the three target instances, artifact/package pins, and setup-script step outlines.
5. Publish the runner step table and cleanup/retry contract.

The key Majors above should be fixed in the same revision; otherwise the next Stage 9 will repeat them. If the owner prefers to proceed without that work, the design should be explicitly accepted as a prototype plan, not an implementation-ready design.

## Review limitations

This focused review is document-based. The reviewers read the design, the revision-2 reports, the approved brief, and the prior-tree files they cite. They did not boot a VM, create the broker, or execute any PoC. The findings are model output, not a deterministic proof.
