# Goldfish Review Report — Stage 8 Intermediate Zoom Out Review

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (`Lines 1-712`; FeatureRange `1-519`, DetailedRange `520-712`)

**Scope note:** Intermediate pass over the unchanged document. The Stage 6 comprehension report and Stage 7 critic report were used as additional lenses. Findings below are limited to new scope, simplicity, or trust-boundary issues, and to confirmations that change a Stage 5 severity or the V1 verdict. Stage 5 findings confirmed without a severity change are summarized in the closing note and are not re-reported.

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-zoom-out` | completed |

**Severity summary:** 4 Blockers, 8 Majors, 2 Nits (14 findings). Provenance: 8 findings are new to this stage (6 Major, 2 Nit); 6 are verdict-changing confirmations of Stage 5 findings (1 Blocker confirmed and enlarged, 3 Major-to-Blocker promotions, 2 Nit-to-Major promotions).

## Prioritized Findings (Blockers -> Major -> Nits)

### V1 Scope Verdict Confirmed and Enlarged by Stage 6/7 Evidence - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 9-13, 17-21, 25-38, 548-697` (Overview, Problem, Goals, Detailed Implementation Plan); Stage 7 FeatureRange findings.
* **Discrepancy Description**: The Stage 5 Blocker said V1 is a full product rebuild rather than a defensible first version. The later stages make that conclusion stronger, not weaker: Stage 7 found five independent Blockers and nineteen Majors in the FeatureRange alone, and Stage 6 found seventeen Majors. The detailed plan still lists roughly one hundred file rows. V1 retains every v2 subsystem except Postgres/Alembic, the knowledge bank, and the deterministic oracle, while adding a browser client, three probe representations, a third storage layer, three provider integrations, a dummy pack, migrations with backup/rollback, an audit bundle, and a System preflight screen. The document still states no line, subsystem, or effort budget, so the "narrow reset" claim remains unfalsifiable; the reset changed the stack and vocabulary, not the breadth.
* **Rationale & Recommendation**: Keep the Stage 5 Blocker. Cut V1 to one input path, one target, the runner-owned nonce/null-actor/evidence spine, and one minimal job view; move the four-screen UI, multi-source ingestion, migrations/backup/rollback, ADK, SSE, the dummy pack, and the second and third targets to V1.x. If the current breadth is intentional, state an explicit line/subsystem budget and show how it remains auditable.

### Prebuilt Packs Still Execute the Repair Path, So the Reviewed Hash Does Not Describe What Runs - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 13, 29, 38, 55, 164, 207, 226, 292, 394` (Overview, G5, G14, Non-Goals, Retry rules, Target packs, Verification path, Alternative 5).
* **Discrepancy Description**: All three real targets are `provisioning: prebuilt` with setup scripts that are hand-reviewed once and hash-pinned, but setup repair (line 164) still applies to prebuilt packs. A repaired script is therefore an unreviewed, root-privileged script while the pack continues to advertise the reviewed hash. Line 226 compounds this by telling the validator it receives "the generated setup script" even for prebuilt packs. Only the test-only dummy pack exercises `generated` provisioning, and Alternative 5 claims "the validator and null actor" are the controls (line 394) even though the approved brief says the null actor cannot close a setup script that reacts to the PoC. The trust control is contradicted rather than merely unexercised.
* **Rationale & Recommendation**: Promote Stage 5 finding 3 from Major to Blocker. Split `script_source: checked_in | generated`. For `checked_in`, execute byte-for-byte, record the executed hash in the validation row, and disable LLM repair or surface any repair as an unreviewed new hash. Define the dummy pack's limits, and state plainly if G14 is demonstrated only on the dummy.

### Same-VM Causality Is Contradicted by the Nonce/Actor Definition and Has No In-Scope Fallback - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 21, 30, 62, 211-213, 219-226, 244-246, 292, 376, 394, 515` (Overview, G6, Open Questions, Target packs, Verification path, Per-target probes, Alternative 5, Non-Goals).
* **Discrepancy Description**: Line 220 requires a nonce the actor cannot read, line 211 says the nonce file is readable by the web user, and line 244 says the RCE reads it into the web root. "Actor" is never defined, and the null actor has no operational definition or pass criterion. The setup author receives the target pack (line 292), which contains `probe.nonce_placement` (line 203), so a generated root script can know the exact read path. For Dirty Frag, the decisive evidence is produced by a compromised guest kernel, so the nonce proves that a root-only file was read somewhere in the guest, not that the PoC read it. The only fallback, a second attacker VM, is explicitly not built in V1 (lines 376, 515). The in-scope path therefore cannot support the causal claim for the two same-VM web targets or Dirty Frag.
* **Rationale & Recommendation**: Promote Stage 5 finding 5 from Major to Blocker. Either build the second attacker VM or state that Dirty Frag and the same-VM web targets are `inconclusive` by construction. Define "actor" and nonce ownership on first use; randomize nonce placement inside the runner and keep it out of model context; add a deterministic check that the executed setup script and wrapper do not reference the nonce path, probe endpoint, or runner credentials.

### VM Trust Boundary Is Contradicted by the Egress and Privilege Constraints - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 31, 113, 252, 265, 339-341, 408-412` (G7, System shape, VM harness, Security and threat model, Alternative 8); prior mechanism at `/home/zran/ambitious_projects/xentry/src/xentry/provision_net.py`.
* **Discrepancy Description**: "The VM is the trust boundary" (line 113) requires default-deny egress after provisioning. The design leaves the mechanism open between per-VM nftables, which needs host root, and a host-side allowlist proxy, which still has to force guest traffic through it and is not controlled under slirp user-mode networking. The prior tree's only working egress mechanism depends on a privileged bridge, a Docker proxy container, and `sudo`; V1 rules out root, Docker, and non-session libvirt. The project therefore cannot simultaneously keep `qemu:///session`, no root broker, no containers, and a default-deny egress rule. This is not an open implementation choice but a contradiction with the stated constraints.
* **Rationale & Recommendation**: Promote Stage 5 finding 6 from Major to Blocker, or withdraw the VM trust-boundary claim and state the residual LAN and internet exposure. Design one egress mechanism with its actual privilege model, and make the fail-closed egress test a Phase 0 gate. (Mechanism read-only verified in the prior tree; not executed.)

### Prior Tree's Typed Provisioning-Module System Is an Unassessed Reuse Opportunity, and V1 Reinvents the Riskier Alternative - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 38, 207, 292, 571-572, 620`; Alternative 17 at `Lines 462-466`; prior files `/home/zran/ambitious_projects/xentry/src/xentry/generate/modules/{base,apt_package,build_source,pip_package,composer_project}.py`, `/home/zran/ambitious_projects/xentry/docs/modules.md`, `/home/zran/ambitious_projects/xentry/tests/unit/test_modules.py`.
* **Discrepancy Description**: V1's generated flow has the model emit a free-form setup script and PoC wrapper (lines 38, 292, 571-572), controlled only by a line cap, "no invented versions or URLs," and, for the first three targets, a one-time human review. The prior tree already contains a tested, documented module system: a `RecipeModule` protocol with `validate(config)` and `render(config)`, where the model selects a module and supplies typed configuration while deterministic code emits the shell fragment. Its documentation states the model should not be free to emit arbitrary shell beyond the module's validated fields. The available modules (`apt_package`, `build_source`, `pip_package`, `composer_project`) match exactly the fragments V1's setup author must produce. Alternative 17 rejects the 12,000-line tree wholesale and never assesses per-module reuse. The old `http_poc` module should not be reused because it prints its own `XENTRY_POC_OK` success marker, the self-reported-oracle failure V1 is trying to escape.
* **Rationale & Recommendation**: Evaluate reusing the provisioning modules, or at minimum adopt the contract: the LLM returns a module list plus typed configuration and runner code renders it; free-form shell becomes an explicitly reviewed escape hatch. This reduces the root-run attack surface, makes review deterministic, and may remove the prebuilt-versus-generated split. This is reference-level reuse of small pure modules, not an import of the rejected Postgres/Alembic stack.

### LLM Validator Duplicates a Deterministic Observation the Runner Already Makes - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 30, 219-246, 226, 228-240, 294, 496` (G6, Verification path, validator schema, Model integration, Alternative 22).
* **Discrepancy Description**: The runner itself performs the HTTP GET, parses the leaked response, or drives the root shell (lines 244-246), so it deterministically knows whether the nonce appeared. The design then sends the same evidence to a tool-less LLM and makes its verdict the product's authority, with no rule that a runner-observed nonce is a precondition for `reproduced` and no requirement that the runner resolve the free-form `evidence_refs` (line 234). The validator layer adds a model call, a prompt, a bundle builder, fixtures, and third-party data egress without adding an authority the runner lacks. If the LLM is meant to judge causality beyond nonce appearance, the decision rule is never stated. This subsumes the Stage 5 validator-determinism recommendation with a simpler design.
* **Rationale & Recommendation**: Record `nonce_observed`, version match, and null-actor pass as runner facts; clamp `reproduced` to false when the nonce was not observed; resolve every `evidence_ref` against transcript and artifact hashes. Either limit the LLM to a reason code and explanation or define the precise causal criterion it applies. Keep the honest `llm_assessed` label without paying for a redundant oracle.

### Probe Is Specified in Three Places, and the Pack Probe Hook Runs Host Code With Full Application Authority - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 200-204, 219-226, 323-324, 584, 588, 592, 619, 645` (Target packs, Verification path, Interfaces, Detailed Implementation Plan).
* **Discrepancy Description**: The probe exists as a manifest block (`probe {nonce_placement, command_or_http_request, expected_evidence}`, lines 203-204), as a per-target `probe.py` that places the nonce, runs the PoC, parses responses, and returns `ProbeEvidence` (lines 584, 588, 592), and as generic helpers `vm/probes.py` plus the `HttpProbe` interface (lines 323-324, 645). `packs.py` imports and executes the pack `probe.py` in the host process (line 619), so pack code runs with the app's filesystem, network, libvirt socket, and DeepSeek-key authority, while the document says only setup scripts are hand-reviewed and hash-pinned. Nothing says which representation is authoritative, whether nonce placement lives in the spec or the hook, or why a generic probe layer and per-target hooks both exist. This extends Stage 5 finding 4 with the generic-layer duplication and the host-authority point.
* **Rationale & Recommendation**: Use one layer. Prefer runner-owned generic primitives driven by a typed pack spec. If hooks remain, declare them part of the trusted computing base, include them in review and hash pinning, and capability-restrict them. Delete the duplicate contract; the current split lets a pack produce arbitrary evidence while the document still describes the runner as the evidence owner.

### Dirty Frag's Destroy Is Ordered After the LLM Call, Keeping the Contaminated VM Alive Across a Remote Request - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 27, 129, 262, 267, 341` (G3, System shape, VM lifecycle, Security and threat model).
* **Discrepancy Description**: The sequence is evidence, validator, destroy (lines 27, 129, 262). Dirty Frag's destroy is described as a security control (line 267) because the page cache is contaminated (line 341). A validator timeout or provider retry therefore keeps the contaminated domain running for the duration of a remote DeepSeek call, contradicting "destroyed on every exit path" (line 28) and making the security control contingent on validator availability. The evidence bundle is immutable and self-contained, so validation does not need the VM.
* **Rationale & Recommendation**: Reorder to evidence, destroy, validate. Record the destroy result before invoking the validator. If the validator is unavailable, the job should still have destroyed the VM and record a validator error rather than holding the domain open.

### Existing `.env.example` Encodes the Opposite of V1's Fixed Defaults, and the Plan Only Adds Variables - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** Design `Lines 538, 544, 556, 608`; current file `/home/zran/ambitious_projects/xentry_claude/.env.example` `Lines 19, 23, 29-31`; approved brief `concepts_brief.md` line 103.
* **Discrepancy Description**: The file the plan says to "Modify" currently sets `XENTRY_LIBVIRT_URI=qemu:///system`, `XENTRY_MAX_SETUP_ATTEMPTS=3`, `XENTRY_MAX_POC_ATTEMPTS=3`, `XENTRY_JOB_TIMEOUT_SECONDS=7200`, and relative `XENTRY_DATA_DIR`/`XENTRY_DB_URL`. The design fixes `qemu:///session` first (line 538), one setup repair and one PoC rerun (lines 164-165), per-target caps (line 544), and a config that rejects relative SQLite URLs (line 608). The plan's `.env.example` row (line 556) only adds six new variables; it does not remove or correct the stale values and never mentions `XENTRY_LIBVIRT_URI`. An operator who copies the existing file gets system libvirt, three setup attempts, three PoC attempts, a two-hour global timeout, and a relative database path, directly contradicting the design's trust and budget decisions. This also corrects Stage 6 finding 14: both files exist in the current repo, so the defect is stale content, not a ground-up inconsistency.
* **Rationale & Recommendation**: Replace the stale values in the plan: session URI by default, per-target caps in packs, no global attempt counts or two-hour job timeout, and absolute data and database paths. Add a startup assertion or test that the resolved settings match the design defaults.

### Evidence Egress to DeepSeek Is an Unmodeled Trust Boundary, and the Brief's Required Disclosure Was Dropped - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 226, 283, 294, 500` (Verification path, Ingestion and evidence, Model integration, NFR Privacy); approved brief `concepts_brief.md` line 89.
* **Discrepancy Description**: The validator bundle includes the pinned PoC, the generated setup script and wrapper, the raw transcript, the nonce value and placement, the null-actor result, and precondition evidence, and it is sent to a third-party DeepSeek endpoint (lines 226, 294). The privacy NFR (line 500) lists only local controls and "no secrets in the guest or logs"; it does not cover provider egress, provider retention, or the fact that the nonce is a bearer proof value leaving the host. The approved brief explicitly required that fetched content sent to DeepSeek be disclosed in the UI, but the design's UI, help page, and threat-model file (line 695) do not mention it. Stage 7 noted this only in passing inside its missing-risk-register finding.
* **Rationale & Recommendation**: Add a data-egress section and threat-model entry. Disclose provider egress in the UI and help page. Minimize the bundle: send the observation that the nonce appeared rather than the nonce value, and prefer hashes or tagged excerpts over raw attacker-controlled text the validator does not need. Record provider, model, prompt hash, and retention assumption in the validation row, and state whether PoC source may be sent.

### Request-Integrity Token and UI Form a Browser Trust Boundary, Not a Thin Adapter - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 25, 95-99, 171-193, 191, 296-298, 334-342` (G1, CUJ 5, Web UI and API, Model integration, Security and threat model).
* **Discrepancy Description**: The token is injected into a same-origin page that renders model summaries, logs, validator evidence, and PoC-derived text, with no stated autoescaping rule or CSP. A stored XSS in that page can read the token and drive every mutation, so the control is only as strong as the origin's output handling. The UI is therefore a second untrusted-content boundary, not a thin adapter, and the JavaScript client with SSE reconnect, backfill, filtering, and token handling is more client-side surface than the design admits. This promotes Stage 5 finding 17 from Nit to Major and restates the UI scope in Stage 5 finding 13.
* **Rationale & Recommendation**: Keep the token but move it out of the DOM (HttpOnly, SameSite cookie or a per-page token endpoint). Require autoescaping and inert-text rendering for all model, PoC, and transcript content, and add a strict CSP. Restate the UI's client-side surface and its trust boundary in the design.

### Altitude Inversion: Load-Bearing Architecture Is Missing While the File-Level Plan Is Over-Specified - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 520-712` (especially `554, 558, 704`), `147-167, 197-207, 228-240, 304-316`; Stage 7 findings on state, pack, reason codes, snapshot, and validator contract.
* **Discrepancy Description**: The document specifies the file table, dependency pins, `secrets.token_hex(16)`, `NoNewPrivileges`, and an 80 percent coverage threshold, while leaving the runner state table, pack schema, closed reason codes, null-actor definition, attempt model, snapshot type, and validator decision rule undefined. This is not premature detail but detail in the wrong layer: the architecture is missing where it is load-bearing and over-specified where it is not. The combination explains why the file plan cannot be implemented consistently and why Stage 6/7 found so many contract gaps.
* **Rationale & Recommendation**: Promote Stage 5 finding 16 from Nit to Major. Move the file table, dependency pins, and test commands to an appendix or separate implementation plan, and use the space for the state table, pack schema, reason-code table, null-actor specification, snapshot semantics, and data contract.

### "Two Model Points" Undercounts the Generator Surface and Omits the Repair Contract - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 27, 111, 164, 289-292, 327, 572, 620, 673` (G3, System shape, Retry rules, Model integration, Interfaces, Detailed Implementation Plan).
* **Discrepancy Description**: The document says the model is invoked at "two points" and has "two declared calls" (lines 111, 289-292), but repair is a separate model call with its own prompt (`prompts/repair.md`, line 572), a different input (typed facts plus a classified log, line 164), and its own retry policy. The validator is a third session. `AgentRuntime` exposes only `extract` and `author_setup` (line 327), and `tests/test_agent_contract.py` covers extractor/setup prompts but not repair (line 673). The document cannot consistently size the LLM surface, prompt-versioning work, or the ADK spike.
* **Rationale & Recommendation**: State the real surface: extract, author, repair, and validate. Add `repair_setup(facts, classified_log, pack)` to `AgentRuntime`, or define repair as a re-invocation of `author_setup` with the same signature, and add it to the contract test. If repair is not a separate call, delete the separate prompt and retry path.

### Check Links and the Job Fetch Are Separate, So the Reviewed Bundle Is Not the Executed Bundle - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 27, 34, 74, 186` (G3, Pre-run plan, CUJ 1, Web UI and API); approved brief `concepts_brief.md` line 152.
* **Discrepancy Description**: `POST /api/links/check` fetches and summarizes both links before a job (line 186), and the job's fetch phase then fetches them again (line 27). Nothing pins the checked bundle's hash or reuses it, so the text the user reviewed is not necessarily the text the extractor sees. The brief asked for the exact extracted text with a SHA-256, but the pre-run plan shows only target, image, kernel, probe, and caps (line 34). This extends Stage 5 finding 13, which treated the link preview as unnecessary scope but did not identify the audit/consistency gap.
* **Rationale & Recommendation**: Make Check links produce a content-addressed manifest that the job adopts, or drop the separate check and render the plan from the job's own fetch. If the check remains, show the bundle hash in the pre-run plan and fail rather than silently refetching different bytes.

## Confirmation Notes (not counted)

The following Stage 5 findings are confirmed without a severity change and are not re-reported: probe outside the reviewed trusted base (finding 4), direct QEMU never evaluated (finding 7), ADK over-engineering (finding 8), storage duplication (finding 9), validator determinism (finding 11, now subsumed by the validator-duplication finding above), adversarial test plan (finding 12), source-aware ingestion (finding 14), and internal inconsistencies (finding 15).

New evidence that strengthens these without changing their severity: the prior `verify/vm.py` already implements `savevm`/`loadvm` pre-PoC snapshots, loopback host forwards, `restrict=on` user networking, overlays, and a pre-PoC cache, which are exactly the snapshot and networking semantics Stage 6/7 flag as undefined; the design now has three stores because the content-addressed `evidence.py` sits beside the authoritative attempt directory and the SQLite index, with cross-job dedupe, retention, and pruning undefined; the ADK tool-call gate is defined with "two tools" while both generator calls are supposed to be tool-less; the prior `sources/` and `normalize/` adapters exist but remain unassessed; and the internal-inconsistency set grows with the stale `.env.example` and a "Create at finalization" row for a design file that already exists and is registered in `docs/designs/SITEMAP.md`.
