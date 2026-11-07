# Goldfish Review Report

**Target:** `/home/zran/ambitious_projects/xentry_claude/docs/designs/xentry-v1.md` (`Lines 1-712`)

## Reviewer Status

| Reviewer | Status |
| --- | --- |
| `egm-zoom-out` | completed |

**Severity summary:** 1 Blocker, 12 Major, 4 Nits.

## Prioritized Findings (Blockers -> Major -> Nits)

### V1 Scope Is a Full Product Rebuild, Not a Defensible First Version - Severity: Blocker

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 9-13, 17-21, 25-38, 548-697` (Overview, Problem, Goals G1-G14, Detailed Implementation Plan)
* **Discrepancy Description**: The design defines v2's failure as roughly 12,000 lines across about 20 subsystems that its owner could not audit (line 17). V1's own plan then specifies roughly 100 file rows across ten areas (lines 548-697): a FastAPI/Jinja2/SSE web app with token, CSRF, Host/Origin, CSP, and security headers; source-aware ingestion for five source shapes; a content-addressed evidence store; a five-table SQLite schema plus migrations, backup-before-migration, and rollback; a libvirt harness with cloud-init, SSH, snapshots, PTY, port forwards, and egress control; three heterogeneous target harnesses; ADK plus a LiteLLM fallback plus a spike; an audit bundle; a systemd unit; and 23 test/fixture files. The reset changes the stack and vocabulary, not the breadth. The root problem is causal evidence (line 19); most of the listed work does not serve it.
* **Rationale & Recommendation**: A defensible first version is the verification spine: one input path, one target, runner-owned nonce/null-actor/evidence, one validator, and a minimal job/evidence view. Move the four-screen UI, multi-source ingestion, migrations/backup/rollback, ADK, SSE, the dummy pack, and the second and third targets to V1.x. If the owner keeps the current scope, the design should state an explicit line/subsystem budget and show how it remains auditable; otherwise V1 repeats the failure mode it was created to escape.

### Three Acceptance Targets Require Three Harnesses, Not Three Rows - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 13, 29, 210-213, 404-406, 543-544, 589-592, 708`
* **Discrepancy Description**: Alternative 7 concedes that one vertical slice is "faster to finish and proves the pipeline with less environment work" (line 404) but keeps all three targets as V1 acceptance gates (line 406). PHP2Shell is a native PHP/Apache build with an HTTP probe, GitLab is a multi-GB Omnibus install with 20-40 minute provisioning, and Dirty Frag needs a pinned kernel, reboot, PTY root shell, and mandatory destroy. The Dirty Frag "cut line" (line 406) is a schedule contingency, not a V1 scope boundary, and GitLab remains a full acceptance gate.
* **Rationale & Recommendation**: Make PHP2Shell the only V1 acceptance target. GitLab and Dirty Frag become V1.1/V1.2 with their own acceptance. If all three are non-negotiable, the document should say that V1 is a three-harness program and stop claiming to be the narrow reset described on line 19.

### Autonomous Generated-Provisioning Claim Is Exercised Only by a Synthetic Pack - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 29, 38, 55, 207, 546, 593-594, 709`
* **Discrepancy Description**: G14 promises a fully autonomous flow "after those three" hand-reviewed scripts (line 38), and the Non-Goals explicitly rule out a human approval gate for generated scripts (line 55). But V1 ships only three `prebuilt` targets (line 546); the only `provisioning: generated` pack is the dummy fourth pack (line 207), whose `probe.py` returns "canned probe evidence" (line 594). The dummy pack, the setup-author prompt, the repair loop, and the "no human review" acceptance (line 709) therefore exist for a future target, not for any V1 user, and a canned probe cannot demonstrate that an unreviewed generated setup script is safe.
* **Rationale & Recommendation**: Drop `generated` provisioning and the dummy pack from V1; ship three `prebuilt` packs and defer the autonomy claim. If autonomy is a V1 requirement, make one real target `generated` and use that target's acceptance run as the evidence. Do not use a synthetic pack as proof for a real trust claim.

### Evidence-Producing Probe Lives Outside the Reviewed Trusted Base, and the Declarative Spec Duplicates It - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 30, 197, 203-204, 226, 584, 588, 592, 594, 619` (G6, pack manifest, target pack implementation, `packs.py`)
* **Discrepancy Description**: G6 says "the runner collects raw evidence" (line 30), and the pack manifest declares a declarative `probe {nonce_placement, command_or_http_request, expected_evidence}` (line 203). But each target also ships an executable `probe.py` that places the nonce, runs the PoC, parses responses, and returns `ProbeEvidence` (lines 584, 588, 592), and `packs.py` imports that code from the pack directory (line 619). The design says only the setup scripts are hand-reviewed and hash-pinned (lines 13, 38, 546); it never says the probe code is reviewed. The component that produces the evidence the validator judges is therefore per-target code outside the stated trusted base, and the design never says whether the manifest spec or the code hook is authoritative.
* **Rationale & Recommendation**: Pick one mechanism. Either move nonce placement, probe invocation, and evidence capture into runner-owned generic primitives driven by the declarative spec, or explicitly include `probe.py` in the hand-review and hash-pinning regime and declare it part of the trusted computing base. Delete the duplicate contract; the current split lets a pack produce arbitrary evidence while the document still describes the runner as the evidence owner.

### Same-VM Causality Is the Central Unproven Assumption, and Its Fallback Is Out of Scope - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 31, 62, 221-226, 376, 515` (G7, open questions, per-target causality, non-goals)
* **Discrepancy Description**: The hard problem is showing that a reported reproduction was caused by the vulnerability (line 19). The design assumes a non-root actor in the same VM with a protected nonce is sufficient for PHP2Shell and GitLab (lines 221-226), but lists same-VM causality as an open question (line 62) and says a second attacker VM is the fallback (line 31). That fallback is explicitly not built in V1 (lines 376, 515) and would double cost and break the one-VM assumption. The V1 acceptance path for two of three targets therefore rests on an assumption with no in-scope contingency.
* **Rationale & Recommendation**: Run a causality spike for PHP2Shell and GitLab before committing the design, and decide the second-VM question now. If the second VM is out, define the weaker claim the one-VM path can actually make and ensure the verdict label and UI state it. Do not defer the decision to "after the probes are tested" while both targets remain V1 acceptance gates.

### Guest-Egress Control Behind the VM Trust Boundary Is Undecided, and Session Libvirt May Need Host Root - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 31, 113, 252, 265, 340, 500` (G7, trust boundaries, network policy, spike plan)
* **Discrepancy Description**: Line 113 states "The VM is the trust boundary." That holds only if the guest cannot reach the host LAN or the internet after provisioning. The design leaves the mechanism open: "a host-side allowlist proxy or per-VM nftables; the plan records which one the Phase 0 spike proves" (line 265). With `qemu:///session`, user-mode networking NATs guest traffic through the host; per-VM nftables typically requires host root, and a host-side proxy is a new privileged component that appears nowhere in the architecture. An unresolved egress control means the VM-boundary claim is currently aspirational.
* **Rationale & Recommendation**: Choose and design the mechanism now, with the actual privilege model. Prefer direct QEMU/slirp with restricted networking and explicit host forwards, or a dedicated tap/bridge with nftables if host root is acceptable; otherwise state the residual LAN-exposure risk and test it. Make the fail-closed egress test a Phase 0 gate (line 711 already lists other gates), not a spike output recorded later.

### Direct QEMU Is Never Evaluated, Despite a Reusable Harness in the Prior Tree - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 28, 252-254, 408-412, 466, 537-538` (VM layer, Alternative 8, Alternative 17)
* **Discrepancy Description**: The design mandates `libvirt-python` and compares only `qemu:///session` against `qemu:///system` (Alternative 8). It never considers driving QEMU directly. The old tree the document cites has a direct-QEMU harness at `/home/zran/ambitious_projects/xentry/src/xentry/verify/vm.py`: it invokes `qemu-system-x86_64` and implements qcow2 overlays, snapshots, SSH, provisioning, PoC attempts, and port forwards. Libvirt adds a daemon dependency, domain XML, the session/system split, and the root-equivalent system-mode hazard; direct QEMU avoids the broker entirely. Alternative 17 rejects importing the 12,000-line tree wholesale (line 466), which is not the same as evaluating per-module reuse of the harness. No per-module reuse assessment appears anywhere in the document.
* **Rationale & Recommendation**: Add direct QEMU as an alternative and evaluate porting the old harness behind `VmDriver`. If libvirt stays, state what it buys over the existing code and why that is worth the daemon and privilege surface. This is the largest concrete reuse opportunity in the document.

### ADK Plus LiteLLM Plus Spike Plus Fallback Plus Parity Tests Is Over-Engineering for Two Tool-Less Calls - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 66, 289-296, 458-460, 536, 620, 673, 710`
* **Discrepancy Description**: The agent has exactly two declared calls, extraction and setup authoring or repair, and both are tool-less (lines 289-292). The design still commits to ADK plus LiteLLM, a one-week 20-scenario spike, a direct-LiteLLM fallback, an `AgentRuntime` abstraction, and an "ADK and LiteLLM runtime parity" test (line 673). Alternative 16 itself says the direct loop is "smaller, easier to audit" and that the old tree already had an 80-line DeepSeek-compatible client (`/home/zran/ambitious_projects/xentry/src/xentry/llm.py`). The framework is the least proven and most replaceable component in the plan.
* **Rationale & Recommendation**: Use one direct LiteLLM/provider call now; delete ADK, the spike, the fallback path, and the parity test. Keep a thin function boundary for testability. Reintroduce ADK only if the design later adds model-chosen tool trajectories.

### Storage Design Is a Dual-Write System With Migrations, Backup, and Rebuild While SQLite Itself Is Still Open - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 33, 302-316, 352, 420-424, 596-601, 610, 622` (G9, persistence section, deferred decisions)
* **Discrepancy Description**: The design specifies a SQLite index with `jobs`, `tool_calls`, `validations`, `artifacts`, and `schema_version` (lines 304-314), WAL/foreign-key settings and a claim query (`db.py`, line 610), forward-only migrations, backup-before-migration, rollback, and a rebuild path. It also says the attempt directory and JSONL are authoritative (line 316), so the SQLite tables are a second copy; `tool_calls` rows duplicate the append-only event log (line 308). Meanwhile the "Deferred decisions" section still asks whether SQLite is needed at all (line 352). The design is specifying both answers to an undecided question.
* **Rationale & Recommendation**: V1 should use the attempt manifest plus JSONL as the only authoritative store, with a minimal `jobs` index only if the job list needs it. Defer migrations, backup/rollback, and the `tool_calls`/`artifacts` tables until a second consumer or real schema churn appears. If the index is truly rebuildable, the migration-safety machinery is largely unnecessary; if migration safety is critical, the index is not fully rebuildable. Resolve the contradiction.

### Design Simultaneously Fixes and Defers the Same Load-Bearing Choices - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 332, 344-355, 535-544, 558, 596-601, 630-660` (Deferred Decisions, Detailed Implementation Plan)
* **Discrepancy Description**: Line 332 says "The detailed file list and function boundaries are fixed in the Implementation Plan section," and the plan fixes FastAPI/Jinja2/`sse-starlette` (line 535), a systemd unit (line 558), SQLite tables and migrations (lines 596-601), and ADK plus LiteLLM (line 536). Yet the Deferred decisions list still includes web framework and live-log transport (line 354), deployment unit (line 355), SQLite versus manifest-plus-JSONL (line 352), ADK survival (line 353), session versus system libvirt (line 346), one process versus web plus worker (line 347), and LAN policy (line 349). Each of those choices changes the file plan and the trust boundary. An implementation-ready plan cannot sit on top of an unresolved decision list.
* **Rationale & Recommendation**: Split the document into decided and open items and make the Implementation Plan explicitly conditional on the open ones, or close the decisions before calling the design Proposed. At minimum, remove the file-level plan for any area whose core choice is deferred; the current combination reads as convergence that has not happened.

### Validator Has No Determinism or Repeatability Contract, Yet Acceptance Requires Repeated Clean Runs - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 30, 228-240, 294-296, 496, 708, 710`
* **Discrepancy Description**: The validator is a DeepSeek LLM. The design records `model` and `prompt_hash` (lines 230-240) but does not specify temperature, seed, model-snapshot pinning, or how a verdict is reproducible. Acceptance is "two consecutive clean runs per target" (line 708), which depends on the validator returning the same verdict on the same evidence; `deepseek/deepseek-chat` is an alias that can move, and line 296 only says the provider-returned model id is logged. A nondeterministic oracle makes the acceptance flaky and the audit record hard to compare over time.
* **Rationale & Recommendation**: Pin the exact provider model snapshot if one is available, set temperature 0 or record the sampling parameters in the validation row, and define acceptance in terms of the runner-owned probe plus validator agreement over N replays of stored evidence. Add a regression test that replays the fixtures and records verdict stability; if the validator disagrees with itself, the UI should show `inconclusive`, not a pass.

### Adversarial Test Plan Misses Both Ways to Fool the Validator, While Security Section Claims the Validator as an Injection Control - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 13, 38, 222, 226, 240, 298, 394, 675, 679, 683-687`
* **Discrepancy Description**: First, the validator receives the generated setup script and wrapper plus the raw transcript (line 226), both model/attacker-influenced text, while line 298 lists "the runner-owned validator" among the prompt-injection controls. The validator has no tools, so the blast radius is a wrong verdict, but that verdict is the product's authority. The prompt-injection corpus covers a fake CVE page requesting a host mount and a fake PoC printing a marker (lines 679, 686-687); it does not cover a setup script or transcript that instructs the validator to return `reproduced`. Second, Alternative 5 says a generated script that manufactures evidence would be caught by "the validator and null actor" (line 394), but the null actor never sends the PoC request, so it cannot catch a setup script that watches for the probe and writes the expected file. No test covers that case either, even though the document's own bootstrap-review rationale is built on it (lines 13, 38).
* **Rationale & Recommendation**: Add a validator-targeted injection fixture and require the validator prompt to delimit and label bundle fields as data, with an output schema that rejects out-of-band claims. Add a reactive-setup-script fixture that watches for the probe and fabricates the expected evidence, and define the expected outcome: either a failed job or an explicitly accepted residual risk. State in the security section that the validator's independence is session isolation, not adversarial robustness, and do not claim the null actor covers reactive setup scripts.

### UI, SSE, and Preflight Surface Is Product Scope, Not the Root-Problem Path - Severity: Major

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 32, 34, 171-193, 501, 632, 653-660` (G8, G10, user experience, web application plan)
* **Discrepancy Description**: Four screens plus a help modal, a System preflight screen, link check, pre-run plan, filterable logs, SSE with backfill/heartbeat/reconnect/terminal close, polling fallback, orphan banner, bundle download, and a token-aware JS client (lines 171-193, 632, 660). For one or two users, a submit page and a job/evidence page that reads the persisted state exercise the same pipeline. The design itself says the UI is an adapter (line 400), but the plan gives it a full product surface. The brief's own suggestion that polling a log file may be enough is not carried into the design.
* **Rationale & Recommendation**: Ship one submit page and one job/evidence page; put preflight in startup/CLI; poll the job state and JSONL first, and add SSE only if a measured UX need appears. Defer the System screen, the link preview, and the log-filter UI until after the verification spine works.

### Source-Aware Ingestion Supports Five Source Shapes for Three Fixed CVEs and Pinned PoCs - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 273-283, 418, 617, 669`
* **Discrepancy Description**: V1 supports three named CVEs and pinned PoCs (lines 13, 43), but the fetcher supports NVD API JSON, cve.org JSON/API, GitHub advisory API, GitHub repository API plus tarball, and generic HTML (lines 273-279), with five adapter tests (line 670). That is speculative input coverage for fixed inputs. The old tree already has source adapters at `/home/zran/ambitious_projects/xentry/src/xentry/sources/nvd.py`, `ghsa.py`, and `cvelist.py`; if any parsing is reusable, its omission from the reuse assessment is an additional gap.
* **Rationale & Recommendation**: Accept only the exact three CVE records and three pinned PoC repositories for V1, with the PoC tarball pinned by commit as the design already does. Add a generic HTML fallback only if a real input requires it. Defer the advisory and cve.org adapters and keep the evidence bundle to the excerpts the extractor actually cites.

### Internal Inconsistencies in the Document - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 11 vs. 545; 158 vs. 228-238; 509 vs. 694`
* **Discrepancy Description**: Line 11 says SQLite stores "job and CVE records," but line 545 says "No `cves` table in V1" and the schema (lines 304-314) has none. Line 158 includes `not_run` in the verdict enum, but the validator contract returns only `reproduced | not_reproduced | inconclusive` (lines 228-238). Line 509 lists `docs/adr/0001-v1-reset.md` as an additional resource while line 694 lists it as a file to create; the file does not exist in the repo.
* **Rationale & Recommendation**: Pick one source of truth for each: remove `not_run` or define it as a pre-validation state, remove the CVE-record claim or add the table, and mark the ADR as pending. Also note that `/home/zran/ambitious_projects/xentry_claude` has no `README.md` or `context.md`, so project alignment is verifiable only against `concepts_brief.md`; add a root context document or cite the brief as governing.

### Premature Implementation Detail at High Altitude - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 221, 520-712` (especially `554, 558, 704`)
* **Discrepancy Description**: The design includes `secrets.token_hex(16)` (line 221), exact dependency lists (line 554), a `NoNewPrivileges` systemd directive (line 558), and an 80% coverage threshold (line 704). These are implementation details that will rot and are not needed to evaluate the architecture; the standard asks high-level sections to focus on interfaces, data flow, and components.
* **Rationale & Recommendation**: Keep the state machine, interfaces, target-pack contract, validation schema, and trust boundaries. Move the file-by-file table, dependency pins, and test commands to an appendix or a separate implementation plan.

### Request-Integrity Token Threat Model Is Narrower Than G1 Implies, Especially on WSL2 - Severity: Nit

* **Reviewer Lens:** `egm-zoom-out`
* **Affected Scope:** `Lines 25, 95-99, 191, 336` (G1, WSL2 deployment, security model)
* **Discrepancy Description**: The token is described as protecting mutations and, for LAN, as the access control. On WSL2, any local Windows process that can reach 127.0.0.1 can GET the server-rendered page, read the token, and then mutate; the token stops cross-origin browser POSTs, not local processes. The design says the token "is request integrity, not a user account" (line 191) and notes WSL2 localhost forwarding (line 336), but G1's "LAN access requires the same token" reads as authentication.
* **Rationale & Recommendation**: State the threat model in one place: the token protects against cross-site requests and unauthenticated network clients, not against local processes or a hostile Windows session. If local processes are in scope, add OS-level access control or accept the risk explicitly. Keep the token, but do not present it as access control.
