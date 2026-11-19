# Design Documents

| Document | Date | Author | Components | Description |
| --- | --- | --- | --- | --- |
| [derived-from-facts.md](derived-from-facts.md) | 2026-11-17 | zran147 | Extractor boundary, `generic.derive`, `release.resolve`, step/script ids, criteria, the step sequence, steps vs verbs vs privileged actions, npm generalisation | What the model decides and what the code derives from its facts, with the two version checks and the gap between them. |
| [xentry-v1.md](xentry-v1.md) | 2026-11-06 | zran147 | Target and attacker VM harness, root-owned broker with registry, proxy capture, and `http_probe`, isolated network and mirror, runner-owned nonce, extractor and validator, typed targets, SQLite/JSONL | xentry V1 revision 5: all three Linux targets, two VMs for remote PoCs, system libvirt broker, checked-in setup scripts, raised budget, normative contracts, and revision-5 corrections. |
| [xentry-v1-contracts.md](xentry-v1-contracts.md) | 2026-11-06 | zran147 | Broker registry, typed models, runner steps, target values, reason codes, DDL/API, tests, phase map, revision-5 corrections | Normative companion contracts for revision 5. |
| [xentry-v1-rev2.md](xentry-v1-rev2.md) | 2026-11-06 | zran147 | Revision 2 reviewed in `consolidated_review_report_rev2.md` | Historical revision 2. |
| [xentry-v1-rev1.md](xentry-v1-rev1.md) | 2026-11-05 | zran147 | Revision 1 reviewed in `consolidated_review_report.md` | Historical revision 1. |
| [naming.md](../naming.md) | 2026-11-19 | zran147 | proxy VM naming, `xentry-proxy.service`, `proxy_url`/`proxy_port`, the artifact mirror and `GATEWAY_IP` as deliberate exceptions | One machine had two names: the proxy VM was also the mirror VM. Everything about that machine is now proxy; the host-side artifact mirror keeps its word because it is one. |
| [initial_designs/](initial_designs/) | 2026-11-19 | zran147 | revisions 1-5, the review and readiness reports, phase 0 and 1 status | The 22 documents this project was generated from, moved out of the repository root. History: where they disagree with the ADRs or the code, the code is right. |
