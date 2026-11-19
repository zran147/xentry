# xentry V1 — Phase 1 Status

**Date:** 2026-11-07
**Design:** revision 5
**Phase 0:** see `phase0_status.md`; Gates B/E/F/G have passing evidence, with deployment-host checks outstanding.
**Phase 1:** all three targets completed two clean runs each with `reproduced` verdicts on the WSL2 development host; see `docs/phase1_results.md`.

## Implemented

* SQLite schema and migrations (`migrations/001_initial.sql`, `src/xentry/db.py`).
* SSRF-safe fetcher with validated-IP connections, redirect rechecks, and byte caps (`src/xentry/fetch.py`).
* Typed target instances from the pinned catalog and step manifest (`src/xentry/targets.py`).
* ADK extractor with prompt-constrained JSON, Pydantic validation, and quote verification (`src/xentry/extract.py`, `extract_adk.py`).
* LiteLLM validator with nonce/version clamps (`src/xentry/validator.py`).
* Job store projections and ordered runner (`src/xentry/jobstore.py`, `src/xentry/runner.py`).
* FastAPI web app with token/CSRF gate, link checks, jobs, steps, validations, evidence, SSE, cancel, preflight, and a no-inline-script UI (`src/xentry/web/`).
* Web hardening: separate 401 token vs 403 CSRF errors, Host and Origin checks, JSON-only mutations, evidence hash verification, terminal-job cancel rejection, queued/running/completed state projection, and an audit bundle (`src/xentry/bundle.py`).
* Restart recovery: unfinished jobs are marked `interrupted`; managed attacker/target/network resources are destroyed in order, with cleanup left pending when the broker is unavailable (`JobRunner.recover_interrupted`). A failed cleanup blocks new submissions until the broker reports the resources gone.
* Broker call attribution: every runner broker verb carries `job_id`, `attempt_id`, and a call sequence, and the returned call record is indexed into `broker_calls` for the audit bundle.
* Append-only attempt journal (`attempt-0/events.jsonl`) with a SHA-256 hash chain for job creation, plan, steps, nonce placement hashes, artifacts, broker calls, cleanup, validation, and outcomes. The audit bundle includes the journal; `scripts/rebuild_index.py` replays verified journals into a fresh SQLite index.
* Job deadline enforcement between steps (`XENTRY_JOB_DEADLINE_S`, default 7200 s), with teardown before failure projection.
* Deployment-host verification script (`scripts/verify_deployment.py`) for the root broker socket, units, AppArmor profile, QEMU user, KVM, paths, and manifests.
* Checked-in setup/build/run/null scripts for all three targets (`targets/`), hash-pinned in `targets/steps.yaml`.
* Broker runtime, mirror, nonce placement, copy-in/copy-out, HTTP probe, QEMU target capture, snapshots/restore, reboot, and SSH exec (`broker/`).
* Target-side `proxy_capture` evidence: the broker attaches QEMU's `filter-dump` to the target's netdev and parses target-to-attacker payload (with a root-only `tshark` tap fallback). The runner uses that capture, not the attacker transcript, as GitLab's decisive evidence.

## Evidence so far

* `pytest -q`: 112 passed.
* Web security tests cover missing/invalid token, CSRF, Host, Origin, content type, check TTL/single-use/URL binding, evidence tampering, and terminal cancel.
* Audit bundle tests cover reconstruction, deterministic manifest hashes, job scoping, and nonce/raw-evidence absence.
* Queue recovery tests cover interrupted jobs, destroy order, finished-job isolation, and broker-unavailable cleanup.
* ADK extractor gate: 20/20 facts, 2/2 invalid fixtures safe.
* Link-check path returns the PHP target plan from the pinned README.
* PHP setup and readiness through the broker: setup 747 s, readiness `php=8.4.26 ready`.
* First full PHP job reached `real_actor`; the PoC with its default Docker offsets failed in 10.5 s (`exploit_failed`). The built module has `zif_system=0x466220`.
* Second full PHP job passed setup/readiness/freeze/restore; `real_actor` still failed at the infoleak. The root cause was target configuration, not the harness: `php.ini-production` (output buffering and assertions) prevented the PoC's UAF leak. On the kept target, with no `php.ini`, OPcache loaded, and `max_multipart_body_parts=5000`, the PoC leaked memory and achieved RCE; the leaked code pointer is at `0x645870`, giving the correct build-specific `dtor_offset`. A manual run wrote the target nonce to `/var/www/html/xentry-leak.txt`.
* Fourth full PHP job completed end-to-end: outcome `completed`, verdict `reproduced`, authority `runner_observed+llm_assessed`, reason `nonce_observed_and_evidence_match`, cleanup `done`. The runner observed the target nonce through the HTTP probe after the freeze/restore real-actor path; the validator agreed.
* The third job had exposed a teardown bug: `virsh undefine` refused a target with memory-snapshot metadata. `Virsh.domain_undefine` now retries with `--snapshots-metadata`, and the fourth job cleaned up fully.
* Dirty Frag completed end-to-end: outcome `completed`, verdict `reproduced`, authority `guest_attested+llm_assessed`, reason `nonce_observed_root_evidence`, cleanup `done`. The kernel install, two reboots, post-boot readiness, PTY PoC, and host serial evidence all passed.
* GitLab completed end-to-end: outcome `completed`, verdict `reproduced`, authority `runner_observed+llm_assessed`, reason `nonce_hash_match`, cleanup `done`. The target capture contained the prefixed nonce and its matching SHA-256; the validator accepted the redacted evidence.
* All three targets have now completed with reproduced verdicts on the WSL2 development host.
* Second clean runs: PHP job `aab62e45a1a24eeb828c00cf605ed7d7`, Dirty Frag job `8a601f4b410b42b8b148c1d5a0e31932`, and GitLab job `802ec092d28643b095b1ada84403171e` all completed `reproduced`. All three targets now have two clean runs.
* Post-hardening PHP run `c1a211013d7c4ead81528c4685daf947` completed `reproduced` (`nonce_hash_match`) with 16/16 steps, `cleanup_state=done`, 18 broker calls attributed to the job and indexed, a verified 59-record event journal, and a valid audit bundle. Rebuilding a fresh index from the journal reproduced the job, 16/16 steps, 18 broker calls, two nonces, two artifacts, one validation, and one outcome.
* Post-hardening GitLab run `e5ea7aef171148cbaf61970212e615b6` completed `reproduced` (`nonce_hash_match`) with 16/16 steps, `cleanup_state=done`, 18 attributed broker calls including `proxy_capture`, a verified 59-event journal, and a valid audit bundle; its rebuilt index reproduced 16/16 steps, 18 broker calls, and the validation.
* Post-hardening Dirty Frag run `00158916f5a54786934d32b2f73c4536` completed `reproduced` (`nonce_observed_and_evidence_hash_match`) with 16/16 steps, `guest_attested+llm_assessed`, 16 attributed broker calls including `read_host_evidence`, a verified 57-event journal, and a valid audit bundle; its rebuilt index reproduced 16/16 steps, 16 broker calls, and the validation.
* Broker teardown now removes the shared per-job SSH key pair only after both role state files are gone, so a partial sweep leaves the remaining VM's keys usable.
* Two-VM smoke: mirror fetch, copy-in, nonce placement, exec, SSH, attacker→target reachability, cleanup.

## Deployment-host verifier on WSL2

`scripts/verify_deployment.py` passes Python, KVM, `virsh`, the artifact manifest, and the image build results. It correctly fails the required user, broker socket, systemd unit, AppArmor, and `/var/lib/xentry` checks on this development host. These failures are expected and are the remaining Gate B items; run the verifier as root after installing the units and a tested profile.

## Known risks

* The PHP2Shell PoC is sensitive to the target build. The target must keep PHP's built-in ini defaults (no `php.ini-production`), load OPcache, and raise `max_multipart_body_parts`; `dtor_offset=0x645870` is the leaked code pointer for this build. Rebuilding PHP with different flags requires re-deriving that offset from a live leak.
* GitLab needs 8 GB target memory plus 2 GB attacker memory; the 15 GiB WSL2 host is tight (Gate E caveat).
* Dirty Frag host serial evidence uses a QEMU TCP chardev, so the unprivileged dev broker can read it; the root broker still owns the log in production. The legacy root-only serial file is only a fallback.
* nftables phase rules are implemented but not applied on WSL2; AppArmor and `xentry-vm` are deployment-host checks. `scripts/verify_deployment.py` reports these gaps without mutating the host.
* The audit bundle is SQLite-index reconstruction with artifact metadata and hashes, not raw artifact bytes; raw evidence stays in the job directory. It contains no nonce value.
* Restart recovery cannot resume a lost in-memory job. It marks the job `interrupted` and cleans broker-managed resources; when the broker is down, cleanup remains `pending` for `xentry cleanup --force`.
* GitLab target capture uses QEMU `filter-dump` and works on the unprivileged dev broker; the `tshark` fallback needs root. Target VMs use userspace virtio networking (vhost off) so QEMU can attach the filter; the attacker keeps vhost. Nginx gzip is off, and the pinned PoC needs the nonce file prefixed with `%zz` (done by `prefix-gitlab-nonce`) so the file-read error echoes the nonce.
* Dirty Frag runs the PoC over SSH and writes host evidence to the guest serial console; the broker captures the QEMU TCP serial chardev across reboots. The validator receives a nonce-centered host-evidence window, so the verdict no longer depends on the attacker transcript alone. The authority remains `guest_attested+llm_assessed` because the guest root shell produces the serial bytes.

## Next

1. Run `scripts/verify_deployment.py` on the deployment host and resolve every required failure: root broker socket/units, nftables application, AppArmor, `xentry-vm`, host serial/capture paths, and cleanup.
2. Add deployment-host acceptance runs and record job ids/evidence paths.
3. Consider prebuilding the PHP/GitLab targets to reduce per-job setup time.
4. Keep the remaining contract work visible: prompt-injection corpus, full audit evidence inclusion, and the VM-boundary acceptance runs.
