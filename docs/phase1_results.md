# xentry V1 — Phase 1 Results

**Date:** 2026-11-07
**Design:** revision 5
**Environment:** WSL2, Ubuntu 26.04 host, system libvirt, unprivileged dev broker, 15 GiB RAM.

## Acceptance status

| Target | Outcome | Verdict | Decisive evidence |
| --- | --- | --- | --- |
| PHP2Shell | completed | reproduced | target HTTP probe contained the nonce |
| Dirty Frag | completed | reproduced | guest root shell + host serial nonce evidence |
| GitLab | completed | reproduced | target-side QEMU capture contained the nonce and its SHA-256 |

Final job records:

* PHP2Shell: `var/smoke/php-job4/app.db`, job `8173afdd726a47249331a056f5c869e9`; second clean run `var/smoke/php-job5/app.db`, job `aab62e45a1a24eeb828c00cf605ed7d7`; post-hardening run `var/smoke/php-posthardening/app.db`, job `c1a211013d7c4ead81528c4685daf947`.
* Dirty Frag: `var/smoke/dirtyfrag-final/app.db`, job `48aa3693a4024cd9915fad97a6cf3019`; second clean run `var/smoke/dirtyfrag-run2/app.db`, job `8a601f4b410b42b8b148c1d5a0e31932`; post-hardening run `var/smoke/dirtyfrag-posthardening/app.db`, job `00158916f5a54786934d32b2f73c4536`.
* GitLab: `var/smoke/gitlab-job4/app.db`, job `d4eb399ca0c04e14b60c8fc5e2ca7eee`; second clean run `var/smoke/gitlab-run2/app.db`, job `802ec092d28643b095b1ada84403171e`; post-hardening run `var/smoke/gitlab-posthardening/app.db`, job `e5ea7aef171148cbaf61970212e615b6`.

All three targets have two clean `reproduced` runs. Every job has 16/16
passed steps, `cleanup_state=done`, and no remaining managed libvirt
resources. A third PHP2Shell run (`c1a211013d7c4ead81528c4685daf947`) was
executed after the harness hardening and also completed `reproduced` with
16/16 steps and `nonce_hash_match`; it additionally verified 18 per-job broker
calls, a 59-record hash-chained event journal, and the audit bundle. A fresh
index rebuilt from that journal reproduced the same job, 16/16 steps, 18 broker
calls, two nonces, two artifacts, one validation, and one outcome.

The post-hardening GitLab run (`e5ea7aef171148cbaf61970212e615b6`) also
completed `reproduced` (`nonce_hash_match`) with 16/16 steps and
`cleanup_state=done`. It recorded 18 attributed broker calls including the
target-side `proxy_capture` call, 59 verified journal events, and a valid audit
bundle. A fresh index rebuilt from its journal reproduced the same job, 16/16
steps, 18 broker calls (including the capture), and one validation.

The post-hardening Dirty Frag run (`00158916f5a54786934d32b2f73c4536`)
completed `reproduced` (`nonce_observed_and_evidence_hash_match`) with 16/16
steps and `guest_attested+llm_assessed`. It recorded 16 attributed broker calls
including `read_host_evidence`, 57 verified journal events, and a valid audit
bundle. A fresh index rebuilt from its journal reproduced the same job, 16/16
steps, 16 broker calls (including the host-evidence read), and the validation.

## PHP2Shell (CVE-2026-109618)

The first two full jobs reached `real_actor` but failed in the PoC's infoleak stage. The harness, VM, freeze/restore, attacker build, and broker exec paths all passed:

* setup: 747–754 s (PHP 8.4.26 source build)
* readiness: `php=8.4.26 ready`
* freeze (`snapshot-create-as --memspec snapshot=internal` on the qcow2 overlay): passed in 4.9 s
* null actor and HTTP probe: no nonce
* restore: passed, including SSH readiness
* real actor: PoC exit 1, `leak failed (worker not single-prefork, or dtor offset wrong)`

The failure was target configuration, not the harness. `php.ini-production` changed output buffering and assertion behavior in a way that broke the PoC's `session.upload_progress` UAF infoleak. On the kept target VM:

1. Remove `/etc/php/php.ini` and keep PHP's built-in defaults.
2. Load the built OPcache extension (`zend_extension=opcache`).
3. Raise `max_multipart_body_parts` to 5000 for the PoC's spray requests.
4. Keep the pinned `zz-poc.ini` values (`memory_limit=8M`, `max_input_vars=1000`, session upload progress enabled).
5. Use `zif_system=0x466220`; the leaked code pointer for this build is at `0x645870`, so `--dtor-offset 0x645870`.

With those changes, the pinned PoC achieved RCE and wrote the target nonce:

```text
✓ chunk base 0x7e5446e00000   libphp base 0x7e5445600000   zif_system 0x7e5445a66220
RCE · r0 = 0x6a160
PROOF blind HIT: stage3 6.0s >= 2.8s (sleep 5s executed)
```

`/var/www/html/xentry-leak.txt` then contained the same 32-hex nonce as `/var/lib/xentry/nonce`.

The setup script now encodes these requirements; `targets/steps.yaml` pins the new script hashes. The fourth full job completed end-to-end:

```text
outcome   completed
verdict   reproduced
authority runner_observed+llm_assessed
reason    nonce_observed_and_evidence_match
cleanup   done
```

The third job had exposed a teardown bug: `virsh undefine` refused the target because the freeze snapshot left snapshot metadata. `Virsh.domain_undefine` now retries with `--snapshots-metadata`; the fourth job cleaned up fully. The failure was a harness cleanup bug, not an exploit or evidence failure.

### Why the offset is build-specific

The PoC discovers the `libphp` base by counting leaked pointers whose low 12 bits match the supplied destructor offset. The official Docker build's default does not match a source build on Ubuntu 24.04. The correct value was derived from a live leak:

```text
leaked pointer 0x7e5445c45870
libphp base    0x7e5445600000
dtor_offset    0x645870
```

The pointer lies inside the build's `rc_dtor_func` code region, not at its symbol start. Rebuilding PHP with different flags requires re-deriving this value; the setup/test checks pin the known-good configuration.

## GitLab target-side capture

`proxy_capture` is implemented in `broker/proxy.py` with two host-side paths.
The primary path attaches QEMU's `filter-dump` object to the target's tap netdev
through QMP, so the QEMU process (not root) records the target's bytes and the
broker only reads the pcap. Target domains now use `<driver name='qemu'/>`
(vhost off), which `filter-dump` requires. A live test on a target VM produced a
pcap with the expected request/response flow. If QEMU cannot attach the filter,
the runtime falls back to a `tshark` capture on the tap, which requires root.

The runner starts the capture in a separate broker call while the attacker runs
the GitLab PoC and uses the capture hash and parsed target-to-attacker text as
the decisive GitLab evidence. The broker server handles each connection in its
own thread so the blocking capture does not block `exec`. The parser is
unit-tested with synthetic pcaps. The unprivileged dev broker cannot use the
`tshark` fallback, but the QEMU path works without root.

GitLab is configured with `external_url 'http://10.42.0.10'` and Nginx gzip
off, so the target-side capture contains the nonce as plaintext. Apache is
stopped before the GitLab install to free port 80; monitoring services are
disabled and Puma/Sidekiq are reduced to fit the target.

The pinned PoC only echoes a file whose contents contain an invalid `%`
sequence. The real GitLab nonce file is therefore prefixed with `%zz` by the
pinned `prefix-gitlab-nonce` root step after `place_nonce`; the nonce value
itself remains the 32-hex secret, and the target probe checks that value in the
captured response. The same step appends `xentry-nonce-sha256:<hash>` so the
validator can match the runner facts without seeing the raw nonce. A manual
run against the first live target leaked `%zz<nonce>` and exited 0.

The second full GitLab job reached `real_actor` and `target_probe`; the captured
response contained `%zz<nonce>`, but the validator returned `inconclusive` with
`no_exploit_evidence` because the run script sent only `gitlab-poc-ran` to the
attacker transcript. The run script now echoes the verbose PoC log. The
validator prompt also states that a matching nonce SHA-256 in the evidence is
sufficient for a redacted nonce; a direct validator call with the job's facts
and hash-bearing target excerpt returned `reproduced` with reason
`nonce_hash_match`. The final GitLab job completed end-to-end:

```text
outcome   completed
verdict   reproduced
authority runner_observed+llm_assessed
reason    nonce_hash_match
cleanup   done
```

The target capture contained both the prefixed nonce and
`xentry-nonce-sha256:<hash>`, and the verbose attacker transcript showed the
Workhorse bypass and FILE LEAK stages.

## Dirty Frag

The target profile installs the pinned 6.17.0-23 kernel and modules, reboots, runs readiness again, and runs the PTY PoC as `xentry-guest`. Target domains expose the guest serial console through a QEMU TCP chardev; the broker reconnects across guest reboots and appends it to a broker-owned log. The PoC's root shell writes a labeled copy of the nonce and its command context to `/dev/ttyS0`, so `target_probe` reads host evidence rather than relying only on the attacker transcript.

The first Dirty Frag runs reached `real_actor` and observed the root shell and nonce, but the validator returned `inconclusive` because the serial file was root-only in the dev broker (`nonce_observed_without_host_evidence`) and later because the host-evidence excerpt shown to the validator was the start of a large serial log rather than the nonce context. The runner now sends a targeted host-evidence window around the nonce. The final Dirty Frag job completed end-to-end:

```text
outcome   completed
verdict   reproduced
authority guest_attested+llm_assessed
reason    nonce_observed_root_evidence
cleanup   done
```

A validator check with the same facts and a targeted host excerpt also returned `reproduced` with reason `nonce_observed`.

## Post-acceptance hardening

The three target acceptance runs above predate the following harness changes;
they do not alter the target evidence or verdicts.

* Web request integrity now checks Host, Origin (when present), the CSRF cookie
  and header, and JSON content type on every non-GET. Token failures are 401;
  CSRF/Host/Origin failures are 403.
* Link checks are claimed atomically, expire after 30 minutes, are single-use,
  and bind to the submitted URLs. A blocked submission releases the check.
* Evidence downloads verify the recorded SHA-256 before serving. Cancel
  rejects unknown jobs (404) and finished jobs (409). Steps, validations, and
  SSE routes return 404 for unknown jobs. Job state is projected separately
  from outcome/verdict/authority.
* `GET /api/jobs/<id>/bundle` returns a deterministic SQLite-index audit bundle
  with a manifest hash, artifact metadata, nonce hashes, outcomes, and broker
  call metadata. It contains no raw artifact bytes or nonce value.
* Restart recovery marks unfinished jobs `interrupted`, destroys managed
  resources attacker → target → network, and leaves cleanup pending when the
  broker is down. Failed cleanup blocks new submissions until the broker
  reports the resources gone.
* Every runner broker call carries job/attempt identity and a sequence; the
  broker journal is per job and the returned records are indexed into
  `broker_calls`. The job deadline (`XENTRY_JOB_DEADLINE_S`, default 7200 s) is
  checked before each step.
* Each attempt now has an append-only `events.jsonl` with a SHA-256 chain over
  job creation, plan, steps, nonce hashes, artifacts, broker calls, cleanup,
  validation, and outcome. The audit bundle includes it. `scripts/rebuild_index.py`
  verifies the chain and replays the journals into a fresh SQLite index.
* Broker teardown removes the per-job SSH key pair after both role state files
  are gone, while retaining them during a partial teardown for diagnosis.
* `pytest -q`: 112 passed; `ruff check src broker tests scripts`: clean;
  budget: 41 modules and about 7.8k handwritten lines (caps 44/8,000).

## Open items

* Run `scripts/verify_deployment.py` on the deployment host; resolve the root broker socket/units, nftables application, AppArmor, `xentry-vm`, and production capture/serial checks.
* Record deployment-host acceptance runs with job ids and evidence paths.
* Consider prebuilding the PHP/GitLab targets to reduce per-job setup time.
* Extend the audit bundle if raw, redacted evidence is required; the current bundle is a deterministic SQLite-index reconstruction with artifact names/hashes only.
