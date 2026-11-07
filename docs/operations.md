# xentry V1 — Operator Notes

These commands are for the development host. Production runs the broker as root
and the web app as the `xentry` app user; the app never joins libvirt.

## Acceptance status

All three pinned targets completed with `reproduced` verdicts on the WSL2
development host (PHP2Shell, Dirty Frag, GitLab). See
[`docs/phase1_results.md`](phase1_results.md) for job ids and evidence paths.

## Run one job end-to-end

```bash
sg libvirt -c 'cd /path/to/xentry_claude && \
  export PATH="$HOME/.local/bin:$PATH" PYTHONPATH="$PWD" && \
  uv run --env-file .env --extra app --extra dev --extra broker \
  python scripts/run_job_php.py \
    --data-dir var/smoke/<job-name> \
    --cve-url <cve-or-readme-url> \
    --poc-url <poc-repo-url> \
    --keep --keep-on-failure --deadline 5400'
```

`scripts/run_job_php.py` starts a broker and runner, submits one job, prints the
job record, steps, and validations, then exits. `--keep-on-failure` leaves the
VMs and keys under `var/smoke/<job-name>/broker/jobs/<job_id>/` for diagnosis.

### Pinned target inputs

| Target | CVE URL | PoC URL |
| --- | --- | --- |
| PHP2Shell | `https://raw.githubusercontent.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit/167085410a9342fafbd1bd64f5006920dbc83b8e/README.md` | `https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit` |
| GitLab | `https://raw.githubusercontent.com/gagaltotal/CVE-2026-85706-gitlab-poc/e275edcdd00dfd921c4b646f4a568a3a092a29a1/README.md` | `https://github.com/gagaltotal/CVE-2026-85706-gitlab-poc` |
| Dirty Frag | `https://raw.githubusercontent.com/V4bel/dirtyfrag/aab16fcada27142dd8ce8704906cf6736cf213b8/README.md` | `https://github.com/V4bel/dirtyfrag` |

### PHP2Shell target requirements

The pinned PoC depends on this build configuration:

* PHP 8.4.26 built from source, no `php.ini` (the built-in defaults).
* OPcache built and loaded (`zend_extension=opcache`).
* `zz-poc.ini` values from the PoC, plus `max_multipart_body_parts = 5000`.
* `zif_system=0x466220`; `dtor_offset=0x645870` (the leaked code pointer for
  this source build).
* Apache prefork with one worker; port 8088.

`targets/php2shell/setup.sh` owns these settings. Rebuilding PHP with different
flags or compiler versions requires re-deriving the leaked dtor offset.

### Capture evidence

GitLab's decisive evidence is a target-side capture. The broker attaches QEMU's
`filter-dump` to the target's netdev, so the QEMU process records the bytes and
the broker only reads the pcap; target domains use userspace virtio networking
(vhost off) for this. The broker adds execute permission on the job path so the
`xentry-vm` QEMU user can open the capture file, and the capture directory is
owned by that user. If QEMU cannot attach the filter, the runtime falls back
to a `tshark` tap capture, which needs root or `CAP_NET_RAW`/`CAP_NET_ADMIN`.

Dirty Frag's host evidence is the guest serial console. The target exposes a
QEMU TCP serial chardev on loopback; the broker reconnects across guest reboots,
appends the console to a broker-owned log, and reads the nonce context from that
log. The PoC writes a labeled nonce copy to `/dev/ttyS0` through its root shell.
PHP uses the trusted `http_probe`.

## Deployment host checklist

1. Install libvirt/QEMU, nftables, AppArmor, cloud-init tooling, Python 3.12, and `uv`.
2. Create the `xentry` app user and the `xentry-vm` QEMU user; configure libvirt to run QEMU as `xentry-vm`.
3. Install `deploy/xentry-broker.service` (root) and `deploy/xentry.service` (app user). The checked-in `deploy/apparmor/xentry-vm` is a placeholder; replace it with a tested host-specific profile and load it as root with `scripts/install-apparmor.sh <profile>`. The installer refuses the placeholder.
4. Pin the artifact catalog, images, and step hashes, then run the three acceptance jobs on the deployment host.
5. Verify nftables phase rules, AppArmor, `xentry-vm`, the root-owned capture/serial paths, and cleanup.

Run the read-only verifier as root after deployment so the AppArmor and
nftables checks can read host state. It exits non-zero on any required failure
and prints a JSON report with `--json`:

```bash
uv run python scripts/verify_deployment.py
```

The WSL2 development host is expected to fail the user, socket, unit, AppArmor,
and `/var/lib/xentry` checks; those are deployment-host gates.

### Web request integrity

Every non-GET request requires the `xentry_token` cookie, the
`X-Xentry-CSRF` header, an allowed `Host`, a matching `Origin` when the browser
sends one, and `Content-Type: application/json`. The default allowed hosts are
`localhost`, `127.0.0.1`, `::1`, and `testserver`; add deployment hostnames with
`XENTRY_ALLOWED_HOSTS`. Missing or invalid token cookies return 401; CSRF,
Host, and Origin failures return 403. API clients such as `curl` must send
`-H 'Content-Type: application/json'` even for an empty body.

### Audit bundle and recovery

`GET /api/jobs/<id>/bundle` returns a deterministic JSON audit bundle with job,
check, attempt, step, validation, outcome, nonce-hash, artifact metadata,
broker-call metadata, and the attempt event journal. It includes no raw
artifact bytes and no nonce value. The manifest hash covers every field except
`manifest_sha256`.

On app restart, `JobRunner.recover_interrupted` marks unfinished jobs
`interrupted`, destroys matching attacker/target domains and networks through
the broker, and records `cleanup_state`. If the broker is unavailable, cleanup
stays `pending`; run `xentry cleanup --force` once it is reachable. When a job
has `cleanup_state=failed`, new submissions return 409 until the broker reports
no matching managed resources; if the broker is unreachable, submission returns
503 and the link check is released for reuse.

The runner checks `XENTRY_JOB_DEADLINE_S` (default 7200) before every step. After
planning it applies the target cap from `XENTRY_JOB_TIMEOUT_PHP` (5400),
`XENTRY_JOB_TIMEOUT_GITLAB` (7200), or `XENTRY_JOB_TIMEOUT_DIRTYFRAG` (5400).
Failure is `deadline_exceeded`, followed by teardown. Per-call broker timeouts
bound a single hung step; they do not preempt it mid-call.

## Inspect and clean up

```bash
# Managed libvirt resources (through a running broker)
xentry --broker-socket var/smoke/<job>/broker.sock cleanup --status
xentry --broker-socket var/smoke/<job>/broker.sock cleanup --force

# If the broker is gone, use libvirt directly:
virsh list --all
virsh net-list --all
```

A target with an internal memory snapshot needs
`virsh undefine <domain> --nvram --snapshots-metadata`.

## Database and evidence

* `var/smoke/<job>/app.db` is the SQLite index.
* `var/smoke/<job>/app/jobs/<job_id>/attempt-0/` holds the fetched artifacts
  and the append-only hash-chained `events.jsonl`.
* Rebuild a fresh index from verified attempt journals (it refuses tampered
  chains and an existing database unless `--force` is given):

```bash
uv run python scripts/rebuild_index.py \
  --jobs-root var/smoke/<job>/app/jobs \
  --db var/smoke/<job>/rebuilt.db
```

* `var/smoke/<job>/broker/jobs/<job_id>/` holds VM state, keys, serial logs,
  exec logs (`exec-<step>-<ts>.json`), and GitLab captures (`capture/*.pcap`).
* The job, steps, validations, and outcomes are separate fields in the UI:
  a completed job with `not_run` or `inconclusive` is not a reproduced verdict.
