# Phase 0 Status

**Date:** 2026-11-06
**Host:** Ubuntu 26.04.1 LTS WSL2
**Design:** revision 5
**Plan:** `phase0_plan.md`

## Completed

* `uv` 0.13.7 installed; Python 3.12.16 installed; `.venv` created.
* `pyproject.toml` with `app`, `broker`, and `dev` extras; `uv.lock` generated and synced.
* Directory skeleton: `src/xentry`, `broker`, `config`, `scripts`, `tests`, `deploy`, `docs`, `targets`, `prompts`.
* `config/artifacts.yaml` with eleven entries and Gate G provenance fields.
* `config/image-manifests.yaml` with the three image profiles and baked package lists.
* `scripts/fetch-artifacts.sh` (catalog validator) and `scripts/build-images.sh`/`build-images.py` (manifest validation and QEMU/cloud-init image builds).
* `broker/registry.py` with the canonical target/profile/image/artifact/step ids and strict resolvers.
* `broker/main.py` Unix-socket server with peer-UID check, fixed-verb dispatch, unknown-id rejection, raw-argv rejection, idempotent destroy stubs, and `broker_calls.jsonl`.
* `src/xentry/broker.py` fixed-verb client.
* `tests/test_broker_contract.py` covering valid verbs, unknown ids, step allowlists, traversal rejection, idempotent destroy, peer UID, `http_probe`, and the journal.
* `broker/libvirt_ops.py` with the fixed `virsh` wrapper and typed network/domain XML builders.
* `tests/test_libvirt_ops.py` covering isolated-network XML, domain disks/seeds/network, and XML escaping.
* `broker/network_ops.py` with provisioning and locked nftables phase rules.
* `tests/test_network_ops.py` covering mirror-only provisioning and attacker-to-target locked rules.
* `broker/runtime.py` with network/VM lifecycle, image hash verification, per-job SSH keys, cloud-init seeds, overlays, DHCP wait, state files, idempotent destroy, artifact mirror start/stop, and `place_nonce`.
* `broker/mirror.py` static allowlisted artifact HTTP server on the bridge address.
* `broker/exec_ops.py` asyncssh transport for root/actor commands, nonce placement, and SFTP copy-in.
* Runtime `copy_in` with artifact-manifest hash verification and remote `sha256sum` verification.
* Runtime `read_host_evidence` over the host-owned serial log.
* `scripts/fetch-artifacts.py` and `scripts/fetch-artifacts.sh --download` for verified artifact files and `manifest.json`.
* `scripts/smoke_broker.py` two-VM broker smoke.
* `tests/test_runtime.py` with a fake libvirt backend for network lifecycle, image hash checks, mirror start/stop, and nonce validation.
* `tests/test_mirror.py` for allowlisted artifact serving.
* `src/xentry/models.py` with the typed contracts skeleton.
* `src/xentry/cli.py` with the `xentry cleanup` entry point.
* `deploy/xentry-broker.service`, `deploy/xentry.service`, `deploy/apparmor/xentry-vm` placeholder.
* `docs/adr/0001-v1-reset.md`.
* `tests/test_budget.py`: 4 tests passing.

## Check results

| Check | Result |
| --- | --- |
| `uv run xentry --help` | PASS |
| `pytest -q` | 60 passed |
| `ruff check src scripts broker tests` | PASS |
| `scripts/build-images.sh --dry-run` | PASS: 3 image manifests |
| `scripts/build-images.sh --execute` | PASS: 3 images built and hashed |
| `scripts/fetch-artifacts.sh --dry-run` | PASS: all eleven artifacts resolved |
| `scripts/fetch-artifacts.sh --download` | PASS: seven runtime artifacts downloaded and manifest written |
| `scripts/smoke_broker.py --start-mirror` | PASS: two VMs, mirror fetch, copy_in, nonce placement, exec, SSH, reachability, cleanup |
| `scripts/run_extractor_gate.py --runtime adk` | PASS: 20/20 facts, 2/2 invalid safe |

## Gate B smoke

A manual WSL2 smoke used the built `ubuntu-24.04-target.qcow2`, the isolated `xentry-smoke` network, a cloud-init NoCloud seed, and a 25 GB qcow2 overlay.

* The network was `10.42.0.0/24`, `<forward mode='none'/>`, with DHCP pins `10.42.0.10` (target) and `10.42.0.20` (attacker).
* The domain booted under KVM and received `10.42.0.10`.
* SSH succeeded as `root` and as `xentry-guest`; cloud-init wrote `/var/lib/xentry-smoke-ready`.
* Actor separation held: `sudo -n true` failed, `/root/xentry-nonce` was unreadable, and `/usr/bin/xentry-test` was unwritable for `xentry-guest`.
* The target image contains `apache2` and `build-essential`.
* Domain and network were destroyed and undefined cleanly.

Caveats: AppArmor is inactive on WSL2; QEMU used the developer UID (`1000:1000`) as a static DAC label, not `xentry-vm`; nftables rules were not applied because the current session is not root. Those three checks run on the deployment host.

Two-VM broker smoke (`scripts/smoke_broker.py`, run under `sg libvirt`):

* Broker socket `create_network` created `xentry-smoke-1` on `10.42.0.0/24`.
* `create_target` built the 25 GB target overlay, generated per-job root/actor keys, booted the target, and returned `10.42.0.10`.
* `create_attacker` booted the attacker and returned `10.42.0.20`.
* SSH as `root` and `xentry-guest` worked on the target; SSH as `root` worked on the attacker.
* The target fetched `php-8.4.26-src` from the on-bridge mirror; the SHA-256 matched the catalog.
* `copy_in` placed `poc-php2shell` at `/var/lib/xentry/artifacts/poc.tar.gz`; the actor read it and the remote SHA-256 matched.
* Broker `place_nonce` wrote `/root/xentry-nonce` as mode `600`, owner `root`, 32 bytes; the returned SHA-256 matched the runner value.
* `xentry-guest` could not read `/root/xentry-nonce`.
* The attacker reached the target on TCP 22.
* `list_managed` returned both running domains and the active network.
* Destroy order attacker → target → network left no `xentry-*` domains or networks; the mirror stopped.
* The guest wrote a marker to `/dev/ttyS0`; the host serial file contained data, but the unprivileged dev broker could not read the root-owned `0600` file. `read_host_evidence` is implemented and must be validated with the root broker on the deployment host.
* `nft_applied=false` for the dev smoke; the deployment host applies the phase rules.

## Artifact research helper

Added `src/xentry/artifact_tools.py`, `scripts/research-artifacts.py`, `scripts/pin-artifact.py`, and `tests/test_artifact_tools.py` (8 tests pass). Research writes only `var/research/artifacts-candidates.json`; it never writes `config/artifacts.yaml`. Pinning requires `--accept`, a source, and a downloaded SHA-256 match.

The helper now prefers deterministic vendor sources: the php.net release JSON, the GitLab apt `Packages.gz`, the Ubuntu security `Packages.gz`, and the dated Ubuntu cloud-image `SHA256SUMS`. The LLM path is a fallback for sources that have no structured parser; the DeepSeek pass alone did not resolve PHP, GitLab, or the kernel and is not treated as a trust source.

Verified and pinned external artifacts (all downloaded and hashed by `pin-artifact.py --accept`):

| Artifact | Version | SHA-256 | Source |
| --- | --- | --- | --- |
| `ubuntu-base-image` | 24.04 dated `release-20261017` | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` | cloud-images `SHA256SUMS` |
| `php-8.4.26-src` | 8.4.26 | `32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1` | php.net release JSON |
| `gitlab-19.2.5-deb` | 19.2.5-ce.0 | `d88005cd1ff3f47f52e72d4cdfb4830ae03e4ffed2f8c137d2ff2fdabe5c0dbc` | GitLab noble `Packages.gz` |
| `kernel-6.17.0-23` | 6.17.0-23.23~24.04.1 | `bf4dd0d202ce223878eed54b8f03cfcaa8162630ceed9b0428f1186eaf3ad74e` | Ubuntu security `Packages.gz` |
| `kernel-modules-6.17.0-23` | 6.17.0-23.23~24.04.1 | `101465bd48c827e0885a89712717b833313018fae22fd68a05a25029e4ea4f5f` | Ubuntu updates `Packages.gz` |
| `poc-php2shell` | commit `1670854` | `a720b7c94df4782ffc4cdbdc679d1ae26318c2ceb39ce090f9967d76fc8e6b05` | GitHub tarball |
| `poc-gitlab` | commit `e275edc` | `b879a9cb2fab7abb6a963daf5e8d72905ac1ae53e226f3777ad0719cb64849f3` | GitHub tarball |
| `poc-dirtyfrag` | commit `aab16fc` | `95fa7e3bcd4c1a8ddf2d4f341737cc708d80876bc3c5ff7850a17b73b2ecea43` | GitHub tarball |

Resolved: `linux-image-6.17.0-23-generic` depends on `linux-modules-6.17.0-23-generic`, so the modules package is now a separate catalog artifact, pinned for the runtime mirror. The contracts correction §N and the ADR amendment record the split; the Dirty Frag setup installs both `.deb`s.

Built derived images with `scripts/build-images.sh --execute`:

| Artifact | Build source | SHA-256 |
| --- | --- | --- |
| `ubuntu-target-image` | `build://ubuntu-base-image+target` | `e434c8cf811a7acf20accaa3553efd4e69994d8626ada92f3a8482d1f30a6d7e` |
| `ubuntu-dirtyfrag-image` | `build://ubuntu-base-image+dirtyfrag` | `a8fad0a9dfe403ec0163812c31950d0639730a40db75c512a50af2986496360e` |
| `ubuntu-attacker-image` | `build://ubuntu-base-image+attacker` | `852e947cbad7102fdc3e56d9ced9ed1b35ea9eac696492a8e59cfc034db02690` |

The vendor cloud image is `ubuntu-base-image`; the three built images build from it. The build is a full qcow2 copy of the pinned base customized by cloud-init in a KVM build VM. The hashes pin the exact built bytes. apt package versions are whatever noble-updates/security served at build time, so a rebuild is not bit-reproducible; re-pin after any rebuild.

## Gate status

* **Gate B:** PARTIAL. KVM, system libvirt, isolated two-VM network, cloud-init, broker-driven VM lifecycle, on-bridge artifact mirror, broker-only nonce placement, verified `copy_in`, SSH root/actor transport, actor separation, and attacker→target reachability pass in the WSL2 smoke. AppArmor is inactive, nftables is not yet applied, QEMU ran as the developer UID, and host serial evidence needs the root broker; final Gate B runs on the deployment host.
* **Gate E:** PASS with a memory caveat. 15 GiB is tight for GitLab (10 GB target+attacker) plus app/broker/host; 32 GiB recommended.
* **Gate F:** PASS. ADK extractor gate: 20/20 facts and 2/2 invalid fixtures safe; every citation quote verified against its artifact. DeepSeek does not accept JSON-schema `response_format`, so the ADK agent returns prompt-constrained JSON and Pydantic validates it.
* **Gate G:** PASS. Eight vendor artifacts are pinned and byte-verified; the three built images are hashed and pinned from `scripts/build-images.sh --execute`. The kernel image/modules split and the base/target image split are recorded in the contracts correction §N and the ADR amendment.

## Next actions

1. Build the Phase 1 app/runner: DB-backed jobs, fetch/extract/plan, broker steps, validator, API/UI, SSE.
2. Run the PHP target setup/readiness and fix build issues.
3. Run the two-VM target E2E with the checked-in scripts.
4. Implement `copy_out`, proxy capture, snapshots/reboot, and production host evidence.
5. Repeat Gate B AppArmor, nftables, and `xentry-vm` checks on the deployment host.
6. Record the reuse-spike result and finalize `docs/phase0_results.md`.

## Stop rules

Do not start Phase 1 until Gate G is resolved, the broker registry/contract tests pass, and the two-VM smoke is clean. AppArmor/QEMU-user Gate B checks run on the deployment host before the VM-boundary claim is final.
