# xentry V1 — Phase 0 Results

**Date:** 2026-11-06
**Host:** Ubuntu 26.04.1 LTS on WSL2, Linux 6.18.54.1-microsoft-standard-WSL2
**Design:** `docs/designs/xentry-v1.md` revision 5
**Contracts:** `docs/designs/xentry-v1-contracts.md` revision 5, including correction §N

## Gate status

| Gate | Result | Notes |
| --- | --- | --- |
| B — broker, network, VM boundary | PARTIAL | KVM, system libvirt, isolated two-VM network, cloud-init, broker-driven lifecycle, on-bridge artifact mirror, broker-only nonce placement, verified `copy_in`, SSH root/actor, actor separation, and attacker→target reachability pass in the WSL2 smoke. AppArmor, nftables application, host serial evidence, and the final QEMU-user check need the deployment host. |
| E — host capacity | PASS with caveat | 15 GiB is tight for GitLab (8 GB) plus attacker (2 GB) and the host. 32 GiB recommended. |
| F — ADK extractor | PASS | 20/20 facts and 2/2 invalid fixtures safe; every citation quote verified. |
| G — artifact provenance | PASS | Eleven artifacts resolved; see below. |

## Gate G artifact pins

All external artifacts were downloaded and hashed by `scripts/pin-artifact.py --accept`. The two image builds and the target build were produced by `scripts/build-images.sh --execute` on this host.

| Artifact | Version / commit | SHA-256 | Provenance |
| --- | --- | --- | --- |
| `ubuntu-base-image` | 24.04 `release-20261017` | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` | cloud-images `SHA256SUMS` |
| `php-8.4.26-src` | 8.4.26 | `32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1` | php.net release JSON |
| `gitlab-19.2.5-deb` | 19.2.5-ce.0 | `d88005cd1ff3f47f52e72d4cdfb4830ae03e4ffed2f8c137d2ff2fdabe5c0dbc` | GitLab noble `Packages.gz` |
| `kernel-6.17.0-23` | 6.17.0-23.23~24.04.1 | `bf4dd0d202ce223878eed54b8f03cfcaa8162630ceed9b0428f1186eaf3ad74e` | Ubuntu security `Packages.gz` |
| `kernel-modules-6.17.0-23` | 6.17.0-23.23~24.04.1 | `101465bd48c827e0885a89712717b833313018fae22fd68a05a25029e4ea4f5f` | Ubuntu updates `Packages.gz` |
| `poc-php2shell` | `167085410a9342fafbd1bd64f5006920dbc83b8e` | `a720b7c94df4782ffc4cdbdc679d1ae26318c2ceb39ce090f9967d76fc8e6b05` | GitHub commit tarball |
| `poc-gitlab` | `e275edcdd00dfd921c4b646f4a568a3a092a29a1` | `b879a9cb2fab7abb6a963daf5e8d72905ac1ae53e226f3777ad0719cb64849f3` | GitHub commit tarball |
| `poc-dirtyfrag` | `aab16fcada27142dd8ce8704906cf6736cf213b8` | `95fa7e3bcd4c1a8ddf2d4f341737cc708d80876bc3c5ff7850a17b73b2ecea43` | GitHub commit tarball |
| `ubuntu-target-image` | built from base + target manifest | `e434c8cf811a7acf20accaa3553efd4e69994d8626ada92f3a8482d1f30a6d7e` | `scripts/build-images.sh --execute` |
| `ubuntu-dirtyfrag-image` | built from base + dirtyfrag manifest | `a8fad0a9dfe403ec0163812c31950d0639730a40db75c512a50af2986496360e` | `scripts/build-images.sh --execute` |
| `ubuntu-attacker-image` | built from base + attacker manifest | `852e947cbad7102fdc3e56d9ced9ed1b35ea9eac696492a8e59cfc034db02690` | `scripts/build-images.sh --execute` |

The built images are 25 GB virtual-size qcow2 overlays' flat results on a 3.5 GB base; the artifact is the flat qcow2. `apt` package versions are whatever noble-updates/security served on 2026-11-06. A rebuild is not bit-reproducible; re-pin after any rebuild.

Gate G corrections recorded during implementation:

* `linux-image-6.17.0-23-generic` depends on `linux-modules-6.17.0-23-generic`; both are pinned, mirrored, and installed by the Dirty Frag setup.
* The vendor cloud image is `ubuntu-base-image`; `ubuntu-target-image` is the built target image. All three image manifests use `ubuntu-base-image`.

## Gate B smoke evidence

Manual one-VM smoke on WSL2:

* Network `xentry-smoke`: `10.42.0.0/24`, `<forward mode='none'/>`, bridge `xentry0`, DHCP pins `10.42.0.10` and `10.42.0.20`.
* Domain `xentry-smoke-target`: built target image, 2 vCPU, 2 GB RAM, 25 GB overlay, cloud-init NoCloud seed.
* KVM boot; DHCP lease `10.42.0.10`.
* SSH as `root` and `xentry-guest` both succeeded; `/var/lib/xentry-smoke-ready` present.
* Actor checks: `sudo -n true` failed, `/root/xentry-nonce` read failed, `/usr/bin/xentry-test` write failed, `id -u` was `1001`.
* Target image has `apache2` and `build-essential` installed.
* Domain and network destroyed/undefined cleanly.

Caveats: AppArmor is inactive on WSL2, QEMU used static DAC label `1000:1000` instead of `xentry-vm`, and nftables was not applied because the session lacks root. The deployment host must repeat these checks.

## Broker socket

`broker/main.py` now provides:

* Unix-socket server, one newline-delimited JSON request per connection.
* `SO_PEERCRED` UID allowlist.
* Fixed-verb dispatch with unknown-verb and unknown-param rejection.
* Registry rejection for unknown target/profile/image/artifact/step ids.
* Raw-argv and unsanitized-path rejection.
* Idempotent destroy stubs.
* `broker_calls.jsonl` with `id`, job/attempt, seq, verb, `params_sha256`, timestamps, status, and `result_sha256`.

`src/xentry/broker.py` is the fixed-verb client. `tests/test_broker_contract.py` covers the contract.

`broker/network_ops.py` defines the two nftables phases: provisioning allows only the target-to-mirror path plus DHCP/DNS, and the locked phase allows only attacker-to-target declared ports. The rules are unit-tested but not applied on WSL2 because the session is not root.

`broker/runtime.py` now owns the real lifecycle behind the socket verbs:

* Verifies each image's SHA-256 against the artifact catalog before use.
* Creates per-job qcow2 overlays, SSH keys, and cloud-init seeds.
* Creates/starts the isolated network and pins target/attacker DHCP addresses.
* Creates/starts target and attacker domains, waits for DHCP leases, and returns `vm_id`/`guest_ip`.
* Destroys attacker, target, and network idempotently and removes overlays/seeds/XML.
* `list_managed` reports `xentry-*` domains and networks.

`scripts/fetch-artifacts.sh --download` downloads the seven runtime artifacts into `var/artifacts/`, verifies each hash, and writes `manifest.json`. `broker/mirror.py` serves only manifest ids at `/artifacts/<id>`; it has no directory listing. The runtime starts it on `10.42.0.1:8081` with the job network and stops it on network destroy.

`broker/exec_ops.py` uses the broker-held per-job root key for SSH and writes the nonce over stdin, not as a command-line argument. The nonce value never appears in the journal; only its SHA-256 does.

## Extractor gate

`src/xentry/extract.py` and `src/xentry/extract_adk.py` implement the labeled-artifact extractor. The ADK agent runs with no tools; DeepSeek rejects JSON-schema `response_format`, so the agent returns prompt-constrained JSON and Pydantic validates it. Every citation quote is checked against the referenced artifact text.

`scripts/run_extractor_gate.py --runtime adk` returned 20/20 facts and 2/2 invalid fixtures safe. The fixtures are in `tests/fixtures/facts/`.

## Two-VM broker smoke

`scripts/smoke_broker.py` ran through the broker socket under `sg libvirt`:

* Created network `xentry-smoke-1` on `10.42.0.0/24`.
* Created the PHP2Shell target VM at `10.42.0.10` and the attacker VM at `10.42.0.20`.
* SSH as `root` and `xentry-guest` succeeded on the target; SSH as `root` succeeded on the attacker.
* The runtime started the allowlisted artifact mirror on `10.42.0.1:8081`; the target fetched `php-8.4.26-src` and the SHA-256 matched the catalog.
* `copy_in` placed `poc-php2shell` at `/var/lib/xentry/artifacts/poc.tar.gz`; the actor read it and the remote SHA-256 matched.
* `place_nonce` wrote `/root/xentry-nonce` as mode `600`, owner `root`, 32 bytes; the returned SHA-256 matched the runner value.
* `xentry-guest` could not read `/root/xentry-nonce`.
* The attacker reached the target on TCP 22.
* `list_managed` returned both running domains and the active network.
* Destroyed attacker → target → network; no `xentry-*` resources remained and the mirror stopped.
* The guest wrote to `/dev/ttyS0`; the host serial file contained data, but the unprivileged dev broker could not read the root-owned `0600` file. `read_host_evidence` is implemented and must be validated with the root broker.
* `nft_applied=false` in the dev smoke; the deployment host must apply the phase rules.

## Checks run

```text
uv run --extra app --extra dev --extra broker pytest -q   # 60 passed
uv run --extra app --extra dev ruff check ...     # pass
scripts/fetch-artifacts.sh --dry-run              # Artifact gate G: PASS
scripts/build-images.sh --dry-run                 # Image manifest: PASS (3 images)
scripts/build-images.sh --execute                 # 3 images built
```

## Open Phase 0 items

1. Build the Phase 1 app/runner: DB-backed jobs, fetch/extract/plan, broker steps, validator, API/UI, SSE.
2. Run the PHP target setup/readiness and fix build issues.
3. Run the two-VM target E2E with the checked-in scripts.
4. Implement `copy_out`, proxy capture, snapshots/reboot, and root-broker host evidence.
5. Repeat Gate B AppArmor, nftables, and `xentry-vm` checks on the deployment host.
6. Record the reuse-spike result.
