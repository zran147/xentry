# xentry V1

Local CVE reproduction with a target VM and, for remote PoCs, a lightweight attacker VM.

**Design:** [docs/designs/xentry-v1.md](docs/designs/xentry-v1.md)
**Normative contracts:** [docs/designs/xentry-v1-contracts.md](docs/designs/xentry-v1-contracts.md)
**Phase 0 plan:** [phase0_plan.md](phase0_plan.md)
**Host preflight:** [phase0_host_preflight.md](phase0_host_preflight.md)
**Operator notes:** [docs/operations.md](docs/operations.md)

## Status

Revision 5 is frozen. Phase 0 gates B/E/F/G have passing evidence on the WSL2 development host, with the deployment-only Gate B items listed in [phase0_status.md](phase0_status.md). The broker, two-VM lifecycle, artifact mirror, nonce placement, ADK extractor, validator, SQLite index, job runner, and web API/UI are implemented. PHP2Shell, Dirty Frag, and GitLab all completed end-to-end with reproduced verdicts on the development host; deployment-host checks remain. The web app now enforces Host/Origin/CSRF/JSON request integrity, verifies evidence hashes before serving, provides a deterministic audit bundle, and marks/cleans unfinished jobs on restart. Each attempt also keeps a hash-chained `events.jsonl` journal. `scripts/verify_deployment.py` reports the remaining deployment-host gaps.

The LLM verdict is an assessment, not a deterministic proof and not a production risk assessment.

## Requirements

* Ubuntu 24.04+ host with KVM (`/dev/kvm`), system libvirt, QEMU, nftables, cloud-init tooling, and AppArmor for the final Gate B.
* Python 3.12 and `uv`.
* A DeepSeek API key in `.env` for the extractor and validator.
* No Docker or other container runtime.

The current development host is WSL2 (Ubuntu 26.04.1). It passes KVM, libvirt, QEMU, nftables, and disk checks, but AppArmor is inactive. Gate B's AppArmor and QEMU-user checks must run on the deployment host.

## Quick start

```bash
cp .env.example .env          # fill DEEPSEEK_API_KEY; never commit .env
uv sync --extra app --extra dev --extra broker
scripts/fetch-artifacts.sh --download
scripts/build-images.sh --execute          # first run or after a manifest change
pytest -q
```

For development on the WSL2 host, run the broker under the `libvirt` group and the app as the normal user:

```bash
sg libvirt -c 'cd "$PWD" && \
  XENTRY_BROKER_SOCKET="$PWD/var/run/broker.sock" \
  XENTRY_DATA_DIR="$PWD/var/lib" \
  XENTRY_IMAGE_DIR="$PWD/var/images" \
  XENTRY_ARTIFACT_CATALOG="$PWD/config/artifacts.yaml" \
  XENTRY_ARTIFACT_MANIFEST="$PWD/var/artifacts/manifest.json" \
  XENTRY_STEPS_MANIFEST="$PWD/targets/steps.yaml" \
  XENTRY_TARGETS_DIR="$PWD/targets" \
  XENTRY_APPLY_NFT=0 XENTRY_QEMU_USER="$USER" \
  PYTHONPATH="$PWD" uv run --extra app --extra broker python -m broker.main'

XENTRY_BROKER_SOCKET="$PWD/var/run/broker.sock" \
XENTRY_DATA_DIR="$PWD/var/instance" \
XENTRY_DB_PATH="$PWD/var/instance/xentry.db" \
uv run --env-file .env --extra app uvicorn xentry.web.app:app --host 127.0.0.1 --port 8000
```

The production broker runs as root from `/opt/xentry-broker`; the app never joins `libvirt` and never receives guest SSH keys. nftables is applied by the production broker. AppArmor, nftables application, root-broker serial evidence, and the `xentry-vm` QEMU user are deployment-host checks. After installing the units and a tested AppArmor profile, run `scripts/verify_deployment.py` as root; it reports every required deployment-host check without changing host state.

## Phase 0 checks

```bash
scripts/fetch-artifacts.sh --dry-run       # Gate G catalog
scripts/fetch-artifacts.sh --download      # runtime artifact files + manifest
scripts/build-images.sh --dry-run          # image manifests and tools
scripts/build-images.sh --execute          # build and hash the three images
pytest -q                                  # unit and contract tests
scripts/run_extractor_gate.py --runtime adk # Gate F (needs DEEPSEEK_API_KEY)
scripts/smoke_broker.py --start-mirror     # two-VM broker smoke
scripts/run_target_php.py                  # PHP setup + readiness
scripts/run_job_php.py                     # full PHP job through the runner
```

The smoke scripts expect `sg libvirt -c '...'` on the WSL2 host. `scripts/run_job_php.py` starts its own broker server and uses the real extractor and validator.

## Layout

```text
docs/designs/     design and normative contracts
config/           artifact and image manifests
broker/           root-owned broker (registry skeleton)
src/xentry/       app package (skeleton)
targets/          checked-in setup scripts
deploy/           systemd units and AppArmor profile
tests/            test suite
var/              runtime state, gitignored
```
