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

* Ubuntu 26.04 LTS deployment host (24.04+ also supported) with KVM (`/dev/kvm`), system libvirt, QEMU, nftables, cloud-init tooling, `tshark`, and AppArmor for the final Gate B.
* Python 3.12 (installed and pinned through `uv`) and `uv`.
* A DeepSeek API key in `.env` for development or `/etc/xentry/app.env` for a systemd deployment. Never commit the key.
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

The production broker runs as root from `/opt/xentry-broker`; the app never joins `libvirt` and never receives guest SSH keys. nftables is applied by the production broker. AppArmor, nftables application, root-broker serial evidence, and the `xentry-vm` QEMU user are deployment-host checks. QEMU is confined by libvirt's AppArmor security driver, which generates a per-domain profile from the domain XML; there is no static emulator profile. After installing the units and the AppArmor deny drop-in, run `scripts/verify_deployment.py` as root; it reports every required deployment-host check without changing host state.

## Deployment setup (Ubuntu 26.04)

These commands install the production layout used by the checked-in systemd
units. Replace the `REPO_URL` example with your repository URL. Run the
commands in a normal shell with `sudo`; the broker and app services themselves
run as separate identities.

### 1. Host packages

```bash
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  qemu-system-x86 qemu-utils \
  libvirt-daemon-system libvirt-daemon-driver-qemu libvirt-clients \
  cloud-image-utils genisoimage xorriso \
  nftables apparmor apparmor-utils \
  tshark openssh-client \
  curl ca-certificates git \
  sqlite3
```

`qemu-system-x86` provides `qemu-system-x86_64`; `qemu-utils` provides
`qemu-img`; `cloud-image-utils` provides `cloud-localds`. `tshark` is required
to parse the target-side GitLab capture. The package installation may ask about
non-superuser packet capture; the broker runs as root and does not need the
`wireshark` group. The primary capture path is QEMU's `filter-dump`; the
checked-in broker unit also grants `CAP_NET_RAW` for the `tshark` tap fallback.

### 2. Users, groups, and directories

```bash
# Host service users. These are not the guest account xentry-guest, which is
# created inside each VM by cloud-init.
sudo groupadd --system xentry 2>/dev/null || true
sudo groupadd --system xentry-vm 2>/dev/null || true
id -u xentry >/dev/null 2>&1 || sudo useradd --system \
  --gid xentry --home-dir /var/lib/xentry --create-home \
  --shell /usr/sbin/nologin xentry
id -u xentry-vm >/dev/null 2>&1 || sudo useradd --system \
  --gid xentry-vm --home-dir /var/lib/xentry-vm --create-home \
  --shell /usr/sbin/nologin xentry-vm
sudo usermod -aG kvm xentry-vm

# App-owned state: SQLite index, app job attempts, broker job directories, and
# the broker mirror. Broker-created subdirectories remain root-owned.
sudo install -d -m 0750 -o xentry -g xentry /var/lib/xentry
sudo install -d -m 0750 -o xentry -g xentry /var/lib/xentry/jobs
sudo install -d -m 0750 -o xentry -g xentry /var/lib/xentry/mirror
# Read-only build inputs: images are read by QEMU; artifacts are read by the
# root broker and the app preflight, so the app group gets read access.
sudo install -d -m 0755 -o root -g root /var/lib/xentry/images
sudo install -d -m 0750 -o root -g xentry /var/lib/xentry/artifacts
sudo install -d -m 0750 -o root -g xentry /etc/xentry
```

The broker unit runs `User=root Group=xentry` so `/run/xentry` and the broker
socket are accessible to the unprivileged `xentry` app. The broker still needs
root for libvirt and nftables. The app is added to no libvirt or KVM group.

### 3. Install `uv` and Python 3.12

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
sudo install -m 0755 "$HOME/.local/bin/uv" /usr/local/bin/uv
sudo env UV_PYTHON_INSTALL_DIR=/opt/uv-python \
  /usr/local/bin/uv python install 3.12
sudo chmod -R a+rX /opt/uv-python
```

Ubuntu 26.04's system Python may be newer than 3.12. `uv` installs a private
3.12 under `/opt/uv-python`; the app and broker virtualenvs point at it. Keep
`/opt/uv-python` readable by `xentry`.

### 4. Install the code and virtualenvs

```bash
export REPO_URL=https://github.com/your-org/xentry.git
sudo git clone "$REPO_URL" /opt/xentry
sudo git clone "$REPO_URL" /opt/xentry-broker
sudo chown -R root:root /opt/xentry /opt/xentry-broker
sudo chmod -R go-w /opt/xentry /opt/xentry-broker
sudo chmod -R a+rX /opt/xentry /opt/xentry-broker

cd /opt/xentry
sudo env UV_PYTHON_INSTALL_DIR=/opt/uv-python \
  /usr/local/bin/uv sync --python 3.12 --extra app
sudo chmod -R a+rX /opt/xentry/.venv

cd /opt/xentry-broker
sudo env UV_PYTHON_INSTALL_DIR=/opt/uv-python \
  /usr/local/bin/uv sync --python 3.12 --extra broker

cd /opt/xentry
sudo .venv/bin/python -c 'import xentry; print(xentry.__file__)'
cd /opt/xentry-broker
sudo .venv/bin/python -c 'import broker; print(broker.__file__)'
```

The app import must resolve under `/opt/xentry/src`, and the broker import
under `/opt/xentry-broker/broker`.

The app stays in `/opt/xentry` and runs from its editable install. The broker
copy stays in `/opt/xentry-broker`; its unit starts it with that working
directory, so `broker.main`, `config/artifacts.yaml`, and `targets/` resolve
from the broker tree. Do not put a `.env` file in either production tree; the
services read `/etc/xentry/app.env` and `/etc/xentry/broker.env`.

### 5. Fetch pinned artifacts and build images

```bash
cd /opt/xentry
sudo env UV_BIN=/usr/local/bin/uv UV_PYTHON_INSTALL_DIR=/opt/uv-python \
  XENTRY_ARTIFACT_DIR=/var/lib/xentry/artifacts \
  scripts/fetch-artifacts.sh --download

sudo env UV_BIN=/usr/local/bin/uv UV_PYTHON_INSTALL_DIR=/opt/uv-python \
  XENTRY_IMAGE_DIR=/var/lib/xentry/images \
  scripts/build-images.sh --execute

sudo chown -R root:root /var/lib/xentry/images
sudo chmod -R a+rX /var/lib/xentry/images
sudo chown -R root:xentry /var/lib/xentry/artifacts
sudo chmod -R g+rX,o-rwx /var/lib/xentry/artifacts
```

`fetch-artifacts.sh` writes `manifest.json` under
`/var/lib/xentry/artifacts` with production paths. `build-images.sh` writes
`build-results.json` and the three qcow2 images under
`/var/lib/xentry/images`; it needs `/dev/kvm` and therefore must run on the
KVM-capable host, as root here.

### 6. QEMU user and libvirt

```bash
sudo systemctl enable --now apparmor
sudo systemctl enable --now libvirtd
sudo cp /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.orig
sudoedit /etc/libvirt/qemu.conf
```

Set or uncomment these values:

```text
user = "xentry-vm"
group = "kvm"
security_driver = "apparmor"
```

The QEMU process runs as user `xentry-vm` and group `kvm` so it can open
`/dev/kvm`. The broker chowns the overlay, seed, and serial files to the
`xentry-vm` user, so ownership still limits access to the job files.

Then restart libvirt and check the KVM path:

```bash
sudo systemctl restart libvirtd
sudo virsh -c qemu:///system net-list --all
sudo -u xentry-vm test -r /dev/kvm && echo "xentry-vm can read /dev/kvm"
```

The broker runs as root and drives libvirt; `xentry-vm` is only the QEMU
process identity. The broker makes the job directories traversable for QEMU and
chowns the overlay, seed, and serial files it owns to `xentry-vm`.

### 7. Environment files

The app service reads `/etc/xentry/app.env`; it does not use the development
`.env`. Copy the example and edit it:

```bash
sudo cp /opt/xentry/.env.example /etc/xentry/app.env
sudo chown root:xentry /etc/xentry/app.env
sudo chmod 0640 /etc/xentry/app.env
sudoedit /etc/xentry/app.env
sudo chown root:xentry /etc/xentry/app.env
sudo chmod 0640 /etc/xentry/app.env
```

Set at least:

```text
DEEPSEEK_API_KEY=<your-key>
XENTRY_DATA_DIR=/var/lib/xentry
XENTRY_DB_PATH=/var/lib/xentry/xentry.db
XENTRY_BROKER_SOCKET=/run/xentry/broker.sock
XENTRY_ALLOWED_HOSTS=localhost,127.0.0.1
XENTRY_IMAGES_MANIFEST=/var/lib/xentry/images/build-results.json
XENTRY_ARTIFACT_MANIFEST=/var/lib/xentry/artifacts/manifest.json
XENTRY_ARTIFACT_CATALOG=/opt/xentry/config/artifacts.yaml
XENTRY_STEPS_MANIFEST=/opt/xentry/targets/steps.yaml
XENTRY_TARGETS_DIR=/opt/xentry/targets
```

For the experimental tab, which asks a model to write the PoC instead of taking
a PoC link, add a model as well. Any provider litellm speaks works; for a local
`llama.cpp` server use the `openai/` prefix and point the base at its
OpenAI-compatible endpoint:

```text
XENTRY_POC_MODEL=openai/qwen2.5-coder-7b-instruct
XENTRY_POC_API_BASE=http://127.0.0.1:8080/v1
XENTRY_POC_API_KEY=sk-local
XENTRY_POC_ATTEMPTS=3
```

`llama.cpp` ignores the key, but litellm requires one to be present. With
`XENTRY_POC_MODEL` empty the tab explains what to set and submits nothing.

Keep the rest of `.env.example` values unless you change a budget or model.
An `nvd.nist.gov/vuln/detail/<CVE-ID>` link is resolved to the matching record
on NVD's REST API before it is fetched, because the detail page is rendered in
the browser: a plain GET of it returns the single-page-app shell for every
path, with no CVE data in it. The API needs no browser and yields the
description, CVSS metrics and affected-version configurations as fields.
`XENTRY_NVD_API_KEY` is optional and raises NVD's rate limit from 5 requests
per 30 seconds to 50; it is sent only to `services.nvd.nist.gov`, checked at
every redirect hop. Any other CVE link is fetched exactly as given.

There is no environment variable for the app's listen address: the bind lives
in the unit, and a non-loopback bind is the drop-in below. `XENTRY_APP_PORT`
and `XENTRY_APP_HOST` are read by nothing.

`XENTRY_ALLOWED_HOSTS` is the Host-header allowlist; add every hostname or
address you use to reach the app, without a port (the check compares the
hostname only). `localhost`, `127.0.0.1`, and `::1` are always allowed. A
missing entry is not a startup error: the app serves pages and then rejects
every POST with `403 host_invalid`.

`XENTRY_APP_HOST` in `.env.example` is not read by anything; the bind address
lives in the unit's `ExecStart`, which defaults to `127.0.0.1`.

#### Serving on a routable address

The app has **no authentication**. The Host, Origin, CSRF, and JSON checks
stop cross-site requests, not a direct client: any client that can reach the
port may `GET /`, receive the token cookie, and `POST /api/jobs`. Submitting a
job detonates a real exploit in a VM on this host, and the evidence API serves
every stored artifact. Treat the listening socket as the access boundary.

To serve on a routable address, override the bind with a drop-in rather than
editing the shipped unit, name the address in the Host allowlist, and install
the source allowlist:

```bash
sudo install -d -m 0755 /etc/systemd/system/xentry.service.d
sudo tee /etc/systemd/system/xentry.service.d/10-bind.conf >/dev/null <<'UNIT'
[Service]
ExecStart=
ExecStart=/opt/xentry/.venv/bin/uvicorn xentry.web.app:app --host 192.168.137.10 --port 8000
UNIT
sudo sed -i 's|^XENTRY_ALLOWED_HOSTS=.*|XENTRY_ALLOWED_HOSTS=192.168.137.10|' /etc/xentry/app.env
sudo /opt/xentry/scripts/install-webfilter.sh <admin-ip> [<admin-ip>...]
sudo systemctl daemon-reload && sudo systemctl restart xentry
```

`scripts/install-webfilter.sh` builds `table inet xentry_admin`, which accepts
the app's port only from the addresses you list, accepts it on loopback, and
drops it from everywhere else. The chain policy is `accept` and only that one
port is filtered, so no other service can be locked out by it. The table is
separate from the broker's `inet xentry`: that one hooks `forward` and is
deleted and re-added on every job phase, while this one hooks `input` and the
broker never touches it. The script also installs
`xentry-webfilter.service` so the rules are re-applied on boot.

Binding to the routable address alone means `127.0.0.1:8000` is no longer
listening; reach the app at the address in the drop-in. Deleting the drop-in
and running `daemon-reload` plus `restart xentry` returns the app to loopback.

Create the broker-only environment file:

```bash
sudo tee /etc/xentry/broker.env >/dev/null <<'EOF'
XENTRY_BROKER_SOCKET=/run/xentry/broker.sock
XENTRY_DATA_DIR=/var/lib/xentry
XENTRY_IMAGE_DIR=/var/lib/xentry/images
XENTRY_ARTIFACT_MANIFEST=/var/lib/xentry/artifacts/manifest.json
XENTRY_ARTIFACT_CATALOG=/opt/xentry-broker/config/artifacts.yaml
XENTRY_STEPS_MANIFEST=/opt/xentry-broker/targets/steps.yaml
XENTRY_TARGETS_DIR=/opt/xentry-broker/targets
XENTRY_APPLY_NFT=1
XENTRY_START_MIRROR=1
XENTRY_QEMU_USER=xentry-vm
# Both provisioning channels. Each is reachable from a guest while it
# provisions and is closed by lock_network before any PoC runs, so each is
# opted into here rather than assumed. Without the first, every derived apt
# target fails at provision; without the second, every ecosystem target does.
XENTRY_START_APT_PROXY=1
XENTRY_START_REGISTRY_PROXY=1
EOF
sudo chown root:root /etc/xentry/broker.env
sudo chmod 0600 /etc/xentry/broker.env
```

Do not put the DeepSeek key in `broker.env`.

### 8. Install and start the services

```bash
sudo install -m 0644 /opt/xentry/deploy/xentry-broker.service \
  /etc/systemd/system/xentry-broker.service
sudo install -m 0644 /opt/xentry/deploy/xentry.service \
  /etc/systemd/system/xentry.service
sudo systemctl daemon-reload
sudo systemctl enable --now xentry-broker.service
sudo systemctl enable --now xentry.service
sudo systemctl --no-pager status xentry-broker.service xentry.service
```

The broker unit creates `/run/xentry` with mode `0750` and group `xentry`; the
socket is mode `0660` and owned by `root:xentry`. Verify:

```bash
ls -l /run/xentry/broker.sock
curl -fsS http://127.0.0.1:8000/api/system   # or the address in the bind drop-in
```

The app is deliberately unauthenticated and loopback-only. Do not expose it to
the network. The CSRF token is request integrity, not a login account.

### 9. AppArmor and final deployment checks

QEMU confinement comes from libvirt's AppArmor security driver, not from a
hand-written profile. With `security_driver = "apparmor"` (step 6), libvirtd
runs virt-aa-helper and switches each domain's QEMU into a generated
`libvirt-<uuid>` profile built from that domain's own XML, so the permitted
overlay, seed ISO, serial log, and backing image are exactly this job's files.
A profile attached to `/usr/bin/qemu-system-x86_64` is never entered in that
configuration, so there is no static emulator profile to load.

Confirm the driver is active and install the xentry deny rules:

```bash
sudo virsh -r -c qemu:///system capabilities | grep -A2 '<secmodel>'
sudo /opt/xentry/scripts/install-apparmor.sh
```

The first command must list `apparmor` among the host security models; if it
lists only `dac`, fix `security_driver` in step 6 before going further.

`deploy/apparmor/local-libvirt-qemu` installs to
`/etc/apparmor.d/local/abstractions/libvirt-qemu`, which the distro
abstraction pulls into every generated domain profile. It only denies: app and
broker state under `/etc/xentry`, `/run/xentry`, `/opt/xentry`, and the
index/evidence/artifacts/mirror trees, plus writes to the pinned base images.
The installer syntax-checks it before installing, because a bad rule here
would break every VM on the host. Running domains keep their current profile,
so the rules apply to domains started from then on.

Until the deployment checks pass and a job has been observed with its QEMU
enforcing under a `libvirt-<uuid>` profile, the VM boundary is not a completed
Gate B claim.

Run the read-only deployment verifier as root, pointing at the production
manifests:

```bash
cd /opt/xentry
sudo .venv/bin/python scripts/verify_deployment.py \
  --artifacts-manifest /var/lib/xentry/artifacts/manifest.json \
  --images-manifest /var/lib/xentry/images/build-results.json
```

It checks the users, broker socket/group, systemd units, the libvirt AppArmor
security model, the deny drop-in, the `libvirtd` and `virt-aa-helper`
profiles, `/var/lib/xentry` paths, manifests, KVM, and `virsh`.

The `apparmor qemu confinement` check is advisory while the host is idle
(nothing is confined when no VM is running) and a required gate once a VM is
up: it fails if any running QEMU is unconfined or in complain mode. Re-run the
verifier during a job to exercise it, and confirm nftables is in the locked
phase at the same time:

```bash
sudo nft list table inet xentry
```

### 10. First job

Open `http://127.0.0.1:8000` (or the address in the bind drop-in) and submit
one of the pinned CVE/PoC pairs from
[`docs/operations.md`](docs/operations.md). The service logs show broker and
job progress:

```bash
sudo journalctl -u xentry-broker.service -f
sudo journalctl -u xentry.service -f
```

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
