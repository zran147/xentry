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
* A DeepSeek API key in `/etc/xentry/app.env`, or in `.env` for a local checkout. Never commit the key.
* No Docker or other container runtime.

The development host is WSL2 (Ubuntu 26.04.1). It passes KVM, libvirt, QEMU, nftables, and disk checks, but AppArmor is inactive there, so Gate B's AppArmor and QEMU-user checks must run on the deployment host.

## Install

Three commands, in this order.

```bash
sudo git clone https://github.com/zran147/xentry /opt/xentry
sudo /opt/xentry/install.sh                 # stops at step 7 for the key
sudo nano /etc/xentry/app.env               # put DEEPSEEK_API_KEY in it
sudo /opt/xentry/install.sh                 # continues from step 8
```

`install.sh` does not clone: it configures a host around the tree already at
`/opt/xentry`, and stops if that tree is missing rather than fetching something
you did not choose. It is every other command the deployment needs, in order,
announcing each as it starts it (`==> step 4/12  code and the two
virtualenvs`). It must run as root, and re-running is safe: users, groups,
directories and files are created only when they are missing.

**The minimum to run is one variable.** Every setting has a working default
except `DEEPSEEK_API_KEY`, which has no sensible one - `extract.py` and
`validator.py` raise `provider_unavailable` without it, and those two steps are
how a CVE becomes a plan. Step 7 writes `/etc/xentry/app.env` from
`.env.example` with the production paths already filled in, so that key is the
only line you must edit by hand. Everything else in the next section is worth
reading but optional.

| | |
|---|---|
| 1 | host packages |
| 2 | users, groups, and directories |
| 3 | `uv` and a private Python 3.12 under `/opt/uv-python` |
| 4 | code and the two virtualenvs |
| 5 | pinned artifacts and the three images |
| 6 | QEMU user and libvirt |
| 7 | environment files |
| 8 | systemd units and the services |
| 9 | AppArmor deny rules and the deployment verifier |
| 10 | optional: serve on a routable address |
| 11 | optional: the mirror VM |
| 12 | optional: developer access |
| 13 | first job |

**`DEV=1` makes the installed tree editable** instead of root-owned, which is
what you want when the loop is change the code, restart, look, change again.
It puts `src/`, `tests/`, `broker/` and `targets/` in a new `xentry-dev` group,
group-writable and setgid so later files inherit the group, and grants two
narrow `sudo` rules: restarting the two services, and `/usr/local/sbin/xentry-read`
for read-only diagnostics. It does **not** touch `/etc/xentry`,
`/var/lib/xentry` or either virtualenv, so `app.env` stays `640 root:xentry`
and a developer still cannot read the API key. Group membership needs a new
login shell; until then, `sg xentry-dev -c '<command>'` works in the current
one.

To take a host back to before step 1, `uninstall.sh` is the inverse: it removes
the services, the tree, the state, the VMs, the networks, the nftables tables,
the users and groups, and offers the host packages that nothing else needs. It
refuses unless you confirm, and it tells you what it is about to destroy first.

Step 7 is where it stops the first time, and nothing is enabled or started
until the key is in place - a half-configured service that fails on its first
job is worse than one that was never started. The next section is what each
variable in that file means.

Two optional steps are off unless you ask for them, and say so when skipped:

```bash
sudo XENTRY_BIND_ADDR=192.168.137.10 XENTRY_ADMIN_IPS="10.0.0.5" /opt/xentry/install.sh
sudo INSTALL_PROXY_VM=1 /opt/xentry/install.sh
sudo DEV=1 /opt/xentry/install.sh          # or DEV=1 DEV_USER=someone
```

**One tree, two virtualenvs.** The code lives only in `/opt/xentry`. The app
runs from `/opt/xentry/.venv` (the `app` and `dev` dependency groups) and the
broker from `/opt/xentry/.venv-broker` (the `broker` group: `asyncssh`,
`pyyaml`), with `WorkingDirectory=/opt/xentry`, so `broker.main`,
`config/artifacts.yaml` and `targets/` resolve from that one tree. There is no
`/opt/xentry-broker`. Do not put a `.env` file in the production tree; the
services read `/etc/xentry/app.env` and `/etc/xentry/broker.env`.

The broker unit runs `User=root Group=xentry` so `/run/xentry` and the broker
socket are accessible to the unprivileged `xentry` app. The broker still needs
root for libvirt and nftables, and it is what applies nftables. The app joins
no libvirt or KVM group and never receives guest SSH keys.

## Environment variables

The app service reads `/etc/xentry/app.env`; it does not use a development
`.env`. Step 7 of `install.sh` creates it from
[`.env.example`](.env.example), owned `root:xentry` mode `0640`, and sets the
production paths. Edit it with `sudoedit /etc/xentry/app.env`.

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

Everything but the key is already set by `install.sh`; the key is the one
thing it will not write for you.

For the experimental tab, which asks a model to write the PoC instead of
taking a PoC link, add a model as well. Any provider litellm speaks works; for
a local `llama.cpp` server use the `openai/` prefix and point the base at its
OpenAI-compatible endpoint:

```text
XENTRY_POC_MODEL=openai/qwen2.5-coder-7b-instruct
XENTRY_POC_API_BASE=http://127.0.0.1:8080/v1
XENTRY_POC_API_KEY=sk-local
XENTRY_POC_ATTEMPTS=3
```

`llama.cpp` ignores the key, but litellm requires one to be present. With
`XENTRY_POC_MODEL` empty the tab explains what to set and submits nothing,
which is why `install.sh` only mentions it and moves on.

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
and `XENTRY_APP_HOST` are read by nothing — `XENTRY_APP_HOST` is still in
`.env.example`, but the bind address is in the unit's `ExecStart`, which
defaults to `127.0.0.1`.

`XENTRY_ALLOWED_HOSTS` is the Host-header allowlist; add every hostname or
address you use to reach the app, without a port (the check compares the
hostname only). `localhost`, `127.0.0.1`, and `::1` are always allowed. A
missing entry is not a startup error: the app serves pages and then rejects
every POST with `403 host_invalid`.

### Serving on a routable address

The app has **no authentication**. The Host, Origin, CSRF, and JSON checks
stop cross-site requests, not a direct client: any client that can reach the
port may `GET /`, receive the token cookie, and `POST /api/jobs`. Submitting a
job detonates a real exploit in a VM on this host, and the evidence API serves
every stored artifact. Treat the listening socket as the access boundary.

Step 10 of `install.sh` does it only when you name both the address and the
clients allowed to reach it:

```bash
sudo XENTRY_BIND_ADDR=192.168.137.10 XENTRY_ADMIN_IPS="10.0.0.5 10.0.0.6" \
  ./install.sh
```

It overrides the bind with `/etc/systemd/system/xentry.service.d/10-bind.conf`
rather than editing the shipped unit, puts the address in
`XENTRY_ALLOWED_HOSTS`, and runs `scripts/install-webfilter.sh` with the
addresses you listed.

`scripts/install-webfilter.sh` builds `table inet xentry_admin`, which accepts
the app's port only from those addresses, accepts it on loopback, and drops it
from everywhere else. The chain policy is `accept` and only that one port is
filtered, so no other service can be locked out by it. The table is separate
from the broker's `inet xentry`: that one hooks `forward` and is deleted and
re-added on every job phase, while this one hooks `input` and the broker never
touches it. The script also installs `xentry-webfilter.service` so the rules
are re-applied on boot.

Binding to the routable address alone means `127.0.0.1:8000` is no longer
listening; reach the app at the address in the drop-in. Deleting the drop-in
and running `daemon-reload` plus `restart xentry` returns the app to loopback.

### /etc/xentry/broker.env

Step 7 writes the broker's own environment file, mode `0600` and `root:root`,
and leaves it alone if it already exists:

```text
XENTRY_BROKER_SOCKET=/run/xentry/broker.sock
XENTRY_DATA_DIR=/var/lib/xentry
XENTRY_IMAGE_DIR=/var/lib/xentry/images
XENTRY_ARTIFACT_MANIFEST=/var/lib/xentry/artifacts/manifest.json
XENTRY_ARTIFACT_CATALOG=/opt/xentry/config/artifacts.yaml
XENTRY_STEPS_MANIFEST=/opt/xentry/targets/steps.yaml
XENTRY_TARGETS_DIR=/opt/xentry/targets
XENTRY_APPLY_NFT=1
XENTRY_START_MIRROR=1
XENTRY_QEMU_USER=xentry-vm
XENTRY_START_APT_PROXY=1
XENTRY_START_REGISTRY_PROXY=1
```

The last two are both provisioning channels. Each is reachable from a guest
while it provisions and is closed by `lock_network` before any PoC runs, so
each is opted into here rather than assumed. Without the first, every derived
apt target fails at provision; without the second, every ecosystem target
does.

Do not put the DeepSeek key in `broker.env`.

### The mirror VM cut-over

The five package mirrors — apt snapshot, registry, OCI — have historically run
inside the broker process, as root on the host, bound to each job network's
gateway. [ADR 0002](docs/adr/0002-mirrors-in-their-own-vm.md) moves them into
a VM of their own, so a guest fetching a package is no longer a guest opening
a connection to a root process on this host. Step 11 of `install.sh` builds
it; [`deploy/proxy-vm/README.md`](deploy/proxy-vm/README.md) is what each
piece refuses to do and the failures that shaped it.

**Nothing is cut over until two variables are set** in `broker.env`, followed
by a restart of `xentry-broker`:

```text
XENTRY_WAN_BRIDGE=xentrywan0
XENTRY_PROXY_IP=10.44.0.2
```

With them unset, every nftables rule is byte-identical to the behaviour
without the VM, and the mirrors stay in the broker process — a test asserts
both shapes.

With them set, five things change together, and a test asserts that too: the
guests go on `xentry-target` and `xentry-attacker` (one bridge each, no host
address), their mirrors are addressed at `10.44.0.2` and reached by routing
through the VM, both phases are pushed to the VM instead of applied here, and
the persistent bridges are never destroyed with a job.

**No job has yet run through that path.** The first one is the test: watch its
provision step, and if it cannot fetch, the phase and the lease are the two
things to look at —

```bash
sudo /opt/xentry/scripts/proxy-vm-doctor.sh
sudo ssh -i /etc/xentry/proxy-vm.key root@10.44.0.2 \
  'nft list table inet xentry_phase; journalctl -u dnsmasq -n 30 --no-pager'
```

`/etc/xentry/proxy-vm.key` is generated on the VM's first run and is how the
broker configures it per job. Keep it; `REBUILD=1` reuses it.

## VM confinement

QEMU confinement comes from libvirt's AppArmor security driver, not from a
hand-written profile. With `security_driver = "apparmor"` in
`/etc/libvirt/qemu.conf` (step 6), libvirtd runs virt-aa-helper and switches
each domain's QEMU into a generated `libvirt-<uuid>` profile built from that
domain's own XML, so the permitted overlay, seed ISO, serial log, and backing
image are exactly this job's files. A profile attached to
`/usr/bin/qemu-system-x86_64` is never entered in that configuration, so there
is no static emulator profile to load.

`deploy/apparmor/local-libvirt-qemu` installs to
`/etc/apparmor.d/local/abstractions/libvirt-qemu`, which the distro
abstraction pulls into every generated domain profile. It only denies: app and
broker state under `/etc/xentry`, `/run/xentry`, `/opt/xentry`, and the
index/evidence/artifacts/mirror trees, plus writes to the pinned base images.
`scripts/install-apparmor.sh` syntax-checks it before installing, because a
bad rule here would break every VM on the host. Running domains keep their
current profile, so the rules apply to domains started from then on.

Step 9 runs `scripts/verify_deployment.py`, which checks the users, broker
socket/group, systemd units, the libvirt AppArmor security model, the deny
drop-in, the `libvirtd` and `virt-aa-helper` profiles, `/var/lib/xentry`
paths, manifests, KVM, and `virsh` — read-only, changing no host state. Its
`apparmor qemu confinement` check is advisory while the host is idle (nothing
is confined when no VM is running) and a required gate once a VM is up: it
fails if any running QEMU is unconfined or in complain mode. Re-run it during
a job to exercise that, and confirm nftables is in the locked phase at the
same time:

```bash
cd /opt/xentry
sudo .venv/bin/python scripts/verify_deployment.py \
  --artifacts-manifest /var/lib/xentry/artifacts/manifest.json \
  --images-manifest /var/lib/xentry/images/build-results.json
sudo nft list table inet xentry
```

Until those checks pass and a job has been observed with its QEMU enforcing
under a `libvirt-<uuid>` profile, the VM boundary is not a completed Gate B
claim.

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

The smoke scripts expect `sg libvirt -c '...'` on the WSL2 development host. `scripts/run_job_php.py` starts its own broker server and uses the real extractor and validator.

## Layout

`deploy/proxy-vm/` holds everything that is deployed **into** the mirror VM or
onto the host's permanent firewall — `serve.py`, its nftables rulesets, its
units, the phase renderer and the isolation probe. It sits outside `src/`,
`broker/` and `scripts/` so the VM's own code does not compete for the line
budget with the application that commands it.

```text
docs/designs/     design and normative contracts
config/           artifact and image manifests
broker/           root-owned broker (registry skeleton)
src/xentry/       app package (skeleton)
targets/          checked-in setup scripts
deploy/           systemd units and AppArmor profile
install.sh        the deployment, step by step
tests/            test suite
var/              runtime state, gitignored
```
