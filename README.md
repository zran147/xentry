# xentry

Local CVE reproduction with a target VM and, for remote PoCs, a lightweight attacker VM.

**Design:** [docs/designs/xentry-v1.md](docs/designs/xentry-v1.md)
**Normative contracts:** [docs/designs/xentry-v1-contracts.md](docs/designs/xentry-v1-contracts.md)
**Decisions:** [docs/adr/](docs/adr/)
**What is derived from facts, and how:** [docs/designs/derived-from-facts.md](docs/designs/derived-from-facts.md)
**Operator notes:** [docs/operations.md](docs/operations.md)

## Status

Local CVE reproduction: a CVE link and a PoC link go in, two VMs come up, the
exploit runs against a real vulnerable build, and the verdict is a nonce the
PoC had to plant plus evidence hashes that match.

Four jobs have reproduced end to end on this deployment — CVE-2021-41773
(Apache path traversal) and three runs of CVE-2025-32463 (sudo chroot local
privilege escalation) — each with `nonce_observed` and matching evidence
hashes. 893 tests pass.

Two things are in flight. The package mirrors have moved out of the broker
process into a VM of their own ([ADR 0002](docs/adr/0002-mirrors-in-their-own-vm.md)),
which is the path those four jobs ran through. Harness mode, where a model
provisions the target itself and produces a reusable provisioning script
([ADR 0003](docs/adr/0003-the-model-provisions-the-target.md),
[ADR 0004](docs/adr/0004-free-exec-and-the-tool-surface.md)), is implemented
and wired in but has not yet completed a job.

The LLM verdict is an assessment, not a deterministic proof and not a
production risk assessment.

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

| # | step |
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
| 11 | the proxy VM |
| 12 | optional: developer access |
| 13 | first job |

**`DEV=1` makes the installed tree editable** instead of root-owned, which is
what you want when the loop is change the code, restart, look, change again.
It is step 12, and it does four things:

- Puts `src/`, `tests/`, `broker/` and `targets/` in a new `xentry-dev` group,
  group-writable and setgid so files created later inherit the group rather
  than reverting to root-only.
- Adds the invoking user (`$SUDO_USER`, or `DEV_USER=`) to that group.
- Grants two narrow `sudo` rules: restarting the two services, and
  `/usr/local/sbin/xentry-read` for read-only diagnostics. Each is parsed
  before it is installed and the whole sudo configuration is re-parsed after,
  because a malformed file in `/etc/sudoers.d` can make `sudo` refuse every
  command.
- Lets `XENTRY_ADMIN_IPS` be empty: the app's port then accepts **any** source
  address instead of refusing to publish. The install says so in full when it
  happens, because the app has no authentication.

It does **not** touch `/etc/xentry`, `/var/lib/xentry` or either virtualenv, so
`app.env` stays `640 root:xentry` and a developer still cannot read the API
keys. Group membership needs a new login shell; until then `sg xentry-dev -c
'<command>'` works in the current one.

To take a host back to before step 1, `uninstall.sh` is the inverse: it removes
the services, the tree, the state, the VMs, the networks, the nftables tables,
the users and groups, and offers the host packages that nothing else needs. It
refuses unless you confirm, and it tells you what it is about to destroy first.

Step 7 is where it stops the first time, and nothing is enabled or started
until the key is in place - a half-configured service that fails on its first
job is worse than one that was never started. The next section is what each
variable in that file means.

Two steps are off unless you ask for them, and say so when skipped:

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

The app service reads `/etc/xentry/app.env`, owned `root:xentry` mode `0640`.
Step 7 of `install.sh` creates it from [`.env.example`](.env.example) with
every path already set; edit it with `sudoedit /etc/xentry/app.env`.

Two settings are yours to make:

```text
DEEPSEEK_API_KEY=<your-key>
XENTRY_ALLOWED_HOSTS=localhost,127.0.0.1
```

`DEEPSEEK_API_KEY` is the only one with no usable default — `extract.py` and
`validator.py` refuse with `provider_unavailable` without it, and those two
steps are how a CVE becomes a plan.

`XENTRY_ALLOWED_HOSTS` is the Host-header allowlist: add every hostname or
address you use to reach the app, without a port. `localhost`, `127.0.0.1` and
`::1` are always allowed. A missing entry is not a startup error — the app
serves pages and then rejects every POST with `403 host_invalid`, which is a
confusing way to find out.

For the experimental tab, which asks a model to write the PoC instead of taking
a PoC link, add a model. Any provider litellm speaks works; for a local
`llama.cpp` server use the `openai/` prefix and point the base at its
OpenAI-compatible endpoint:

```text
XENTRY_POC_MODEL=openai/qwen2.5-coder-7b-instruct
XENTRY_POC_API_BASE=http://127.0.0.1:8080/v1
XENTRY_POC_API_KEY=sk-local
XENTRY_POC_ATTEMPTS=3
```

`llama.cpp` ignores the key but litellm requires one to be present. Leaving
`XENTRY_POC_MODEL` empty disables the tab, which is a valid state.

Two optional API keys raise rate limits, and each is sent only to its own
host, checked at every redirect hop. `XENTRY_NVD_API_KEY` takes NVD from 5
requests per 30 seconds to 50. `XENTRY_GITHUB_TOKEN` matters more: GitHub
allows 60 requests an hour **per address** unauthenticated and every check
spends one listing the PoC repository, so a sweep of sixty CVEs exhausts it —
and each check after that reads an empty listing, which the extractor reports
as "the PoC text does not name a file that runs the exploit". That is a
verdict about content for a file list it never read, so the failure does not
look like a rate limit. A fine-grained token with no scopes raises it to 5,000.

The broker has its own file, `/etc/xentry/broker.env`, mode `0600` and
`root:root`. `install.sh` writes it and there is nothing in it you need to
change. The DeepSeek key does not belong in it.

### Serving on a routable address

The app has **no authentication**. The Host, Origin, CSRF, and JSON checks
stop cross-site requests, not a direct client: any client that can reach the
port may `GET /`, receive the token cookie, and `POST /api/jobs`. Submitting a
job detonates a real exploit in a VM on this host, and the evidence API serves
every stored artifact. Treat the listening socket as the access boundary.

**This is a bind, not a Host-header question.** Adding an address to
`XENTRY_ALLOWED_HOSTS` does not publish the app: the listen address lives in
the unit's `ExecStart`, and with it unset nothing on the network can reach the
port to have its `Host` checked at all.

Both settings live in `app.env`, and step 7 stops for them along with the API
key:

```text
XENTRY_BIND_ADDR=192.168.137.10
XENTRY_ADMIN_IPS=10.0.0.5 10.0.0.6
```

Step 10 then overrides the bind with
`/etc/systemd/system/xentry.service.d/10-bind.conf` rather than editing the
shipped unit, adds the address to `XENTRY_ALLOWED_HOSTS`, and runs
`scripts/install-webfilter.sh` with the sources you listed. Passing either as
an environment variable still works for a one-off and wins over the file.

Leaving `XENTRY_ADMIN_IPS` empty **refuses** to publish — except under `DEV=1`,
where it means `0.0.0.0/0` and the install says so in full. That is a
development convenience and nothing else: it puts an unauthenticated port on
every network this host is attached to.

The filter it installs is a separate nftables table from the broker's, which
the broker deletes and re-adds on every job phase; this one it never touches.
Only the app's port is filtered and the chain policy is `accept`, so no other
service can be locked out by it, and a unit re-applies it on boot.

Binding to the routable address alone means `127.0.0.1:8000` is no longer
listening; reach the app at the address in the drop-in. Deleting the drop-in
and running `daemon-reload` plus `restart xentry` returns the app to loopback.

### The proxy VM

The five package mirrors — apt snapshot, registry, OCI — used to run inside the
broker process, as root on the host, bound to each job network's gateway.
[ADR 0002](docs/adr/0002-mirrors-in-their-own-vm.md) moved them into a VM of
their own, so a guest fetching a package is no longer a guest opening a
connection to a root process on this host. Step 11 of `install.sh` builds it;
[`deploy/proxy-vm/README.md`](deploy/proxy-vm/README.md) is what each piece
refuses to do and the failures that shaped it.

**One machine, two names.** The proxy VM and the proxy VM are the same thing.
The code and paths say proxy — `deploy/proxy-vm/`, `scripts/proxy-vm-up.sh`,
`XENTRY_PROXY_IP` — while the unit and these docs say mirror
(`xentry-proxy.service`). Nothing switches on the difference.

**It is not optional.** `install.sh` builds it on every run, and
`SKIP_PROXY_VM=1` is the opt-out rather than a flag to opt in. The broker
addresses `10.44.0.2` over `xentrywan0` whether or not that machine exists:
`proxy_ip` falls back to the constant `PROXY_VM_IP` and is never empty, so all
nine `if self.proxy_ip:` branches in the runtime are taken and the two
`if not self.proxy_ip:` guards are unreachable. Without the VM there are no
package mirrors, and every job fails at provision. The bring-up is idempotent
and refuses to finish unless its isolation probe passes inside the VM, so
re-running the step costs little.

One value addresses it, and `install.sh` writes it into `broker.env`:

```text
XENTRY_PROXY_IP=10.44.0.2
```

These are not a switch. They are defaults in the broker as well, and an empty
value does not fall back to running the mirrors on the host — that path no
longer exists. With them in effect the guests sit on `xentry-target` and
`xentry-attacker` with one bridge each and no host address, their mirrors are
reached by routing through the VM, both firewall phases are pushed to the VM
rather than applied here, and the persistent bridges outlive a job.

When a provision step cannot fetch, the phase and the lease are the two things
to look at:

```bash
sudo /opt/xentry/scripts/proxy-vm-doctor.sh
sudo ssh -i /etc/xentry/proxy-vm.key root@10.44.0.2 \
  'nft list table inet xentry_phase; journalctl -u dnsmasq -n 30 --no-pager'
```

## Services

Four on the host, two inside the proxy VM.

| unit | runs as | what it does |
|---|---|---|
| `xentry.service` | `xentry` | The web app: UI, JSON API, evidence and audit bundles. Unprivileged and owns no VM; everything it needs done it asks the broker for. Binds `127.0.0.1` unless `XENTRY_BIND_ADDR` says otherwise. |
| `xentry-broker.service` | `root` | The only thing that touches libvirt, nftables, QEMU and the job directories. Listens on `/run/xentry/broker.sock`, and `SO_PEERCRED` decides who may call. Accepts 27 named verbs and nothing else. |
| `xentry-wan-firewall.service` | `root` | The permanent host rules for the proxy VM's bridge: `table inet xentry_wan`. Re-applied at boot, because a bridge with no filter is a guest with a route to your network. |
| `xentry-webfilter.service` | `root` | Re-applies `table inet xentry_admin` at boot — the source allowlist for the app's port. Installed only when `XENTRY_BIND_ADDR` publishes the app. |
| `xentry-proxy.service` | `root`, in the VM | The package proxies for one job: apt snapshot, registry (npm/PyPI), OCI. This is why the VM exists — a guest fetching a package no longer opens a connection to a root process on the host. |
| `xentry-job-nics.service` | `root`, in the VM | Addresses the job bridges inside the VM and serves DHCP on them. |

The two host firewall tables never overlap: `xentry_wan` hooks `forward` and is
rebuilt per job phase, `xentry_admin` hooks `input` and the broker never
touches it.

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

## Layout

```text
/opt/xentry/              the one code tree; root-owned, 755
  .venv/                  app virtualenv (app + dev groups)
  .venv-broker/           broker virtualenv (asyncssh, pyyaml)
  src/xentry/             the app package: runner, extractor, validator, web
  broker/                 the root broker; imports nothing from src/
  targets/                checked-in step scripts, digests in steps.yaml
  config/                 artifact and image catalogues
  deploy/                 systemd units, AppArmor profile
  deploy/proxy-vm/        what is deployed INTO the proxy VM, and the host
                          firewall: serve.py, rulesets, units, phase renderer,
                          isolation probe. Outside src/ and broker/ so the VM's
                          code does not compete for the line budget with the
                          application that commands it.
  docs/adr/               decisions, numbered
  docs/designs/           designs and normative contracts
  migrations/             schema, applied in order at startup
  scripts/                operator tools
  tests/                  the suite
  tools/                  developer diagnostics, outside the line budget
  install.sh              the deployment, step by step
  uninstall.sh            its inverse, dry-run by default

/etc/xentry/              755 root:xentry
  app.env                 0640 root:xentry  - the app's settings and the key
  broker.env              0600 root:root    - the broker's settings
  proxy-vm.key            the proxy VM's ssh key

/var/lib/xentry/          751 xentry:xentry - production state
  xentry.db               the SQLite index
  jobs/<job_id>/          per-job attempts, evidence, hash-chained events.jsonl
  artifacts/              pinned PoCs and packages, with manifest.json
  images/                 base images, with build-results.json
  mirror/                 the broker's artifact mirror

/run/xentry/              0750 root:xentry, tmpfs, created by the broker unit
  broker.sock             0660 root:xentry; SO_PEERCRED decides who may call
```

**Every path in `app.env` and `broker.env` is absolute.** They used to be
relative — `./var/artifacts`, `./targets` — resolved against whatever working
directory the process had, and the app and the broker do not share one. A
deployed host ended up reading artifacts from `/opt/xentry/var/artifacts` while
its manifest named `/var/lib/xentry/artifacts/manifest.json`: two directories,
over a gigabyte in the one nothing consulted, and a backup that could easily be
taken of the wrong one. `.env.example` ships absolute paths and a test refuses
a relative default.

The 22 `*_report.md` and `phase*.md` files at the top level are notes from the
original generation of this project. They are history, not documentation.
