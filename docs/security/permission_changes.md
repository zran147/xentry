# Permission changes

Every place xentry changes a file mode or owner, why, and which direction it
moves. Eighteen sites in the application and broker, plus the installer.

Read this before adding another. The question to answer is not "does it work"
but **who can now read what, and how would anyone notice if that were wrong.**

## The two reasons any of this exists

**Most of it tightens.** Secrets and state are created by whatever umask the
process happens to have, which is not a security decision. So keys become
`0600`, the broker socket `0660 root:xentry`, cached downloads `0640`. These
are the access control, not exceptions to it.

**Five sites loosen, all for one reason.** Three identities own parts of this
system and they are deliberately different:

| identity | runs | owns |
|---|---|---|
| `root` | the broker | job directories, VM definitions, nftables |
| `xentry` | the web app | the index, evidence, its own job attempts |
| `xentry-vm` | QEMU | nothing — it is handed what it needs |

`xentry-vm` is in `kvm` and nothing else. It is not in `xentry`, on purpose:
QEMU is the process running untrusted guest code, and it must not be able to
read the evidence those guests are judged by. But it still has to open its own
disk, which lives under directories the broker owns. That is the whole of the
loosening.

## The invariant

**`o+x` is granted on ancestors. `o+r` never is.**

`o+x` on a directory permits traversal of a path you already know. Listing
requires `o+r`, which appears nowhere. So the directories cannot be enumerated
and a job id cannot be discovered from the filesystem. Job ids are
`uuid4().hex` — 128 bits.

A test enforces this: `tests/test_runtime.py::test_a_vm_disk_is_not_world_readable`
asserts `| 0o001` is present, `| 0o004` and `| 0o007` are not, and that no host
path is chmod'd world-writable.

## Every site

### Tightening — the access control itself

| where | mode | what it protects |
|---|---|---|
| `broker/runtime.py:522` | `0600` | the per-job SSH private key |
| `broker/runtime.py:523` | `0644` | its public half, which is published to the guest |
| `broker/main.py:500` | `0660` | the broker socket, `root:xentry`. With `/run/xentry` at `0750 root:xentry` this is the authorisation boundary: `SO_PEERCRED` decides who may call a verb |
| `src/xentry/web/app.py:152` | `0600` | the app's CSRF token at `instance/token` |
| `broker/runtime.py:666` | `0640` | the guest serial log |
| `broker/runtime.py:1543,1546` | `0750`,`0640` | `staged/` and each staged artifact, after its digest is verified |
| `broker/runtime.py:1635,1636` | `0750`,`0640` | `copy_out` results, so the app can read what the harness retrieved |
| `broker/aptproxy.py:263` | `0640` | a cached apt object |
| `broker/ociproxy.py:232` | `0640` | a cached OCI blob |
| `broker/registryproxy.py:317,337` | `0640` | a cached npm or PyPI object |
| `src/xentry/artifact_tools.py:76` | `0644` | the artifact catalog, which is not secret and is read by both services |

### Loosening — so QEMU can reach its own disk

| where | what | why |
|---|---|---|
| `broker/runtime.py:640` | `| 0o001` on `data_dir`, `jobs_root`, `job_dir`, `vm_dir` | QEMU runs as `xentry-vm` and must traverse broker-owned directories to open its overlay. Execute only |
| `broker/runtime.py:673` | `chown` `vm_dir`, overlay, seed, serial to `xentry-vm` | QEMU writes to all four |
| `broker/runtime.py:680` | `0640` on overlay and seed | **see below** |
| `broker/runtime.py:1713,1714` | `chown` + `0770` on `capture/` | QEMU opens the filter-dump pcap itself, over the monitor. Group-writable to its own group, not to the world |
| `broker/runtime.py:1719` | `| 0o001` on `job_dir`, `jobs_root`, `data_dir` | the same traversal, for that pcap path |

## The one that was wrong

The ancestors were always handled correctly. The files were not.

`qemu-img` and `genisoimage` write their output at `0644` under root's umask,
and nothing set a mode on them. Combined with the traversal above, **anyone on
the host who learned a job id could read a target VM's disk image and its
cloud-init seed.** Learning a job id is easy: the web app has no
authentication, so `curl 127.0.0.1:8000/api/jobs` lists them.

QEMU owns both files, so `0640` costs it nothing. Fixed at
`broker/runtime.py:680`, and the test above pins it.

The lesson generalises: granting traversal is safe only if the leaf's own mode
is deliberate. Two of these five sites create files with a tool's default mode,
and a default is not a decision.

## Not a permission change, despite appearances

`broker/runtime.py:1244` and `:2094` contain `0o777`. They are the **upper
bound** on the mode a caller may request when `place_nonce` writes a file
**inside a guest** — a validated range, not a permission this process grants
itself. A world-writable file in a disposable guest is not a host concern.

`exec_ops` issues `chmod 0755` and `chmod 0644` over SSH. Those run in the
guest, on the guest's filesystem.

## The installer

`install.sh` creates the layout; these are the modes everything above assumes.

| path | mode | note |
|---|---|---|
| `/var/lib/xentry` | `0751 xentry:xentry` | **`o+x` deliberately.** QEMU must traverse it. At `0750` libvirt cannot open a disk underneath and the domain stays "shut off" with a zero-byte console log — which is how step 11 failed on a freshly installed host. `broker/runtime.py:640` grants this per job, so any host that had run one job was silently correct and the bug only appeared on a fresh install |
| `/var/lib/xentry/jobs` | `0750 xentry:xentry` | stays closed; traversal is granted per job |
| `/var/lib/xentry/artifacts` | `0750 root:xentry` | the app reads them for preflight |
| `/var/lib/xentry/images` | `0755 root:root` | base images, read by QEMU |
| `/etc/xentry` | `0750 root:xentry` | the group traverses; nobody else reaches the keys |
| `/etc/xentry/app.env` | `0640 root:xentry` | the app reads it, and cannot write it |
| `/etc/xentry/broker.env` | `0600 root:root` | the broker only |
| `/run/xentry` | `0750 root:xentry` | tmpfs, from the unit's `RuntimeDirectory` |
| `/etc/sudoers.d/xentry-*` | `0440 root:root` | required by sudo; each rule is parsed before install and the whole config re-parsed after |

`DEV=1` additionally puts `src/`, `tests/`, `broker/` and `targets/` in the
`xentry-dev` group at `2775`/`664`. It does not touch `/etc/xentry`,
`/var/lib/xentry` or either virtualenv, so a developer still cannot read the
API keys.

`scripts/proxy-vm-up.sh` runs `chmod o+x /var/lib/xentry` itself rather than
depending on the installer having done it, because it runs before any job has.

## If you add one

1. Say which of the three identities needs the access, and why it cannot be
   handed the file instead.
2. If it is a directory, grant `o+x` and never `o+r`.
3. If it is a file created by an external tool, set its mode explicitly. The
   tool's default is not a decision.
4. Add the case to `test_a_vm_disk_is_not_world_readable`, which is where these
   invariants are enforced.
