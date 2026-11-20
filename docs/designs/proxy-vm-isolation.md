# Moving the mirrors off the host, into a VM of their own

## What this changes

Today every mirror runs **in the broker process, on the host**, bound to the
job network's gateway - which is the host's own address on that bridge:

| service | port | upstream |
|---|---|---|
| `AptSnapshotProxy` (target) | 8082 | snapshot.debian.org / snapshot.ubuntu.com |
| `AptSnapshotProxy` (container) | 80 | same, for the in-VM container runtime |
| `AptSnapshotProxy` (attacker) | 8084 | same, for the attacker VM |
| `RegistryProxy` | 8083 | PyPI / npm / nodejs.org |
| `OciMirror` | 8086 | `library/debian`, `library/ubuntu` |

So a guest reaching a mirror is a guest **reaching the host**. That is why
`network_ops.py` needs an `input` chain at all: those packets are delivered
locally and never traverse `forward`. The isolation rests on five nftables
rules being exactly right, and on five HTTP servers - written here, parsing
attacker-adjacent input - not having a bug that matters, in a process running
as **root on the host**.

After this change the guests have no path to the host at all, and the thing
they do reach is a VM that cannot reach the host either.

## Topology

```
                    internet
                       |
                  [ NAT, libvirt ]
                       |
  xentry-wan  10.44.0.0/24          host 10.44.0.1 (unreachable, see rules)
                       |
                 +-----------+
                 | proxy VM  |  10.44.0.2, static
                 | the five  |  no second NIC
                 | mirrors   |
                 +-----------+
                       ^
                       | host ROUTES, policed by the xentry table
                       |
  xentry-<job> 10.42.N.0/24         host 10.42.N.1 (DHCP/DNS only)
                       |
            +----------+----------+
            | target VM           | attacker VM
            +---------------------+
```

A guest's mirror host becomes **10.44.0.2** instead of its own gateway. That
is the only change a guest sees: same ports, same paths, same pinned serial.

## Why the proxy VM is NOT on the job bridge

The obvious design gives the proxy VM a second NIC on each job network, so
guests talk to it directly. On this host that would make it **unfilterable**:

```
$ lsmod | grep -c br_netfilter        0
$ sysctl net.bridge.bridge-nf-call-iptables     (absent)
```

`br_netfilter` is not loaded, so two VMs on one Linux bridge talk at layer 2
and the host's `ip` `forward` hook never sees the packets. Every rule in
`network_ops.py` would be decorative for guest-to-proxy traffic. Loading
`br_netfilter` would fix that by changing bridge filtering semantics for
**every** bridge on the box - including `docker0`, which exists here - which
is a large blast radius for a policy that is meant to be narrow.

Keeping the proxy VM on its own bridge means guest-to-proxy traffic is
**routed by the host between two different bridges**, so it traverses
`forward` and the existing phase model keeps working, with `ip_forward`
already 1.

## The rules, in all four directions

Policy, per job, in the `xentry` table:

1. **job bridge -> wan bridge**: accept only `daddr 10.44.0.2` on the five
   mirror ports, and only in the provisioning phase. The locked phase drops
   it, as it drops everything else today.
2. **job bridge -> host (`input`)**: DHCP and DNS only. The two
   `host_services` rules that exist for the mirrors are **deleted** - the
   point of the exercise.
3. **wan bridge -> host (`input`)**: drop, with no exception. The proxy VM
   gets a static address from cloud-init and a public resolver, so it needs
   neither DHCP nor the host's DNS. This is the user's requirement stated as
   one rule.
4. **wan bridge -> anywhere else**: accept to the internet, drop to
   `192.168.136.0/23` (the operator's LAN, where this host lives) and to
   `172.16.0.0/12`, and to a job bridge allow `established,related` only - so
   the proxy VM can answer a guest but never open a connection to one.

Rule 4 needs care that today's table does not: our `forward` chain has
**policy drop**, and libvirt's NAT network installs its own accept rules in a
different table. A drop in any table kills the packet, so proxy-to-internet
has to be accepted explicitly by us, not left to libvirt.

## Lifecycle

**One persistent proxy VM, reconfigured per job.** Not per-job, because the
apt cache is what makes provisioning survivable - redis took ten minutes of
archive fetching, and a cold cache every job multiplies that across the
sweeps. The cache lives on a second disk attached to the proxy VM.

Per job the broker writes that job's pinned serial, archive and allowlists to
the proxy VM over SSH and restarts the five services, exactly as it
constructs the five objects today. Gate G8 (one job at a time) is what makes
a single shared proxy VM safe: no two jobs ever want a different serial at
once.

This keeps the proxy VM out of G8's teardown requirement, which is about the
job's own VMs and network. The proxy VM holds no evidence and no nonce.

## What this does not change

- **Evidence.** apt verifies the archive's signatures inside the guest, and
  pinned artifacts are checked by sha256. The nonce never transits a mirror.
  Moving the mirrors changes who serves bytes, not who attests to them.
- **The authority model**, the step vocabulary, the phase model's shape.
- **The guest-visible contract**: ports and paths are identical.

It also removes a standing oddity: five HTTP servers parsing hostile-adjacent
input as **root on the host** become five HTTP servers in a disposable VM
that can reach nothing but the internet.

## Cost

Free here: the wan network XML, the proxy VM's image manifest, its systemd
units, its cloud-init, the host nftables rule text, this document, the ADR
entry, and every test.

Budgeted (Python in `src/`, `broker/`, `scripts/`):

| change | lines |
|---|---|
| a second `<interface>` and a second disk in the domain XML | +10 |
| define and start the persistent wan network and proxy VM | +25 |
| push a job's mirror config over SSH, restart the five units | +45 |
| delete the in-process proxy startup and its cleanup table entries | -35 |
| the four new nftables directions in `network_ops.py` | +40 |
| runtime wiring, readiness probe for the proxy VM, reporting | +25 |

Net **about +110**, and I would ask for **+130** so the readiness probe and
its failure messages can be verbose, which is where the first week of this
will be spent.

G14 requires an ADR entry for a budget change, and this needs one anyway:
ADR 0001 decision 3 says "the VM is the isolation boundary", and this makes
that true of the mirrors as well, which is a strengthening rather than a
reversal.

## The risk worth stating plainly

The failure mode of getting rule 4 wrong is a proxy VM with a route to the
operator's LAN. The failure mode of getting rule 1 wrong is a job that cannot
install anything, which is loud. So the first thing built is a test that
asserts, from the proxy VM, that `192.168.137.10` and `192.168.136.1` are
unreachable on every port, and that the internet is reachable - run as a job
step, not as a one-off.

## Known gap: the typed targets cannot provision

The three typed targets — PHP2Shell, GitLab, Dirty Frag — fetch their pinned
software from an **artifact mirror** on port 8081:

```bash
# targets/php2shell/setup.sh
curl -fsS "$proxy_url/artifacts/$artifact_id" -o "$tarball"
```

`deploy/proxy-vm/serve.py` binds five ports: three apt proxies, a registry and
an OCI mirror. **Nothing binds 8081.** That service, `broker/mirror.py`'s
`ArtifactMirror`, is the one thing ADR 0002 did not move into the VM. Its
host-side instance was gated behind `start_mirror and not self.proxy_ip`, and
`proxy_ip` defaults to the constant `10.44.0.2`, so it could not run either.

So all three fail at provision with

```
curl: (7) Failed to connect to 10.44.0.2 port 8081
```

and have since the cutover. It stayed hidden because nothing else uses that
port: generic targets fetch from the apt proxy on 8082, which is why
CVE-2021-41773 and CVE-2025-32463 reproduce end to end today.

**This is documented rather than fixed, deliberately.** Generic is the path
forward; the typed targets are pinned to three specific CVEs and the generic
pipeline covers the same ground. The dead host-side module was deleted on
2026-11-20 and a test asserts it stays deleted, because reintroducing it would
put a root process back on a guest-reachable address — the shape ADR 0002
exists to remove.

If a typed target is needed again, the work is:

1. A sixth service in `serve.py` on 8081, serving `/artifacts/<id>` with the
   same allowlist-by-digest behaviour the old module had. It is recoverable
   from `git show 25a8997~1:broker/mirror.py`.
2. A per-job copy of only the APPROVED artifacts into the VM, because they
   live on the host at `/var/lib/xentry/artifacts` and the guest cannot reach
   the host by design. Per-job and approved-only, not the whole 1.3G set — the
   allowlist is what stops a guest pulling an artifact from another job.
3. `job.json` gaining the artifact list, as it already carries the ports.
