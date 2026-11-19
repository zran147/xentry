# The mirror VM

Everything here is deployed **into** the VM or onto the host's firewall, not
run as part of the application. It sits outside `src/`, `broker/` and
`scripts/`, so none of it counts against the host's line budget — the VM's own
code should not compete for budget with the application that commands it.

| file | where it lands | what it is |
|---|---|---|
| `serve.py` | VM: `/opt/xentry-mirror/serve.py` | starts the five mirrors from `/etc/xentry-mirror/job.json` |
| `firewall.nft` | VM: `/etc/nftables.conf` | the VM's own filter, the second of two layers |
| `xentry-mirror.service` | VM: `/etc/systemd/system/` | one unit, started per job by the broker |
| `isolation-probe.sh` | VM: `/opt/xentry-mirror/` | proves the isolation; the only thing that decides whether a change worked |
| `host-wan.nft` | **host**: `/etc/xentry/host-wan.nft` | the host's permanent rules for this VM's bridge |
| `xentry-wan-firewall.service` | **host**: `/etc/systemd/system/` | loads those rules at boot, and the routes to the job subnets |

`serve.py` imports `broker/aptproxy.py`, `broker/ociproxy.py` and
`broker/registryproxy.py`, copied in beside it. Those three import **only the
standard library**, so the VM needs `python3` and nothing else: no venv, no
wheels, no network at build time. A test asserts that with an AST walk, so an
`import requests` added to a proxy later fails the install rather than
silently requiring a venv inside the VM.

## Arming a rollback without killing yourself

Loading a filter over ssh needs a dead-man, and the obvious one is wrong:

```sh
nohup setsid sh -c 'sleep 90; nft delete table inet xentry_mirror' &
nft -f firewall.nft
pkill -f 'sleep 90'              # WRONG
```

`pkill -f` matches full command lines, and the remote shell running that very
command has `sleep 90` in its own argv - so it kills itself, ssh returns
non-zero, and a `set -e` caller exits believing the load failed. The sleeping
child survives into its timeout and deletes a filter that was fine. That
happened: the whitelist load reported success, the script died at the
cancellation, and ninety seconds later the VM lost its filter entirely.

Use a sentinel the rollback reads, and no pattern matching at all:

```sh
rm -f /run/xentry-keep-filter
nohup setsid sh -c 'sleep 90; [ -f /run/xentry-keep-filter ] \
  || nft delete table inet xentry_mirror' &
nft -f firewall.nft
touch /run/xentry-keep-filter    # cancels it
```

## Who may talk to this VM

| from | may reach |
|---|---|
| the host, `10.44.0.1` | everything, including **port 22** |
| a guest, `10.43.1.0/24` or `10.43.2.0/24` | DHCP and DNS, the mirror range `8081-8086`, and a ping |
| anything else | nothing: the input chain's policy is drop, and the wan network is libvirt NAT, which forwards nothing inbound |

Port 22 is the whitelisted one on purpose. It is the broker's **jumphost** -
every guest command is tunnelled through it - so a guest able to reach it
could ask it to forward anywhere this VM can reach, which is the whole
internet, and could work on the key's authentication at its leisure. The rule
was `tcp dport 22 accept` with no source at all, beneath a blanket
`ip saddr 10.43.0.0/16 accept` that reached every other port too.

The host rule matches on **source, not conntrack state**, which preserves the
dead-man property the unconditional rule had: loading this ruleset is what
loads `nf_conntrack`, so the session doing the loading is not yet tracked and
a state-only allowance would drop it mid-load.

Whether the mirror ports answer *at this moment* is still the phase table's
decision at priority -10, which drops all tcp from the job subnets while the
PoC runs. The base rule only declines to stand in its way, because an accept
in one table does not survive a drop in another.

## The host needs routes, and that is not a weakening

`xentry-wan-firewall.service` also installs:

```
10.43.1.0/24 via 10.44.0.2
10.43.2.0/24 via 10.44.0.2
```

The broker provisions every guest over ssh. Stage 2 took this host's address
off the guests' bridges, which stopped the guests reaching the host - the
point - and also stopped the host reaching the guests, which was an oversight:
`ip route get 10.43.1.10` resolved via the LAN gateway, so the broker's
connection left for the internet and `create_target` waited for an ssh that
could never arrive.

Host-to-guest is the opposite direction from the one being defended. A guest's
own packets to this host are still dropped three times over: the VM's phase
rules drop a new flow from a job subnet, the VM's egress filter drops anything
addressed to 10.44.0.1, and `xentry_wan`'s input chain drops whatever arrives
from that bridge anyway.

## Setting it up

```bash
sudo /opt/xentry/scripts/proxy-vm-up.sh              # build or re-provision
sudo REBUILD=1 /opt/xentry/scripts/proxy-vm-up.sh    # discard the disk first
sudo /opt/xentry/scripts/proxy-vm-doctor.sh          # read-only diagnosis
```

The bring-up is idempotent and re-runnable. It redefines the domain every time
(an older definition keeps an older seed and no console log), reuses the disk
and its package cache unless `REBUILD=1`, and **refuses to finish unless the
isolation probe passes inside the VM**.

It ends by printing the two variables that actually move the mirrors off the
host. Nothing is cut over until they are set:

```
XENTRY_WAN_BRIDGE=xentrywan0
XENTRY_PROXY_IP=10.44.0.2
```

Put them in the broker's environment file and restart `xentry-broker`. With
them unset, every rule is byte-identical to the pre-VM behaviour and the
mirrors stay in the broker process — a test asserts both shapes, because a lab
with six reproduced CVEs is not worth a flag day.

**No job has run through this path yet.** The broker writes `job.json`,
restarts the unit, pushes `provisioning` at `create_network` and `locked` at
`lock_network`, and puts the guests on the two island bridges — all of it
tested in isolation, none of it against a real job. Expect the first one to
find something.

What the locked phase guarantees, and the reason it is written as it is: the
broker pushes it with **no mirror ports at all**, which `phase.sh` renders as

```
ip saddr { 10.42.1.0/24, 10.42.2.0/24 } meta l4proto tcp drop
```

so while the PoC runs, neither the target nor the attacker can open a TCP
connection to the mirror VM — not to the five mirror ports, not to anything.
The only path that phase opens is the attacker to the target's declared ports.
The mirrors are also stopped, which is what makes the guarantee hold if a rule
is ever wrong.

## What each thing refuses to do

**`serve.py` refuses to start without a pinned snapshot serial.** A mirror
with no date serves today's archive, and a CVE "reproduced" against today's
packages is a CVE reproduced against a build that already carries the fix —
a false negative indistinguishable from a working job. The refusal goes to the
journal, and `configure_mirror_vm` carries that journal into the job's failure
rather than leaving it on a box nobody will ssh into.

**It binds `0.0.0.0`.** Three things decide who can reach these ports, and the
bind address is the weakest: the host's single rule allowing a job bridge to
cross to this VM on the mirror ports during provisioning only; this VM's own
filter; and then the bind. Binding one address would add nothing and would
break when a job network is renumbered.

**`host-wan.nft` clears only its own table.** `flush ruleset` on the host
would delete libvirt's NAT rules for every network and the per-job `xentry`
table with them, mid-job. It uses `table` then `delete table` so a reload
replaces its rules instead of appending a second copy — which is what happened
when the script and the unit both loaded it.

**`xentry-wan-firewall.service` has no `ExecStop`.** Stopping it would restore
the hole it exists to close.

## Things worth knowing before changing any of this

**The in-VM filter must accept ssh without consulting conntrack.** Loading
nftables is what loads `nf_conntrack`, so the ssh session doing the loading is
not yet tracked: a state-only allowance drops it, and a drop is not a refusal,
so the load *hangs*. `tcp sport 22 accept` comes first in the output chain for
that reason. The bring-up also arms `sleep 90; nft flush ruleset` inside the
VM before loading and cancels it only after proving it can still get in, so a
future mistake in that file unlocks itself.

**Replies are addressed into private ranges.** This VM has one NIC and serves
guests on `10.42.0.0/16`, so every answer a mirror sends has a private
destination. `established,related` must precede the private drops in both the
VM's filter and the host's rules, or no mirror can answer the guest it exists
to serve — and it presents as "apt hangs", not as a firewall problem.

**The address comes from DHCP, not from a static config.** Static required
cloud-init to rename the NIC, and the rename left the VM answering nothing at
all while libvirt's lease table showed DHCP had worked perfectly. The address
is pinned by the `<host mac=.../>` entry in the `xentry-wan` network — the
same mechanism every job VM uses. The cost is one UDP port (67) through the
host's rules; `dhclient` is told to supersede the resolver dnsmasq offers, so
there is no DNS path to the host.

**The disk's backing format must be read, not inferred.** The base image is
qcow2 behind a `.img` name, and `qemu-img info --output=json` has two
`"format"` fields — the protocol layer's and the image's. Taking the first
produced an overlay declaring its qcow2 base as raw; the VM booted nothing and
the only symptom was ssh timing out. The bring-up reads it with a JSON parser
and then verifies the overlay it created.

**The VM's files must be owned by the user qemu runs as.** `runtime.py` chowns
every per-job VM file to `XENTRY_QEMU_USER`; the bring-up does the same, and
resolves that user from the broker's env, else the owner of an image libvirt
already opens, else `/etc/libvirt/qemu.conf`. A `750 root:root` directory is
why the domain first refused to start at all.
