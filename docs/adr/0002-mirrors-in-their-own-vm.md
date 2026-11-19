# ADR 0002: the mirrors move into a VM, and the host leaves the job network

Status: accepted
Date: 2026-11-17

## Context

ADR 0001 decision 3 says "the VM is the isolation boundary". That has not been
true of the five mirrors. They run in the broker process, as **root on the
host**, bound to the job network's gateway - the host's own address on the
job's bridge:

| service | port |
|---|---|
| apt snapshot proxy, target | 8082 |
| apt snapshot proxy, container runtime | 80 |
| apt snapshot proxy, attacker | 8084 |
| registry proxy (PyPI, npm, nodejs.org) | 8083 |
| OCI mirror (`library/debian`, `library/ubuntu`) | 8086 |

So "the guest fetches a package" means "the guest opens a TCP connection to a
root process on the host, which parses what the guest sends". The isolation
rests on five nftables rules in the `input` chain being exactly right, and on
five hand-written HTTP servers not having a bug that matters.

## Decision

**The mirrors move into a dedicated VM. The host keeps no network presence on
a job's bridge, and the proxy VM gets no route to anything private except the
job networks it serves.**

Three properties, in the order they matter:

1. The target and attacker VMs have **no bridge to the host**. Their only
   neighbour is the proxy VM.
2. Only the proxy VM reaches the internet.
3. The proxy VM reaches **no service on the host**, enforced twice - once
   inside it, once on the host.

### Why both firewalls, and not just one

They fail in different directions, which is the only good reason to have two:

- **Inside the proxy VM**, an egress rule denying private destinations stops a
  redirect or a crafted upstream reply from steering a mirror at
  `192.168.137.10`. It catches the accident and the SSRF-shaped attack at the
  point of origin. But the proxy VM runs the code most likely to be
  compromised, and root inside it can flush its own ruleset - so this layer
  cannot be the boundary.
- **On the host**, dropping everything that arrives from the proxy VM's
  address is authoritative: nothing inside that VM can change a host rule.
  This is the boundary.

**Amended after the first bring-up.** This said "no exception, not even
DHCP", and that was written before the VM existed. Static addressing through
cloud-init required renaming the NIC - Debian's cloud image ships no netplan,
so version 2 may do nothing and version 1 renames - and the rename left the
VM answering nothing at all, while libvirt's own lease table showed DHCP had
worked before it. The address is now pinned by libvirt's `<host mac=.../>`
entry, the same mechanism every job VM uses, and the host admits **one UDP
port, 67, from that bridge**.

Every TCP service on the host stays unreachable, which is the property that
matters: ssh, the broker socket, and port 8000, where the app answers without
authentication. dhclient is told to supersede the resolver dnsmasq offers, so
there is no DNS path to the host either.

The host rule alone would be enough for the threat model. The in-VM rule is
kept because it turns a silent misconfiguration into a loud one, close to
where the mistake would be made.

### One correction to "deny outgoing private IP traffic"

A blanket RFC1918 deny inside the proxy VM would break the mirrors: the job
networks it serves are `10.42.0.0/16`, which is private. The rule is scoped to
the **wan interface**, not to address family:

```
oifname $wan ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop
oifname $wan accept
```

so private destinations are unreachable *through the internet-facing NIC*,
while the mirrors still answer guests on the job-facing NICs. Said the other
way round: the proxy VM may talk privately only to the networks it exists to
serve.

On the host, the matching rule needs no such care, because it is written from
the host's point of view: everything arriving on the wan bridge from the proxy
VM's address is dropped at `input`, and forwarded only to destinations that
are not `192.168.136.0/23` or `172.16.0.0/12`.

## Consequence that is not free: the phase model moves too

Today the host polices attacker-to-target traffic in its `forward` chain -
nothing during provisioning, only the target's declared ports once locked.
That works because both guests are on a bridge the host has an address on.

Take the host off that bridge and the enforcement goes with it. It cannot be
replaced by host filtering of a shared bridge, because `br_netfilter` is not
loaded on this host, so two VMs on one bridge talk at layer 2 and never
traverse `forward`; loading it would change bridge filtering for every bridge
on the machine, `docker0` included.

So the target and the attacker get **a bridge each**, and the proxy VM routes
between them, carrying the phase rules the host carries today. Every policy
decision for a job then sits in one place, and the host becomes a hypervisor
with no presence inside the job at all.

This is a strengthening of ADR 0001 decision 3, not a reversal: more of the
system is behind the VM boundary than before, not less.

## Budget

G14 binds the budget and requires this entry for a change to it. Delivered in
two stages, each shippable on its own:

**Stage 1, +130: the mirrors leave the host.** A persistent proxy VM on a NAT
network, the five mirrors as units inside it, per-job configuration pushed
over SSH, the host routing the job bridge to the proxy VM and dropping
everything from the proxy VM to itself. The job bridge keeps its host address
in this stage, so the phase model is untouched and the change is testable on
its own. The `input` chain's two mirror rules are deleted here - the guests
lose their last reason to address the host.

**Stage 2, +70: the host leaves the job network.** Target and attacker on
separate bridges with no host address, the proxy VM routing between them, the
phase rules pushed to it per phase. After this the guests have no path to the
host at all.

New cap after stage 1: **14,527**. After stage 2: **14,597**. Nothing else in
this work costs budget - the network XML, the image manifest, the systemd
units, the cloud-init, the nftables rule text, the documents and every test
are free.

## The test that is written first

From **inside the proxy VM**, as a job step and not a one-off: every port of
`192.168.137.10` and `192.168.136.1` unreachable, `172.17.0.1` unreachable,
and a known internet host reachable. Getting the egress rules wrong gives the
proxy VM a quiet route to the operator's LAN; getting the mirror rules wrong
breaks installs loudly. Only the first needs a test to be noticed.
