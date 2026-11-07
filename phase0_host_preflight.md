# Phase 0 Host Preflight

**Date:** 2026-11-06
**Host:** Ubuntu 26.04.1 LTS (WSL2), kernel `6.18.54.1-microsoft-standard-WSL2`
**Design target host:** Ubuntu 24.04.4 with libvirt 10+ and QEMU 8.2+
**Scope:** read-only checks; no VMs created, no packages installed.

## Results

| Check | Result | Evidence | Action |
| --- | --- | --- | --- |
| OS | WARN | Ubuntu 26.04.1 LTS, WSL2 | Dev host only; pin the deployment host to the design version or update the design |
| KVM device | PASS | `/dev/kvm` present, mode `crw-rw---- root:kvm` | User in `kvm` group |
| CPU virtualization | PASS | `vmx` present; QEMU `kvm` accelerator listed | None |
| QEMU | PASS | 10.2.1 | Meets 8.2+ |
| libvirt | PASS | 12.0.0; `libvirtd` active; system connection works | None |
| libvirt default network | PASS | `default` active, autostart | Phase 0 creates per-job networks |
| libvirt group | PASS | Current user in `libvirt` | App user `xentry` still to be created |
| `virt-host-validate` | PASS with warnings | KVM, `/dev/kvm`, msr, vhost-net, tun, cgroups pass; devices cgroup, IOMMU, SEV/TDX warn | Warnings are outside the V1 device/SEV scope |
| QEMU user / security driver | UNKNOWN | `/etc/libvirt/qemu.conf` not readable without sudo | Run `sudo grep -E '^(user|group|security_driver)' /etc/libvirt/qemu.conf`; Gate B needs the domain to run as `xentry-vm` |
| AppArmor | FAIL (this host) | `apparmor module is loaded`, `apparmor filesystem is not mounted`, service inactive | Gate B cannot be validated on WSL2; run it on the deployment host or explicitly relax the design |
| nftables | PASS | `nft` 1.1.6 | Broker root applies rules |
| cloud-init seed tooling | PASS | `cloud-localds`, `genisoimage`, `xorriso` present | None |
| disk image tools | PASS | `qemu-img` 10.2.1, `ssh-keygen` | None |
| Python | WARN | 3.14.4 | Pin Python 3.12 in `uv`; 3.14 may break dependencies |
| uv | FAIL | `uv` missing | Install `uv`, then `uv python install 3.12` |
| libvirt-python | PASS | Import works, version 12000000 | Broker env will pin it |
| Memory | WARN | 15 GiB total, 14 GiB available | GitLab peak is 10 GB guest plus app/broker/host; 32 GB recommended for headroom |
| CPU | PASS | 8 vCPU | GitLab 4 + attacker 2 fits |
| Disk | PASS | 862 GB free on `/` | 100 GB ceiling fits |
| systemd user lingering | WARN | `Linger=no` | Enable lingering for the app user, or use a system unit |
| Host users | TODO | `xentry`, `xentry-guest`, `xentry-vm` not created | Create in the host setup script |

## Gate status

* **Gate B (broker/network):** PARTIAL. KVM, libvirt, QEMU, nftables, cloud-init tooling, and disk pass. AppArmor fails on WSL2 and the QEMU user/security driver is unreadable without sudo. Gate B must be completed on the deployment host, or the design must explicitly relax AppArmor.
* **Gate E (host capacity):** PASS with a memory caveat. GitLab 10 GB guest plus app/broker/host fits in 15 GiB only without headroom; 32 GiB is the safer host.
* **Gate F (extractor):** NOT RUN. Phase 0 task.
* **Gate G (artifact provenance):** NOT RUN. Phase 0 task.

## Immediate actions

1. Install `uv` and pin Python 3.12.
2. Read `qemu.conf` with sudo and confirm the QEMU user/group and security driver; configure `xentry-vm` if needed.
3. Decide where Gate B runs. WSL2 can validate KVM, libvirt, network, mirror, proxy, and two-VM boot; it cannot validate AppArmor.
4. Create `xentry`, `xentry-guest`, and `xentry-vm`; enable systemd lingering for the app user.
5. Confirm the host memory target: 15 GiB is tight for GitLab + attacker + app; 32 GiB is recommended.
6. Then create the repository skeleton and artifact schemas. No broker logic until the skeleton and catalog are in place.
