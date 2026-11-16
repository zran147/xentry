# Local privilege escalation on the derived path — a plan

Status: proposal. Nothing here is implemented. Written 2026-11-15 after
measuring what the existing dirtyfrag target actually does and what the
archives actually carry.

## 1. The premise, corrected

Dirty Frag does not use a pre-built vulnerable VM. It boots the same kind of
built image every other job boots and makes itself vulnerable **inside the
disposable VM, per job**:

* `targets/dirtyfrag/setup.sh` downloads two pinned artifacts from the
  per-job artifact mirror — `linux-image-6.17.0-23-generic.deb` and
  `linux-modules-6.17.0-23-generic.deb` — checks both SHA-256s, `dpkg -i`s
  them, then runs `update-initramfs -u -k all` and `update-grub`.
* The runner calls the broker's `reboot` verb (real, in
  `broker/runtime.py`; the `not_implemented` copy in `broker/main.py` is the
  runtime-less skeleton and is not reached when a runtime is attached).
* `targets/dirtyfrag/readiness.sh` then asserts `uname -r` is exactly
  `6.17.0-23-generic`, so a job that silently kept the old kernel fails
  instead of reporting a false negative.

So "install a vulnerable kernel in a throwaway VM and boot it" is already
proven on this host. What is missing is not the mechanism — it is the
resolver driving it, and an observation channel for the generic path.

## 2. What actually blocks local privesc today

Three things, none of them the kernel:

1. **Admission.** The derived path refuses `poc_context: "local"` outright:
   *"a local PoC has no attacker to attest from: its evidence has to come
   from inside the target, which is a per-CVE channel (a serial console, a
   PTY)"*. Every local CVE dies here — measured this week on sudo
   CVE-2021-3156, PwnKit CVE-2021-4034, Dirty Pipe CVE-2022-0847 and Looney
   Tunables CVE-2023-4911.
2. **The nonce is the wrong kind of secret.** `generic.NONCE_MODE` is
   `0o644` at `/var/lib/xentry/nonce`, root-owned but world-readable — right
   for the remote proof ("the attacker read a file only the target has"),
   worthless as a privilege proof, since any user can read it. dirtyfrag's
   is `/root/xentry-nonce`, owner root, mode `0o600`.
3. **No generic step relays root evidence out.** dirtyfrag has one, written
   by hand for its specific exploit binary: it pipes
   `cat $nonce; printf 'xentry-root-evidence:' > /dev/ttyS0; cat $nonce > /dev/ttyS0`
   into `./exp`, which happens to read commands on stdin.

## 3. The channel already exists, and it is generic

Worth stating plainly, because it is the part people assume is missing:

* **Every** VM gets a serial device wired to a host-side file —
  `serial_path` and `serial_log_path` in `broker/libvirt_ops.py`, passed for
  every role in `broker/runtime.py`, plus a TCP serial for the target role.
  Nothing about it is dirtyfrag-specific.
* The broker verb `read_host_evidence` reads that file on the host side, and
  `src/xentry/validator.py` already carries `host_evidence_sha256` and
  `host_evidence_excerpt` fields for it.
* `/dev/ttyS0` is `root:dialout 0660`, and cloud-init creates
  `xentry-guest` with `sudo: false` and no supplementary groups. The
  unprivileged guest therefore **cannot write to the serial console**. That
  is what makes "the nonce appeared in the host's serial log" evidence the
  runner observed rather than a claim the guest made.

One bug to not copy. When the serial log does not contain the nonce,
dirtyfrag's probe **falls back silently** to the attacker transcript and the
job still passes (`src/xentry/runner.py`, the `target_id == "dirtyfrag"`
branch) — unlike gitlab and php2shell, which raise `nonce_not_observed`. The
authority string is already `guest_attested+llm_assessed` either way, so
nothing over-claims, but `what_proves` names a channel that may not have been
used and only an empty `host_evidence_sha` hints at it. The local generic
path must fail instead, and dirtyfrag's fallback should be reconsidered —
that is a change to a reviewed target, so it is your call, not mine.

## 4. Plan A — local privesc with no kernel work

This is the cheap 80%: every package-level local privesc, which is most of
what the corpus holds.

| Piece | Where | Shape |
|---|---|---|
| Root-only nonce for local jobs | `src/xentry/generic.py` | `/root/xentry-nonce`, owner root, mode `0o600`, chosen when `poc_context == "local"` |
| `privesc_shape`, a typed enum | `src/xentry/models.py` + prompt | how the PoC hands over root — the harness must not guess |
| One checked-in script per shape | `targets/common/run-poc-local-*.sh` | each ends with the same relay to `/dev/ttyS0` |
| `probe-generic-serial` | `src/xentry/generic.py`, `broker/registry.py` | decisive, reads `read_host_evidence`, **fails** when the nonce is absent |
| Admission | `src/xentry/generic.py` | `poc_context == "local"` admitted only when a shape is named |

Four shapes cover the known corpus. Each is a small checked-in script taking
positional parameters, under the same four-table contract as every other step
(`targets/steps.yaml` params, the script's `${N-}` reads,
`broker/registry.py` STEPS, the runner's params dict):

* `stdin-shell` — the PoC reads commands on stdin. This is dirtyfrag's `./exp`
  and several sudo PoCs, so the shape is already proven.
* `argv-command` — the PoC takes the command to run as an argument
  (`./exploit "id"`).
* `spawns-shell` — needs a PTY and keystrokes; PwnKit's `pkexec` drops an
  interactive `sh`. The broker already has `run_tty` and `_run_tty` in
  `broker/exec_ops.py`, used by dirtyfrag's PTY probe.
* `setuid-drop` — the PoC leaves a setuid binary or a writable root-owned
  path behind, and a named path is run afterwards.

The control run matters more here than anywhere else. `null-generic` already
runs the same step without the exploit; for privesc it is what separates "the
exploit worked" from "the harness handed the guest root", and the existing
`probe_null` failure path already covers it.

**Authority.** Two independent facts would hold: a file only root can read
was read, and a device only root can write was written, the second observed
by the runner outside the guest. That is stronger than the remote derived
path. It is still not forge-proof against a compromised kernel — which is
precisely what a kernel exploit produces — so I would keep
`guest_attested+llm_assessed` rather than invent a stronger label, and say in
`what_proves` which channel was decisive on this run.

**Cost.** The four scripts are shell, and the budget counts only `.py` under
`src`, `broker` and `scripts`, so they are free. The Python is the enum, the
prompt text, the generic.py branch, the registry ids and the runner params:
roughly 60–80 counted lines against 280 spare.

**What it unblocks**, measured against the live archives today:

| CVE | package, resolved | shape |
|---|---|---|
| CVE-2021-4034 PwnKit | sid `policykit-1 0.120-2` (Debian's fix is 0.120-3, first seen 2022-01-25) | `stdin-shell` |
| CVE-2021-3156 sudo | sid `sudo 1.9.5-1` (fix 1.9.5p2) | `stdin-shell` / `argv` |
| CVE-2023-4911 glibc | noble `libc6 2.38-3ubuntu1` (fix 2.39) | `argv-command` |

## 5. Plan B — a vulnerable kernel

### B1: install the kernel from the archive and reboot (recommended)

Generalises exactly what dirtyfrag proves. Measured through the existing
snapshot proxy today:

* Debian's `linux-image-amd64` meta-package: **796 versions** reachable.
  Ubuntu's `linux-image-generic`: 142. The versioned
  `linux-image-5.16.0-5-amd64` exists at 5.16.14-1.
* The resolver already picks correctly with **no new code**: Dirty Pipe
  (`linux-image-amd64`, "5.8 to 5.16.11", fixed 5.16.11/5.15.25) resolves to
  **sid 5.16.10-1** — the last kernel before the fix.

Needed:

* `targets/common/setup-kernel-generic.sh` — install `linux-image-*` plus
  `linux-modules-*`, `update-initramfs -u -k all`, `update-grub`, pin the
  default entry. Shell, so free against the budget.
* A `reboot-generic` step id in the registry and the manifest; the broker
  verb exists and is implemented.
* Readiness asserting `uname -r` against the resolved version, as dirtyfrag's
  does — otherwise a kernel that failed to boot reports a false negative.
* Prompt: when the affected product is the Linux kernel, `setup_packages` is
  `linux-image-amd64` (Debian) or `linux-image-generic` (Ubuntu).

Downsides, stated plainly:

* **A failed exploit panics the VM**, and today that looks like an
  infrastructure failure rather than a negative result. This needs its own
  outcome code — `target_panicked` — read out of the serial log, which the
  existing channel can actually see. Small, and B1 needs it.
* The VM must boot an old kernel on a modern QEMU machine type, and the
  initramfs must carry virtio-blk and virtio-net or it boots to nothing.
  Untested here; it is the main thing I would prototype first.
* `snapshot.ubuntu.com` starts at 2023-06, so pre-2023 Ubuntu kernels are
  unreachable and only Debian's archive serves the old ones. The chosen
  version must also exist **at the serial**, not merely somewhere in history.
* Two extra boots, roughly 60–90s a job.
* A kernel prefix is coarse — "5.16" matches every 5.16.x — so the
  `fixed_versions` ceiling is doing the real work. It is in place now, and
  the `~bpo` case was a live bug: `5.16.11-1~bpo11+1` is the *fix* rebuilt
  for an older suite, not a pre-release of it.

### B2: nested QEMU inside the target VM

Possible, and weaker than it looks.

* The host supports nesting: `/sys/module/kvm_intel/parameters/nested` is
  `Y` on an Intel Core Ultra 5 125H, 18 cores, 30 GiB RAM, 377 GiB free.
* **The guest cannot use it as configured.** `broker/libvirt_ops.py` emits
  no `<cpu>` element, so the domain gets QEMU's default CPU model, which has
  no `vmx`. An inner QEMU would fall back to TCG — software emulation,
  workable for a tiny kernel and a one-shot exploit, but slow. Enabling KVM
  means `<cpu mode='host-passthrough'/>`, which exposes host CPU features to
  the guest and widens the AppArmor/seccomp surface for an inner qemu — the
  opposite direction from ADR 0001's "the VM is the isolation boundary", so
  it needs its own ADR entry reversing that.
* You still need a kernel image and an initramfs, and the ADR forbids
  building upstream kernels. Without compiling that means unpacking
  `/boot/vmlinuz-*` out of an official `linux-image` .deb — the same artifact
  as B1 — plus `busybox-static` from the archive for a userland, plus a
  ~40 MB `qemu-system-x86` install in the target.
* **The authority problem is the reason not to do this for attestation.**
  The proof the lab produces is "a root-only file on the target was read, and
  a device only root can write was written". Inside a nested VM, root is root
  of a machine the guest built and populated; the inner serial lands in a
  guest-writable file, so the guest can forge it, and there is no host
  witness for the inner VM. It also does not prove the *target* was
  compromised, which is what the CVE claims.
* Where nesting genuinely wins: a panic kills only the inner VM, so the job
  can report "the exploit crashed the kernel" instead of losing its target;
  and kernels the archive cannot install as a .deb become reachable.

## 6. Order I would work in

1. **Plan A.** No kernel, reuses a proven channel, unblocks every
   package-level local privesc.
2. **`target_panicked`** plus reading the serial log for a panic. Small, and
   B1 depends on it.
3. **B1**, prototyping the "does an old kernel boot at all" question before
   writing any of the plumbing.
4. **B2** only if 3 proves insufficient, as an explicitly-labelled triage
   mode whose authority is `self_reported`, with its own ADR entry.
