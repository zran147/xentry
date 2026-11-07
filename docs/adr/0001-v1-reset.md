# ADR 0001 — xentry V1 reset

* **Status:** Accepted
* **Date:** 2026-11-06
* **Owner:** zran147
* **Supersedes:** the prior v2 design and old ADR 0007 for the V1 scope

## Context

The prior xentry tree grew to roughly 12,000 lines and about 20 subsystems and could not be audited by its owner. Its verification path was self-reported. The V1 design reduces the product to three known Linux targets, a local web app, and a runner-owned evidence path.

## Decisions

1. **All three targets remain in V1:** PHP2Shell (CVE-2026-109618), GitLab (CVE-2026-85706), and Dirty Frag (CVE-2026-43500).
2. **Remote PoCs use a target VM plus a lightweight attacker VM.** GitLab and PHP2Shell run their pinned PoCs from the attacker VM. Dirty Frag stays in the target VM with host-side evidence because it is a local kernel exploit.
3. **The VM is the isolation boundary; xentry uses no container runtime.** Docker/Podman are not used for xentry or target/attacker provisioning.
4. **System libvirt through a root-owned, fixed-verb broker.** The app never joins `libvirt`. The broker validates a broker-owned registry, runs SSH with per-job root and actor keys, and exposes only the contract verbs.
5. **The first three setup scripts are checked in and hash-verified.** There is no LLM setup authoring or repair in V1. The generated path moves to V1.1 with a fourth real target.
6. **ADK is the extractor only.** It is load-bearing for target admission and the pre-run plan. The validator is a direct LiteLLM call, no tools, no generator history. ADR 0007's "explicit Python, no model tools" decision is reversed for extraction only; the model still has no execute/validate/destroy tools.
7. **The runner-owned nonce is the causal anchor.** The LLM cannot return `reproduced` without `nonce_observed`. Dirty Frag's authority is `guest_attested+llm_assessed` until the host channel is proven non-forgeable.
8. **Budget:** 8,000 handwritten Python lines, 44 modules, 14 weeks. The two-VM and broker work is explicitly budgeted.
9. **AppArmor is required at Gate B.** The WSL2 development host cannot validate it; Gate B's AppArmor and QEMU-user checks run on the deployment host. The final design is not relaxed for WSL2.

## Gate G amendment (2026-11-06)

The kernel pin is split into two vendor-pinned artifacts: `kernel-6.17.0-23` (signed image) and `kernel-modules-6.17.0-23` (modules). The image package depends on the modules package, so the Dirty Frag setup installs both and the mirror serves both. The vendor cloud image is `ubuntu-base-image`; the three built images (`ubuntu-target-image`, `ubuntu-dirtyfrag-image`, `ubuntu-attacker-image`) build from it. This is a correctness correction to the Gate G artifact set, not a scope change.

## Phase 0 implementation note (2026-11-06)

The root broker drives system libvirt through the fixed `virsh` CLI instead of `libvirt-python`. This removes the host `libvirt-dev` build dependency while keeping the same root-owned, fixed-verb, system-libvirt boundary. The WSL2 smoke used a static DAC seclabel for the developer UID (`1000:1000`); the deployment host must use the dedicated `xentry-vm` user. AppArmor, nftables application, and the final QEMU-user check remain deployment-host Gate B items.

## Consequences

* V1 is a two-VM program for remote targets, not a single-VM demo.
* The broker is a root-owned trust surface; its fixed verbs, peer UID, registry, and QEMU user are security-critical.
* The design remains LLM-assessed, not deterministically verified. The full harness contract is deferred.
* Gate B is split: WSL2 can validate KVM, libvirt, network, mirror, proxy, and two-VM boot; AppArmor/QEMU-user validation moves to the deployment host.
* Any further scope growth requires a budget change and an amendment to this ADR.

## References

* `docs/designs/xentry-v1.md`
* `docs/designs/xentry-v1-contracts.md`
* `phase0_plan.md`
* `phase0_host_preflight.md`
