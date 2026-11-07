# xentry V1 — Phase 0 Implementation Plan

**Status:** Ready to execute
**Date:** 2026-11-06
**Design:** `docs/designs/xentry-v1.md` (revision 5)
**Normative contracts:** `docs/designs/xentry-v1-contracts.md` (revision 5 corrections)

## Goal

Prove the two-VM broker, isolated network, artifact mirror, root transport, host-evidence channel, and ADK extractor before building the app, runner, UI, or target packs. Phase 0 is a go/no-go gate, not a demo.

## Non-goals

No web UI, no job runner, no target setup scripts beyond what the image build needs, no GitLab/PHP/DirtyFrag acceptance runs, no SQLite schema beyond the migration smoke file. Those belong to Phases 1–3.

## Work packages

### Day 1–2: repository skeleton and artifact inputs

* Create `pyproject.toml`, `uv.lock`, `README.md`, `.env.example`, `.gitignore`, `src/xentry/__init__.py`, `broker/__init__.py`, `config/artifacts.yaml`, `config/image-manifests.yaml`, `scripts/fetch-artifacts.sh`, `scripts/build-images.sh`.
* Define the artifact schema from contracts §5 and §10: image, package, kernel, PoC, commit, SHA-256, provenance.
* `scripts/fetch-artifacts.sh` verifies vendor checksums/signatures and refuses a first-fetch pin without an out-of-band value.
* Gate G starts here: every image/package/kernel/PoC pin must have a provenance record.

**Outputs:** tracked artifact catalog, fetch/build script skeleton, project env.

### Day 3–4: images and host prerequisites

* Build `ubuntu-24.04-target`, `ubuntu-24.04-dirtyfrag`, `ubuntu-24.04-attacker` with baked apt dependencies and toolchains (contracts §10).
* Verify host prerequisites: Ubuntu 24.04.4, libvirt 10+, libvirt-clients/`virsh`, QEMU 8.2+, nftables, cloud-image-utils, qemu-img, openssh-client, Python 3.12, uv, systemd, AppArmor.
* Create `xentry` host user, `xentry-guest` guest account, `xentry-vm` QEMU user, `xentry-broker` root unit, socket `root:xentry 0660`.
* Write `deploy/apparmor/xentry-vm` and `scripts/install-apparmor.sh`.

**Outputs:** hash-pinned images, install scripts, AppArmor profile, host preflight.

### Day 5: broker registry and socket

* Implement `broker/registry.py` with the canonical ids from contracts §1 and the revision-5 corrections: targets, profiles including `isolated`, images including `ubuntu-24.04-dirtyfrag`, image-to-artifact mapping, steps including `build-poc-php`, artifacts.
* Implement `broker/main.py`: Unix socket, peer-UID check, verb dispatch, unknown-id rejection, `broker_calls.jsonl`.
* Implement `src/xentry/broker.py` client skeleton and `src/xentry/vm/driver.py` protocol.

**Outputs:** registry-completeness tests, socket contract test.

### Day 6–7: libvirt, network, nftables, mirror

* Implement `broker/libvirt_ops.py`, `broker/profiles.py`, `broker/network_ops.py`.
* Fixed network `10.42.0.0/24`; target `10.42.0.10`, attacker `10.42.0.20`, mirror `10.42.0.1:8081`.
* nftables phases: provisioning mirror only; post-provision default-deny; attacker→target ports; broker→target SSH/probe. `run_egress_test` fails closed.
* Implement `start_artifact_mirror`/`stop_artifact_mirror`; the mirror serves only the pinned PHP source, GitLab `.deb`, kernel `.deb`, and PoC artifacts. No `Packages.gz`/`Release`.
* Implement `http_probe(vm_id, network_id, ...)` with server-side IP binding.

**Outputs:** network/mirror tests, egress test, two-VM boot smoke.

### Day 8: exec, nonce, proxy, host evidence

* Implement `broker/exec_ops.py`: SSH with per-job root and actor keys, `PermitRootLogin prohibit-password`, `exec(step_id, params)`, `copy_in` with relative paths, `cancel_exec`, `place_nonce`, `snapshot(vm_id, kind)`, `restore`, `reboot`.
* Implement `broker/proxy.py`: per-job TCP proxy for GitLab target-side response capture.
* Implement `broker/host_evidence.py`: serial/QMP host channel `org.xentry.evidence.0`.
* Add `xentry-guest` denial tests; root steps only for `setup-*`; `collect-host-evidence` broker-side.

**Outputs:** exec/place_nonce/proxy/host-evidence tests, actor-separation tests.

### Day 9: image and broker integration

* Boot target + attacker through the broker; provision a trivial image; run SSH root setup and actor exec; place a nonce; capture GitLab proxy traffic; read host evidence; destroy in attacker→target→network order.
* Run `tests/test_broker_contract.py`, `tests/test_network_mirror.py`, `tests/test_actor_separation.py`, and the gated `tests/test_vm_libvirt.py`.

**Outputs:** two-VM integration transcript, cleanup report, Gate B evidence.

### Day 10: extractor and reuse spike, gate review

* Run the ADK extractor on 20 facts fixtures and 2 invalid fixtures; gate 19/20 valid and 100% citation (Gate F). If it fails, switch `XENTRY_AGENT_RUNTIME=litellm`.
* Run the prior-tree reuse spike: old `verify/vm.py` behind `VmDriver`/`FakeDriver`, `evidence/store.py` shape, `llm.py` client. Record whether the broker is still justified (Gate B/ADR).
* Record Gates B, E, F, G in `docs/phase0_results.md`; write `docs/adr/0001-v1-reset.md`.
* Decide go/no-go: Gates B, E, F, G must pass. Gate C (Dirty Frag host evidence) and Gate D (target builds) are measured in Phases 3 and 1–3 per the revision-5 corrections.

## Exit artifacts

* `docs/phase0_results.md` with gate results, commands, evidence hashes, and accepted risks.
* `docs/adr/0001-v1-reset.md` with the two-VM, broker, checked-in-script, extractor, and no-container decisions.
* `config/artifacts.yaml` with vendor provenance and hashes.
* `config/image-manifests.yaml` and the three built images.
* `broker/` registry, socket, libvirt, network, mirror, exec, proxy, host evidence, and tests.
* `deploy/xentry-broker.service`, `deploy/apparmor/xentry-vm`, host setup scripts.
* `src/xentry/broker.py`, `src/xentry/vm/driver.py`, `src/xentry/vm/fake_driver.py`, `src/xentry/targets.py`, `src/xentry/profiles.py` skeletons.
* Test results: broker contract, network/mirror, actor separation, two-VM smoke, budget, extractor gate.

## Stop rules

* Gate B fails: fix the broker/network or withdraw the VM-boundary claim; do not start Phase 1.
* Gate E fails: reduce the target set (drop GitLab) or raise host memory; record the decision.
* Gate F fails: use the direct LiteLLM extractor; record the ADR amendment.
* Gate G fails: block Phase 1 until every image/package/kernel/PoC has vendor provenance and SHA-256.
* Any root broker path that requires app-owned code, a shared venv, or a shared SSH key: stop and redesign the broker ownership.
* Any need for Docker or a container runtime: stop; the design forbids it.

## First implementation step

Create the repository skeleton and artifact schemas, then run `scripts/fetch-artifacts.sh --dry-run` to validate the catalog and vendor-provenance fields. No broker code starts until the catalog schema and host preflight are in place.
