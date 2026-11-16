"""Broker-owned registry ids.

The authoritative registry is docs/designs/xentry-v1-contracts.md section 1 and
the revision-5 corrections. This Phase 0 skeleton contains the canonical ids and
a strict resolver; it does not yet load a runtime registry file.
"""

from __future__ import annotations

from dataclasses import dataclass

# "generic" is the derived target: one id for every CVE admitted from
# extracted facts. The broker still owns its image and resources, and
# broker/runtime.py must carry an entry for every id in here.
TARGETS = frozenset({"php2shell", "gitlab", "dirtyfrag", "generic", "npm"})
PROFILES = frozenset(
    {
        "isolated",
        "target-php2shell",
        "target-gitlab",
        "target-dirtyfrag",
        "attacker-remote",
    }
)
IMAGES = {
    "ubuntu-24.04-target": "ubuntu-target-image",
    "ubuntu-24.04-dirtyfrag": "ubuntu-dirtyfrag-image",
    "ubuntu-24.04-generic": "ubuntu-generic-image",
    "ubuntu-20.04-generic": "ubuntu-focal-generic-image",
    "debian-11-generic": "debian-11-generic-image",
    "ubuntu-22.04-generic": "ubuntu-jammy-generic-image",
    "ubuntu-18.04-generic": "ubuntu-bionic-generic-image",
    "ubuntu-24.04-attacker": "ubuntu-attacker-image",
}
ARTIFACTS = frozenset(
    {
        "ubuntu-target-image",
        "ubuntu-dirtyfrag-image",
        "ubuntu-generic-image",
        "ubuntu-focal-generic-image",
        "debian-11-generic-image",
        "ubuntu-jammy-generic-image",
        "ubuntu-bionic-generic-image",
        "ubuntu-jammy-base-image",
        "ubuntu-bionic-base-image",
        "ubuntu-focal-base-image",
        "debian-11-base-image",
        "ubuntu-attacker-image",
        "php-8.4.26-src",
        "gitlab-19.2.5-deb",
        "kernel-6.17.0-23",
        "kernel-modules-6.17.0-23",
        "poc-php2shell",
        "poc-gitlab",
        "poc-dirtyfrag",
    }
)
STEPS = frozenset(
    {
        # Derived targets. Registered here as well as in targets/steps.yaml:
        # resolve_step() is the broker's own allowlist, and a step the manifest
        # describes but this set omits is refused as "unknown step id" at the
        # first provisioning call - which is how every derived job died.
        "setup-generic",
        "setup-attacker",
        "setup-docker",
        "readiness-generic",
        # The local privesc path. One run step per shape, because the relay
        # that carries the proof out has to be handed to the exploit the way
        # that exploit accepts it, and the app never supplies a command.
        "readiness-local",
        "null-local",
        "run-poc-local-stdin",
        "run-poc-local-argv",
        "run-poc-local-patch",
        "run-poc-local-pty",
        "run-poc-local-setuid",
        "run-poc-local-stage",
        "reboot-generic",
        "setup-npm",
        "readiness-npm",
        "build-poc-generic",
        "run-poc-generic",
        "null-generic",
        "setup-php",
        "setup-gitlab",
        "setup-dirtyfrag",
        "readiness-php",
        "readiness-gitlab",
        "readiness-dirtyfrag",
        "build-poc-php",
        "build-poc-gitlab",
        "build-poc-dirtyfrag",
        "run-poc-php",
        "run-poc-gitlab",
        "run-poc-dirtyfrag",
        "probe-php-http",
        "probe-gitlab-response",
        "probe-dirtyfrag-pty",
        "null-php",
        "null-gitlab",
        "null-dirtyfrag",
        "prefix-gitlab-nonce",
        "reboot-dirtyfrag",
    }
)
BROKER_SIDE = frozenset({"collect-host-evidence", "proxy_capture", "http_probe"})
ROOT_STEPS = frozenset({"prefix-gitlab-nonce"})


class RegistryError(ValueError):
    """An id or step is not in the broker-owned registry."""


@dataclass(frozen=True)
class Step:
    step_id: str
    allowed_users: tuple[str, ...]
    broker_side: bool = False


def resolve_target(target_id: str) -> str:
    if target_id not in TARGETS:
        raise RegistryError(f"unknown target id: {target_id}")
    return target_id


def resolve_profile(profile_id: str) -> str:
    if profile_id not in PROFILES:
        raise RegistryError(f"unknown profile id: {profile_id}")
    return profile_id


def resolve_image(image_id: str) -> str:
    try:
        return IMAGES[image_id]
    except KeyError as exc:
        raise RegistryError(f"unknown image id: {image_id}") from exc


def resolve_artifact(artifact_id: str) -> str:
    if artifact_id not in ARTIFACTS:
        raise RegistryError(f"unknown artifact id: {artifact_id}")
    return artifact_id


def resolve_step(step_id: str) -> Step:
    if step_id in STEPS:
        user = (
            "root"
            if step_id.startswith("setup-") or step_id in ROOT_STEPS
            else "xentry-guest"
        )
        return Step(step_id=step_id, allowed_users=(user,))
    if step_id in BROKER_SIDE:
        return Step(step_id=step_id, allowed_users=("broker",), broker_side=True)
    raise RegistryError(f"unknown step id: {step_id}")
