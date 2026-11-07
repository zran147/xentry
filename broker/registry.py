"""Broker-owned registry ids.

The authoritative registry is docs/designs/xentry-v1-contracts.md section 1 and
the revision-5 corrections. This Phase 0 skeleton contains the canonical ids and
a strict resolver; it does not yet load a runtime registry file.
"""

from __future__ import annotations

from dataclasses import dataclass

TARGETS = frozenset({"php2shell", "gitlab", "dirtyfrag"})
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
    "ubuntu-24.04-attacker": "ubuntu-attacker-image",
}
ARTIFACTS = frozenset(
    {
        "ubuntu-target-image",
        "ubuntu-dirtyfrag-image",
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
