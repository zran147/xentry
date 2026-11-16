"""Tests for the application-package target.

The lab in these tests is the real one from briskets/CVE-2026-126187-poc, which
is the shape this path was built against.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from xentry import ecosystem
from xentry.models import Facts

LAB = json.dumps(
    {
        "name": "ghsa-xqc2-lab",
        "private": True,
        "scripts": {"build": "next build", "start": "next start -p 3100"},
        "dependencies": {"next": "16.4.0", "react": "19.3.0", "react-dom": "19.3.0"},
    }
)
POC_REPO = "https://github.com/briskets/CVE-2026-126187-poc"


def _facts(**overrides: Any) -> Facts:
    base: dict[str, Any] = {
        "cve_id": "CVE-2026-126187",
        "product": "next",
        "affected_range": ">= 16.4.0, < 16.4.1",
        "version_evidence": [],
        "protocol": "http",
        "ports": [],
        "auth_required": False,
        "build_strategy": "npm closure",
        "poc_context": "remote",
        "citations": [],
    }
    base.update(overrides)
    return Facts(**base)


def test_a_lab_declares_its_whole_environment() -> None:
    env = ecosystem.read_app(LAB)
    assert env.build == "next-build"
    assert env.start == "next-start"
    # The port comes from the lab, not the advisory - which is where the
    # derived path kept failing, because no advisory names a port.
    assert env.port == 3100


@pytest.mark.parametrize("declared", ["^16.4.0", "~16.4", "16", ">=16.4.0", "16.4.0 - 16.5.0"])
def test_a_version_range_is_admitted_because_the_mirror_dates_it(declared: str) -> None:
    """The change the registry mirror buys.

    A range used to be refused because it installed whatever was newest, which
    for a CVE is usually the fix. Against an index holding only what existed
    before the advisory, a range resolves to what the lab's author would have
    got - so the lab can be taken as written.
    """
    body = json.loads(LAB)
    body["dependencies"]["next"] = declared
    assert ("next", declared) in ecosystem.read_app(json.dumps(body)).dependencies


@pytest.mark.parametrize("declared", ["latest", "*", "git+https://x/y.git", "file:../next", ""])
def test_a_dependency_that_leaves_the_mirror_is_still_refused(declared: str) -> None:
    """A git url or a file path reaches past the mirror to somewhere this job
    cannot date, so the one property the target rests on would be gone."""
    body = json.loads(LAB)
    body["dependencies"]["next"] = declared
    with pytest.raises(ecosystem.NoEnvironment, match="not a version or range"):
        ecosystem.read_app(json.dumps(body))


@pytest.mark.parametrize(
    ("script", "command"),
    [("start", "node server.js"), ("start", "bash run.sh"), ("build", "make all")],
)
def test_a_command_outside_the_vocabulary_is_refused(script: str, command: str) -> None:
    """The author writes scripts.start; running it would hand them a shell."""
    body = json.loads(LAB)
    body["scripts"][script] = command
    with pytest.raises(ecosystem.NoEnvironment) as excinfo:
        ecosystem.read_app(json.dumps(body))
    assert "not one this harness runs" in str(excinfo.value)


def test_a_start_command_cannot_smuggle_a_shell() -> None:
    body = json.loads(LAB)
    for attempt in ("next start -p 3100; id", "next start -p 3100 && id", "next start -p $(id -u)"):
        body["scripts"]["start"] = attempt
        with pytest.raises(ecosystem.NoEnvironment):
            ecosystem.read_app(json.dumps(body))


def test_the_default_port_applies_when_the_lab_names_none() -> None:
    body = json.loads(LAB)
    body["scripts"]["start"] = "next start"
    assert ecosystem.read_app(json.dumps(body)).port == 3000


def test_the_advisory_product_is_not_the_subject_package() -> None:
    """CVE-2026-126187 is the case that makes this concrete.

    The advisory's product is react. The lab reproduces through next. And the
    affected package, react-server-dom-webpack, is in neither the lab's pins
    nor the resolved closure, because next vendors its own copy. Inferring the
    subject from the product would have asserted a react version that has
    nothing to do with the finding.
    """
    env = ecosystem.read_app(LAB)
    assert ecosystem.declared_version(env, "react") == "19.3.0"
    assert ecosystem.declared_version(env, "react-server-dom-webpack") == ""
    # The product is react and the lab declares react, so react is the subject
    # a reader would pick. What matters is that it is only ever the advisory's
    # product and only when the lab declares it.
    assert ecosystem.subject_for(_facts(product="React"), env) == "react"
    assert ecosystem.subject_for(_facts(product="react-server-dom-webpack"), env) == ""
    assert ecosystem.subject_for(_facts(product="Linux kernel"), env) == ""

    target = ecosystem.derive(_facts(), POC_REPO, env)
    assert target.subject_package == ""
    assert target.expected_version == ""
    assert any("fixed version" in line for line in target.what_does_not_prove)


def test_a_named_subject_is_recorded_and_validated() -> None:
    env = ecosystem.read_app(LAB)
    target = ecosystem.derive(_facts(), POC_REPO, env, subject="next")
    assert target.subject_package == "next"
    # Not asserted from here: the version is whatever the mirror's date
    # resolved, and readiness measures it in the guest.
    assert target.expected_version == ""
    with pytest.raises(ecosystem.NoEnvironment):
        ecosystem.derive(_facts(), POC_REPO, env, subject="next; id")


def test_the_derived_target_is_shaped_like_the_others() -> None:
    env = ecosystem.read_app(LAB)
    target = ecosystem.derive(_facts(), POC_REPO, env)
    assert target.target_id == "npm"
    assert target.target_ports == (3100,)
    # The generic image, not one of its own: node comes from the job's mirror
    # like any other dependency, which is what stops the image table growing
    # 2.3 GB per ecosystem.
    assert target.base_image_id == "ubuntu-24.04-generic"
    assert target.actor_user == "xentry-guest"
    assert "only the package version" in " ".join(target.what_does_not_prove)


def test_the_npm_steps_are_registered_everywhere_they_have_to_be() -> None:
    import yaml

    from broker.registry import ARTIFACTS, IMAGES, TARGETS, resolve_step
    from broker.runtime import TARGET_IMAGES, TARGET_PROFILES

    env = ecosystem.read_app(LAB)
    target = ecosystem.derive(_facts(), POC_REPO, env)
    manifest = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "targets/steps.yaml").read_text()
    )["steps"]

    assert target.target_id in TARGETS
    assert target.target_id in TARGET_IMAGES
    assert target.target_id in TARGET_PROFILES
    assert target.base_image_id in TARGET_IMAGES[target.target_id]
    assert IMAGES[target.base_image_id] in ARTIFACTS
    for step_id in (target.setup_step_id, target.readiness_step_id, target.build_step_id,
                    target.invocation_step_id, target.null_step_id):
        resolve_step(step_id)
        assert step_id in manifest, step_id


def test_the_setup_step_is_hashed_as_checked_in() -> None:
    """setup_sha256 comes from the manifest, so an edited script fails to load."""
    env = ecosystem.read_app(LAB)
    target = ecosystem.derive(_facts(), POC_REPO, env)
    assert len(target.setup_sha256) == 64


def test_a_missing_script_says_so() -> None:
    body = json.loads(LAB)
    del body["scripts"]["start"]
    with pytest.raises(ecosystem.NoEnvironment) as excinfo:
        ecosystem.read_app(json.dumps(body))
    assert "declares no start script" in str(excinfo.value)


def test_every_start_command_has_a_port_to_fall_back_to() -> None:
    """A new vocabulary entry without a default would KeyError at job time."""
    for name in ecosystem.START_COMMANDS.values():
        assert name in ecosystem.DEFAULT_PORTS, name


# ------------------------------------------- the fixed-version control run ---


def _control(**kwargs: Any) -> Any:
    env = ecosystem.read_app(LAB)
    return ecosystem.derive(
        _facts(),
        POC_REPO,
        env,
        subject=kwargs.pop("subject", "next"),
        fixed_version=kwargs.pop("fixed_version", "16.4.1"),
        **kwargs,
    )


def test_a_control_run_serves_the_fixed_build_beside_the_vulnerable_one() -> None:
    target = _control()
    assert target.control_port == 3101
    # Both are opened to the attacker, and the vulnerable one stays first:
    # every other step takes target_ports[0] as the port under test.
    assert target.target_ports == (3100, 3101)
    assert target.fixed_version == "16.4.1"
    assert target.subject_package == "next"


def test_without_a_control_nothing_changes() -> None:
    target = ecosystem.derive(
        _facts(), POC_REPO, ecosystem.read_app(LAB), subject="next"
    )
    assert target.control_port == 0
    assert target.target_ports == (3100,)
    assert target.what_proves == ecosystem.PROVES
    assert target.what_does_not_prove == ecosystem.DOES_NOT_PROVE


def test_the_control_changes_what_the_job_claims() -> None:
    """The caveat a control answers is replaced, not left standing beside it."""
    plain = ecosystem.derive(
        _facts(), POC_REPO, ecosystem.read_app(LAB), subject="next"
    )
    assert any("until the same stack" in claim for claim in plain.what_does_not_prove)

    target = _control()
    assert not any("until the same stack" in claim for claim in target.what_does_not_prove)
    proof = " ".join(target.what_proves)
    assert "16.4.1" in proof and "next" in proof
    # And it still says what moving one package drags with it.
    assert any("dependency constraints resolve to" in c for c in target.what_does_not_prove)


def test_a_control_with_nothing_named_to_compare_is_refused() -> None:
    with pytest.raises(ecosystem.NoEnvironment, match="subject package"):
        _control(subject="")
    # No fixed version simply means no control run, which is the honest
    # weaker result rather than a refusal.
    assert _control(fixed_version="").control_port == 0


def test_a_fixed_version_equal_to_the_affected_one_is_refused() -> None:
    """Two identical builds would make a failed control look like proof."""
    with pytest.raises(ecosystem.NoEnvironment, match="the same run"):
        _control(fixed_version="16.4.0")


def test_a_fixed_version_has_to_be_a_version() -> None:
    """A range here would make the control build unpredictable, which is the
    one thing it cannot be."""
    with pytest.raises(ecosystem.NoEnvironment, match="refused fixed version"):
        _control(fixed_version="^16.4.1")


@pytest.mark.parametrize(
    ("port", "control"), [(3100, 3101), (80, 81), (65534, 65535), (65535, 65534)]
)
def test_the_control_port_is_always_beside_and_never_on_the_app_port(
    port: int, control: int
) -> None:
    assert ecosystem.control_port_for(port) == control


def test_no_image_exists_for_this_ecosystem_or_any_other() -> None:
    """One 2.3 GB image per ecosystem is what the registry mirror removes.

    node comes from the job's mirror like any other dependency, so an npm
    target boots the same generic image a derived apt target does - and a
    python or php target later will too.
    """
    import yaml

    from broker.registry import IMAGES
    from broker.runtime import TARGET_IMAGES

    manifests = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "config/image-manifests.yaml").read_text()
    )
    names = set((manifests.get("images") or manifests).keys())
    assert TARGET_IMAGES["npm"] == ("ubuntu-24.04-generic",)
    for table in (names, set(IMAGES)):
        assert not [name for name in table if "npm" in name], f"an ecosystem image: {table}"
    # Every image a target can boot is one the manifest knows how to build.
    for images in TARGET_IMAGES.values():
        for image in images:
            assert image in names, f"{image} has no manifest"
            assert image in IMAGES, f"{image} is not in the broker's image table"


# ------------------------------------------- picking the fix for the branch ---

# What the live extractor returned for CVE-2026-126187, which names one fixed
# version per supported React branch.
LIVE_FIXES = ["19.0.9", "19.1.10", "19.2.9", "19.3.1"]


def test_the_fix_for_the_branch_the_lab_is_on_is_the_one_used() -> None:
    """Asked for "the fixed version" the live extractor returned 19.0.9, two
    minors below the lab's 19.3.0. The control build would then have been a
    different stack rather than the same one one version on - and would not
    have satisfied next's own peer range either."""
    env = ecosystem.read_app(LAB)
    assert ecosystem.declared_version(env, "react") == "19.3.0"
    assert ecosystem.fixed_for(env, "react", LIVE_FIXES) == "19.3.1"


def test_a_fix_below_what_the_lab_declares_is_no_control_at_all() -> None:
    env = ecosystem.read_app(LAB)
    assert ecosystem.fixed_for(env, "react", ["19.0.9", "19.2.9"]) == ""
    assert ecosystem.fixed_for(env, "react", []) == ""
    assert ecosystem.fixed_for(env, "react", ["not-a-version"]) == ""


def test_a_range_declaration_still_gives_a_floor() -> None:
    body = json.loads(LAB)
    body["dependencies"]["react"] = "^19.3.0"
    env = ecosystem.read_app(json.dumps(body))
    assert ecosystem.fixed_for(env, "react", LIVE_FIXES) == "19.3.1"


def test_select_uses_the_branch_fix_end_to_end() -> None:
    target, _ = ecosystem.select(
        _facts(product="React", fixed_versions=LIVE_FIXES), POC_REPO, LAB
    )
    assert target.subject_package == "react"
    assert target.fixed_version == "19.3.1"
    assert target.control_port == 3101
