#!/usr/bin/env python3
"""Resolve an npm dependency closure on the host and pin it as one artifact.

The target VM has no route to a registry, and giving it one would mean a
provisioning channel open while a stranger's exploit runs. So the closure is
resolved here, where the resolution is a metadata-only operation - no tarball is
fetched and no lifecycle script runs - and every tarball the lockfile names is
downloaded and checked against the sha512 integrity the registry published.

What ships is a single tar.gz: the lockfile exactly as npm wrote it, plus the
tarballs. In the guest, ``npm cache add`` each tarball and ``npm ci --offline``
installs from the cache with the registry unreachable, verifying every digest
from the untouched lockfile. One artifact, pinned and reviewed once, served by
the mirror that already exists.

Two measurements decided the shape. A registry proxy would stream 31 MB of
metadata per package (``next`` has 4,034 published versions). And filtering the
lockfile by its own ``os``/``cpu`` fields cuts the pin set from 407 MB to 131
MB, because two thirds of it is macOS and Windows binaries.

A lab pins a whole dependency set, so the closure is resolved for all of them
at once - resolving them one at a time would produce sets that disagree about a
shared transitive dependency. --subject names the one the advisory is about; it
only decides the artifact id.

--fixed-version resolves a second closure with the subject moved to the version
the advisory says fixes it, and everything else left as the lab pinned it. That
is the control run's whole point: both are installed on the same VM from the
same app source, and the only difference the two runs have is one package's
version. Without it a job can show the exploit works in this environment but
not that the vulnerability is why.

Usage:
  scripts/pin-npm-closure.py --subject next \
      --dep next@16.4.0 --dep react@19.3.0 --dep react-dom@19.3.0 \
      --fixed-version 16.4.1
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import httpx

from xentry.ecosystem import closure_id

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = "/var/lib/xentry/artifacts"
USER_AGENT = "xentry-npm-closure/0.1"
PLATFORM_OS = "linux"
PLATFORM_CPU = "x64"
# A closure is pinned per (package, version); the name is the artifact id.


class ClosureError(RuntimeError):
    """The closure could not be resolved or did not verify."""


def resolve(deps: list[str], work: Path) -> dict[str, Any]:
    """The lockfile npm writes for one dependency set.

    --package-lock-only keeps this to metadata: no tarball is fetched and no
    node_modules is created. --ignore-scripts is belt and braces, since nothing
    is installed for a script to run from.
    """
    (work / "package.json").write_text(
        json.dumps({"name": "xentry-closure", "version": "1.0.0", "private": True}) + "\n",
        encoding="utf-8",
    )
    # Fixed argv, no shell.
    result = subprocess.run(
        [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            *deps,
        ],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        raise ClosureError(f"npm could not resolve {' '.join(deps)}: {result.stderr[-2000:]}")
    if (work / "node_modules").exists():
        raise ClosureError("resolution created node_modules; it should not have")
    lock = json.loads((work / "package-lock.json").read_text(encoding="utf-8"))
    if not isinstance(lock.get("packages"), dict):
        raise ClosureError("lockfile has no packages map")
    return lock


def relevant(entry: dict[str, Any]) -> bool:
    """Whether this platform can use the package at all.

    An unfiltered closure is mostly binaries for other platforms. npm skips
    them at install time by the same two fields, so pinning them would mean
    downloading 407 MB to install 131 MB of it.
    """
    oses = entry.get("os")
    cpus = entry.get("cpu")
    if isinstance(oses, list) and oses and PLATFORM_OS not in oses:
        return False
    return not (isinstance(cpus, list) and cpus and PLATFORM_CPU not in cpus)


def wanted(lock: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(name, url, integrity) for every package this platform will install."""
    out: list[tuple[str, str, str]] = []
    for name, entry in lock["packages"].items():
        if not name or not isinstance(entry, dict):
            continue
        url = str(entry.get("resolved") or "")
        integrity = str(entry.get("integrity") or "")
        if not url.startswith("https://"):
            # A link or a workspace entry carries no tarball.
            continue
        if not integrity:
            raise ClosureError(f"{name} has a tarball but no integrity digest")
        if relevant(entry):
            out.append((name.removeprefix("node_modules/"), url, integrity))
    return out


def check_integrity(data: bytes, integrity: str) -> None:
    algorithm, _, expected = integrity.partition("-")
    digests = {"sha512": hashlib.sha512, "sha256": hashlib.sha256, "sha1": hashlib.sha1}
    if algorithm not in digests:
        raise ClosureError(f"unsupported integrity algorithm: {algorithm}")
    got = base64.b64encode(digests[algorithm](data).digest()).decode()
    if got != expected:
        raise ClosureError(f"integrity mismatch: published {expected}, got {got}")


def download(url: str, integrity: str, into: Path) -> int:
    response = httpx.get(
        url, follow_redirects=True, timeout=120.0, headers={"User-Agent": USER_AGENT}
    )
    response.raise_for_status()
    check_integrity(response.content, integrity)
    into.write_bytes(response.content)
    return len(response.content)


def tarball_name(package: str, url: str) -> str:
    """A filename that cannot collide with another package's.

    The URL's basename drops the scope - @next/env and @other/env both arrive
    as env-16.4.0.tgz - so one would overwrite the other. The completeness
    audit would still pass, because a file by that name exists, and the only
    symptom would be npm failing an integrity check in the guest with no hint
    why. The package name goes in the filename instead; npm cache add reads the
    tarball, so what it is called does not matter to it.
    """
    suffix = ".tgz" if url.endswith(".tgz") else Path(url).suffix or ".tgz"
    return package.lstrip("@").replace("/", "-") + "-" + url.rsplit("-", 1)[-1].removesuffix(
        suffix
    ) + suffix


def audit(lock: dict[str, Any], pinned: set[str]) -> list[str]:
    """Packages this platform needs that are not in the pin set.

    A package the host failed to pin does not fail loudly: npm falls back to
    the configured registry, which in a locked VM is a hard failure found
    mid-job. This is the check that moves it to pin time.
    """
    missing = []
    for name, url, _integrity in wanted(lock):
        if tarball_name(name, url) not in pinned:
            missing.append(name)
    return missing


def build_bundle(work: Path, out: Path, name: str) -> tuple[Path, str, int]:
    bundle = out / f"{name}.tar.gz"
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(bundle, "w:gz") as tar:
        for member in ("package.json", "package-lock.json"):
            tar.add(work / member, arcname=member)
        tar.add(work / "tarballs", arcname="tarballs")
    data = bundle.read_bytes()
    return bundle, hashlib.sha256(data).hexdigest(), len(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dep", action="append", required=True, metavar="NAME@VERSION",
        help="repeatable; every dependency the lab pins, at an exact version",
    )
    parser.add_argument("--subject", required=True, help="the package the advisory is about")
    parser.add_argument(
        "--fixed-version", default="",
        help="also pin a control closure with --subject moved to this version",
    )
    parser.add_argument("--out", default=str(ROOT / "var" / "closures"))
    args = parser.parse_args()
    for dep in args.dep:
        name, _, version = dep.rpartition("@")
        if not name or not version:
            raise ClosureError(f"--dep must be NAME@VERSION, not {dep!r}")
    subject_versions = {
        dep.rpartition("@")[0]: dep.rpartition("@")[2] for dep in args.dep
    }
    if args.fixed_version:
        if args.subject not in subject_versions:
            raise ClosureError(
                f"--fixed-version needs {args.subject} among the --dep list, and it is not; "
                "the control closure has to move a package the lab actually pins"
            )
        if subject_versions[args.subject] == args.fixed_version:
            raise ClosureError(
                f"{args.subject} is already pinned at {args.fixed_version}: "
                "the two closures would be identical and the control would compare nothing"
            )

    results = [pin_one(args.dep, args.subject, Path(args.out))]
    if args.fixed_version:
        moved = [
            f"{args.subject}@{args.fixed_version}"
            if dep.rpartition("@")[0] == args.subject
            else dep
            for dep in args.dep
        ]
        print()
        results.append(pin_one(moved, args.subject, Path(args.out), control=True))

    print("\ninstall and pin them with:")
    for name, bundle, digest, _ in results:
        # A closure has no vendor URL: it is built here, from tarballs whose
        # own digests were verified above. build:// is how the catalog already
        # records a locally produced artifact, and it tells pin-artifact.py not
        # to try downloading one.
        print(
            f"  sudo install -D -o root -g xentry -m 640 {bundle} \\\n"
            f"    {ARTIFACT_DIR}/{name}/{name}.tar.gz\n"
            f"  sudo scripts/pin-artifact.py --artifact {name} --kind npm_closure \\\n"
            f"    --url build://npm-closure+{args.subject} --sha256 {digest} \\\n"
            "    --source 'npm registry, resolved and digest-verified' --accept"
        )
    print(
        "\nthen register them with the broker, which reads a manifest rather than\n"
        "the catalog:\n"
        f"  sudo scripts/fetch-artifacts.py --mode download --out {ARTIFACT_DIR}"
    )
    return 0


def pin_one(
    deps: list[str], subject: str, out: Path, *, control: bool = False
) -> tuple[str, Path, str, int]:
    """Resolve, verify and bundle one dependency set."""
    label = "control closure" if control else "closure"
    with tempfile.TemporaryDirectory(prefix="xentry-closure-") as tmp:
        work = Path(tmp)
        print(f"resolving {label}: {' '.join(deps)} (metadata only)", flush=True)
        lock = resolve(deps, work)
        every = [name for name in lock["packages"] if name]
        needed = wanted(lock)
        print(f"  {len(every)} packages resolved, {len(needed)} for {PLATFORM_OS}-{PLATFORM_CPU}")

        tarballs = work / "tarballs"
        tarballs.mkdir()
        total = 0
        for name, url, integrity in needed:
            total += download(url, integrity, tarballs / tarball_name(name, url))
        print(f"  {len(needed)} tarballs verified, {total / 1048576:.1f} MB")

        missing = audit(lock, {path.name for path in tarballs.iterdir()})
        if missing:
            raise ClosureError(f"not pinned: {', '.join(missing[:10])}")
        print("  pin set is complete")

        pairs = tuple(
            (dep.rpartition('@')[0], dep.rpartition('@')[2]) for dep in deps
        )
        # The id fingerprints the whole set, so the two closures get different
        # ids without anything having to say which is the control.
        name = closure_id(subject, pairs)
        bundle, digest, size = build_bundle(work, out, name)

    print(f"  bundle  {bundle}")
    print(f"  sha256  {digest}")
    print(f"  bytes   {size}")
    return name, bundle, digest, size


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ClosureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
