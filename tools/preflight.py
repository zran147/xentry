"""Does the dated archive actually carry the package at an affected version?

No model call, no job, no VM. The check already resolved a package, a suite and
a serial; this asks the archive the one question that decides whether the job
can provision at all, and which until now was only answered four steps in by
readiness.
"""
import glob
import json
import pathlib
import re
import subprocess
import sys

DEB = "https://snapshot.debian.org/archive/debian/{serial}/dists/{suite}/main/binary-amd64/Packages.xz"
UBU = "https://snapshot.ubuntu.com/ubuntu/{serial}/dists/{suite}/{comp}/binary-amd64/Packages.xz"
UBUNTU_SUITES = {"focal", "jammy", "noble"}
COMPONENTS = ("main", "universe")


def index(serial: str, suite: str, comp: str) -> str:
    url = (UBU if suite in UBUNTU_SUITES else DEB).format(serial=serial, suite=suite, comp=comp)
    got = subprocess.run(
        ["curl", "-sSL", "-m", "180", url], capture_output=True, check=False
    )
    if got.returncode or not got.stdout[:6] == b"\xfd7zXZ\x00":
        return ""
    return subprocess.run(
        ["xz", "-dc"], input=got.stdout, capture_output=True, check=False
    ).stdout.decode("utf-8", "replace")


def versions(text: str, package: str) -> list[str]:
    found = []
    for stanza in text.split("\n\n"):
        if re.search(rf"^Package: {re.escape(package)}$", stanza, re.M):
            m = re.search(r"^Version: (.+)$", stanza, re.M)
            if m:
                found.append(m.group(1))
    return found


rows = []
for path in sorted(glob.glob("sw-*.json")):
    try:
        data = json.loads(pathlib.Path(path).read_text())
    except Exception:
        continue
    plan = data.get("plan")
    if not plan:
        continue
    serial = plan.get("apt_snapshot") or ""
    package = plan.get("resolved_package") or plan.get("packages") or ""
    if not serial or not package:
        continue
    rows.append(
        (
            path.replace("sw-", "").replace(".json", ""),
            data.get("cve_id") or "",
            serial,
            plan.get("suite") or "",
            package.split()[0],
            plan.get("expected_version") or "",
        )
    )

cache: dict[tuple[str, str, str], str] = {}
print(f"{'cve':17} {'suite':7} {'package':20} {'want':10} archive")
bad = 0
for name, cve, serial, suite, package, want in rows:
    hit: list[str] = []
    for comp in COMPONENTS:
        key = (serial, suite, comp)
        if key not in cache:
            cache[key] = index(serial, suite, comp)
        if not cache[key]:
            continue
        hit = versions(cache[key], package)
        if hit:
            break
    if not hit:
        verdict = "ABSENT from the dated archive"
        bad += 1
    elif want and not any(v.startswith(want) for v in hit):
        verdict = f"carries {hit[0]} - NOT {want}"
        bad += 1
    else:
        verdict = f"{hit[0]}  ok"
    print(f"{cve:17} {suite:7} {package[:20]:20} {want[:10] or '(any)':10} {verdict}")
print(f"\n{len(rows)} plans checked, {bad} would fail at provisioning", file=sys.stderr)
