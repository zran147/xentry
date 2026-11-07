#!/usr/bin/env python3
"""Research Gate G artifact candidates. Never writes config/artifacts.yaml."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from xentry.artifact_tools import (
    candidate,
    extract_hashes,
    extract_urls,
    fetch_and_hash,
    fetch_gzip_text,
    fetch_text,
    github_latest_commit,
    load_catalog,
    now_iso,
    parse_deb822,
    parse_sha256sums,
)

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "artifacts.yaml"
OUT = ROOT / "var" / "research" / "artifacts-candidates.json"

SOURCES: dict[str, list[str]] = {
    "ubuntu-target-image": [
        "https://cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS",
        "https://cloud-images.ubuntu.com/releases/24.04/release/",
    ],
    "php-8.4.26-src": [
        "https://www.php.net/distributions/php-8.4.26.tar.xz.sha256",
        "https://www.php.net/releases/",
        "https://www.php.net/downloads",
    ],
    "gitlab-19.2.5-deb": [
        "https://packages.gitlab.com/gitlab/gitlab-ce",
        "https://packages.gitlab.com/gitlab/gitlab-ce/packages/ubuntu/jammy/gitlab-ce_19.2.5-ce.0_amd64.deb",
        "https://docs.gitlab.com/update/package/",
    ],
    "kernel-6.17.0-23": [
        "https://packages.ubuntu.com/search?keywords=linux-image-6.17.0-23-generic&searchon=names&suite=all&section=all",
        "https://launchpad.net/ubuntu/+source/linux",
    ],
}

GITHUB_REPOS = {
    "poc-php2shell": ("78ResearchLab/PHP2Shell-Full-Chain-Exploit", "main"),
    "poc-gitlab": ("gagaltotal/CVE-2026-85706-gitlab-poc", "main"),
    "poc-dirtyfrag": ("V4bel/dirtyfrag", "master"),
}

PHP_RELEASES_JSON = "https://www.php.net/releases/index.php?json&version=8.4.26"
GITLAB_PACKAGES_INDEX = (
    "https://packages.gitlab.com/gitlab/gitlab-ce/ubuntu/dists/noble/main/"
    "binary-amd64/Packages.gz"
)
KERNEL_PACKAGES_INDEX = (
    "https://security.ubuntu.com/ubuntu/dists/noble-security/main/"
    "binary-amd64/Packages.gz"
)
UBUNTU_RELEASES_INDEX = "https://cloud-images.ubuntu.com/releases/24.04/"
UBUNTU_IMAGE = "ubuntu-24.04-server-cloudimg-amd64.img"


def research_github(artifact_id: str, repo: str, branch: str) -> list[dict[str, str]]:
    info = github_latest_commit(repo, branch)
    tarball_sha, _ = fetch_and_hash(info["tarball_url"])
    return [
        candidate(
            artifact_id=artifact_id,
            url=info["tarball_url"],
            sha256=tarball_sha,
            commit=info["commit"],
            source_url=info["source_url"],
            method="github-api",
            notes=f"latest commit on {repo} branch {branch}; tarball hash computed from the pinned commit",
        )
    ]


def research_source(artifact_id: str, url: str) -> list[dict[str, str]]:
    text = fetch_text(url)
    candidates: list[dict[str, str]] = []
    sums = parse_sha256sums(text)
    for name, sha in sums.items():
        if artifact_id == "ubuntu-target-image" and "ubuntu-24.04-server-cloudimg-amd64.img" in name:
            candidates.append(
                candidate(
                    artifact_id=artifact_id,
                    url=f"https://cloud-images.ubuntu.com/releases/24.04/release/{name}",
                    sha256=sha,
                    source_url=url,
                    method="sha256sums",
                    notes=name,
                )
            )
    for sha in extract_hashes(text)[:5]:
        candidates.append(
            candidate(
                artifact_id=artifact_id,
                sha256=sha,
                source_url=url,
                method="regex",
                notes="hash found on vendor page; verify the matching file and version",
            )
        )
    for link in extract_urls(text)[:20]:
        if any(token in link.lower() for token in ("19.2.5", "8.4.26", "6.17.0-23", "gitlab-ce", "linux-image")):
            candidates.append(
                candidate(
                    artifact_id=artifact_id,
                    url=link,
                    source_url=url,
                    method="regex",
                    notes="matching link on vendor page",
                )
            )
    return candidates


def research_php(artifact_id: str) -> list[dict[str, str]]:
    data = json.loads(fetch_text(PHP_RELEASES_JSON))
    if str(data.get("version")) != "8.4.26":
        return []
    results: list[dict[str, str]] = []
    for item in data.get("source") or []:
        if not isinstance(item, dict):
            continue
        filename = str(item.get("filename") or "")
        sha = str(item.get("sha256") or "")
        if filename == "php-8.4.26.tar.xz" and sha:
            results.append(
                candidate(
                    artifact_id=artifact_id,
                    url=f"https://www.php.net/distributions/{filename}",
                    version=str(data.get("version")),
                    sha256=sha,
                    source_url=PHP_RELEASES_JSON,
                    method="vendor-json",
                    notes=f"official PHP release metadata; released {item.get('date', '')}",
                )
            )
    return results


def research_gitlab(artifact_id: str) -> list[dict[str, str]]:
    entries = parse_deb822(fetch_gzip_text(GITLAB_PACKAGES_INDEX))
    for entry in entries:
        if entry.get("Package") != "gitlab-ce" or entry.get("Architecture") != "amd64":
            continue
        if entry.get("Version") != "19.2.5-ce.0":
            continue
        filename = entry.get("Filename", "")
        sha = entry.get("SHA256", "")
        if filename and sha:
            return [
                candidate(
                    artifact_id=artifact_id,
                    url=(
                        "https://packages.gitlab.com/gitlab/gitlab-ce/ubuntu/"
                        f"{filename}?download=1"
                    ),
                    version=entry["Version"],
                    sha256=sha,
                    source_url=GITLAB_PACKAGES_INDEX,
                    method="apt-index",
                    notes=f"{filename}; {entry.get('Size', '?')} bytes",
                )
            ]
    return []


def research_kernel(artifact_id: str) -> list[dict[str, str]]:
    entries = parse_deb822(fetch_gzip_text(KERNEL_PACKAGES_INDEX))
    for entry in entries:
        if entry.get("Package") != "linux-image-6.17.0-23-generic":
            continue
        if entry.get("Architecture") != "amd64":
            continue
        if entry.get("Version") != "6.17.0-23.23~24.04.1":
            continue
        filename = entry.get("Filename", "")
        sha = entry.get("SHA256", "")
        if filename and sha:
            return [
                candidate(
                    artifact_id=artifact_id,
                    url=f"https://security.ubuntu.com/ubuntu/{filename}",
                    version=entry["Version"],
                    sha256=sha,
                    source_url=KERNEL_PACKAGES_INDEX,
                    method="apt-index",
                    notes=(
                        f"{filename}; {entry.get('Size', '?')} bytes; "
                        "linux-modules-6.17.0-23-generic is a separate dependency"
                    ),
                )
            ]
    return []


def research_ubuntu(artifact_id: str) -> list[dict[str, str]]:
    index = fetch_text(UBUNTU_RELEASES_INDEX)
    dated = sorted(set(re.findall(r"release-(\d{8}(?:\.\d+)?)/", index)))
    if not dated:
        return []
    release = dated[-1]
    base = f"https://cloud-images.ubuntu.com/releases/24.04/release-{release}/"
    sums = parse_sha256sums(fetch_text(base + "SHA256SUMS"))
    sha = sums.get(UBUNTU_IMAGE)
    if not sha:
        return []
    return [
        candidate(
            artifact_id=artifact_id,
            url=base + UBUNTU_IMAGE,
            sha256=sha,
            source_url=base + "SHA256SUMS",
            method="sha256sums",
            notes=f"dated Ubuntu 24.04 release {release}; {UBUNTU_IMAGE}",
        )
    ]


def maybe_llm(artifact_id: str, texts: list[tuple[str, str]]) -> list[dict[str, str]]:
    if not os.environ.get("DEEPSEEK_API_KEY"):
        return []
    try:
        import litellm
    except ImportError:
        return []
    prompt = (
        "Extract candidate artifact pins from the vendor text. Return a JSON list of "
        "objects with keys url, version, sha256, commit, source_url, notes. Only use "
        "values present in the text; never invent a hash. Artifact: " + artifact_id
    )
    body = "\n\n".join(f"SOURCE: {url}\n{text[:8000]}" for url, text in texts)
    response = litellm.completion(
        model=os.environ.get("XENTRY_VALIDATOR_MODEL", "deepseek/deepseek-chat"),
        api_key=os.environ.get("DEEPSEEK_API_KEY"),
        api_base=os.environ.get("DEEPSEEK_API_BASE"),
        messages=[{"role": "user", "content": prompt + "\n\n" + body}],
        temperature=0,
        timeout=120,
    )
    content = response.choices[0].message.content or ""
    raw = content.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
    if fenced:
        raw = fenced.group(1).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        array = re.search(r"\[.*\]", raw, re.DOTALL)
        parsed = json.loads(array.group(0)) if array else None
    if parsed is None:
        return [candidate(artifact_id=artifact_id, source_url="llm", method="llm", notes=content[:1000])]
    results: list[dict[str, str]] = []
    for item in parsed if isinstance(parsed, list) else []:
        if not isinstance(item, dict):
            continue
        results.append(
            candidate(
                artifact_id=artifact_id,
                url=str(item.get("url") or ""),
                version=str(item.get("version") or ""),
                sha256=str(item.get("sha256") or ""),
                commit=str(item.get("commit") or ""),
                source_url=str(item.get("source_url") or "llm"),
                method="llm",
                notes=str(item.get("notes") or ""),
            )
        )
    return results


DEDICATED = {
    "ubuntu-target-image": research_ubuntu,
    "php-8.4.26-src": research_php,
    "gitlab-19.2.5-deb": research_gitlab,
    "kernel-6.17.0-23": research_kernel,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--llm", action="store_true", help="add DeepSeek candidate summaries")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()

    catalog = load_catalog(CATALOG).get("artifacts", {})
    ids = list(catalog) if args.all or not args.artifact else args.artifact
    output: dict[str, object] = {"generated_at": now_iso(), "artifacts": {}}
    for artifact_id in ids:
        if artifact_id not in catalog:
            print(f"unknown artifact: {artifact_id}", file=sys.stderr)
            continue
        candidates: list[dict[str, str]] = []
        texts: list[tuple[str, str]] = []
        dedicated = DEDICATED.get(artifact_id)
        resolved = False
        if dedicated:
            try:
                found = dedicated(artifact_id)
                candidates.extend(found)
                resolved = bool(found)
            except Exception as exc:  # noqa: BLE001 - fall through to generic sources
                print(f"{artifact_id}: vendor source error: {exc}", file=sys.stderr)
        if artifact_id in GITHUB_REPOS:
            repo, branch = GITHUB_REPOS[artifact_id]
            try:
                candidates.extend(research_github(artifact_id, repo, branch))
            except Exception as exc:  # noqa: BLE001 - network/source gaps are candidates
                print(f"{artifact_id}: github error: {exc}", file=sys.stderr)
        if not resolved:
            for url in SOURCES.get(artifact_id, []):
                try:
                    text = fetch_text(url)
                    texts.append((url, text))
                    candidates.extend(research_source(artifact_id, url))
                except Exception as exc:  # noqa: BLE001 - source failures are candidate gaps
                    print(f"{artifact_id}: {url}: {exc}", file=sys.stderr)
        if args.llm and texts:
            candidates.extend(maybe_llm(artifact_id, texts))
        unique: dict[tuple[str, ...], dict[str, str]] = {}
        for item in candidates:
            key = (
                item.get("method", ""),
                item.get("url", ""),
                item.get("sha256", ""),
                item.get("commit", ""),
            )
            unique[key] = item
        candidates = list(unique.values())
        output["artifacts"][artifact_id] = {  # type: ignore[index]
            "current": catalog[artifact_id],
            "candidates": candidates,
        }
        print(f"{artifact_id}: {len(candidates)} candidate(s)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"candidates written to {args.out}")
    print("Research only. Review the source and run scripts/pin-artifact.py with --accept to pin.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
