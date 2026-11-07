#!/usr/bin/env bash
# Build the GitLab PoC on the attacker VM. Runs as xentry-guest.
# Args: poc_archive poc_sha256 poc_dir
set -euo pipefail
archive="${1:?poc_archive}"
expected_sha="${2:?poc_sha256}"
poc_dir="${3:?poc_dir}"
test -f "$archive"
echo "$expected_sha  $archive" | sha256sum -c -
rm -rf "$poc_dir"
mkdir -p "$poc_dir"
tar -xzf "$archive" -C "$poc_dir" --strip-components=1
cd "$poc_dir"
export HOME=/home/xentry-guest
export GOCACHE=/home/xentry-guest/.cache/go-build
go build -o CVE-2026-85706 CVE-2026-85706.go
test -x CVE-2026-85706
printf 'gitlab-poc-ready\n'
