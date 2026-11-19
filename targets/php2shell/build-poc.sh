#!/usr/bin/env bash
# Extract the pinned PHP2Shell PoC on the attacker VM. Runs as xentry-guest.
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
test -f "$poc_dir/exploit.py"
chmod 0755 "$poc_dir/exploit.py"
printf 'php2shell-poc-ready\n'
