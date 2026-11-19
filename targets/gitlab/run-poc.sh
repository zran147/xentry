#!/usr/bin/env bash
# Run the GitLab PoC from the attacker VM. Runs as xentry-guest.
# The broker's target capture, not this transcript, is decisive; the transcript
# is echoed so the validator can see the exploit stages.
# Args: target_ip nonce_path poc_dir
set -euo pipefail
target_ip="${1:?target_ip}"
nonce_path="${2:?nonce_path}"
poc_dir="${3:?poc_dir}"
case "$nonce_path" in
  /*) ;;
  *) echo "nonce_path must be absolute" >&2; exit 2 ;;
esac
case "$nonce_path" in
  *[[:space:]]*) echo "nonce_path must not contain whitespace" >&2; exit 2 ;;
esac
cd "$poc_dir"
if ! ./CVE-2026-85706 -u "http://$target_ip" --file "$nonce_path" --no-banner \
  > "$poc_dir/run.log" 2>&1; then
  cat "$poc_dir/run.log" >&2
  exit 1
fi
test -s "$poc_dir/run.log"
cat "$poc_dir/run.log"
printf 'gitlab-poc-ran\n'
