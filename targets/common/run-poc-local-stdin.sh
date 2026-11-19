#!/usr/bin/env bash
# Run a LOCAL privesc PoC that hands over a root shell reading stdin, and
# carry the proof out through the host's serial console.
# Runs as xentry-guest ON THE TARGET. Args: poc_dir entrypoint nonce_path
#
# Two things the actor cannot do before the exploit runs, and readiness has
# already asserted the second: read /root/xentry-nonce, and write /dev/ttyS0
# (root:dialout 0660, and xentry-guest has no sudo and no supplementary
# groups). The serial console is wired to a file on the host that nothing
# inside this VM can reach, so a value appearing there was observed outside
# the guest rather than claimed inside it.
#
# The first cat goes to this transcript. The second goes to the console, which
# is the decisive channel; a PoC that ignores its stdin produces neither, and
# the job ends nonce_not_observed - the correct answer.
set -euo pipefail
poc_dir="${1:?poc_dir}"
entrypoint="${2:?entrypoint}"
nonce_path="${3:?nonce_path}"

case "$entrypoint" in
  /*|*..*) echo "refused entrypoint: $entrypoint" >&2; exit 2 ;;
esac
case "$nonce_path" in
  /*) ;;
  *) echo "nonce_path must be absolute" >&2; exit 2 ;;
esac
case "$nonce_path" in
  *[[:space:]]*) echo "nonce_path must not contain whitespace" >&2; exit 2 ;;
esac

cd "$poc_dir"
# A source file is not a runnable. The build step has already required this
# path to exist and be executable, so reaching here with a non-executable
# entrypoint means the extractor named the source rather than the binary the
# Makefile writes - and `exec ./hax.c` fails as "cannot execute binary file",
# which reads like a broken harness.
case "$entrypoint" in
  *.py|*.sh|*.rb|*.pl|*.js|*.php) test -f "./$entrypoint" || {
    echo "no such file: ./$entrypoint" >&2; exit 2; } ;;
  *) [ -x "./$entrypoint" ] || { echo "not runnable: ./$entrypoint" >&2; exit 2; } ;;
esac
runner=()
case "$entrypoint" in
  *.py) runner=(python3) ;;
  *.sh) runner=(bash) ;;
esac
printf 'cat %s\nprintf "xentry-root-evidence:" > /dev/ttyS0; cat %s > /dev/ttyS0 2>&1\nexit\n' \
  "$nonce_path" "$nonce_path" | "${runner[@]}" "./$entrypoint"
