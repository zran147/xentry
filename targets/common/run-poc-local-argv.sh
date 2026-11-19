#!/usr/bin/env bash
# Run a LOCAL privesc PoC that takes the command to run as an argument, and
# carry the proof out through the host's serial console.
# Runs as xentry-guest ON THE TARGET. Args: poc_dir entrypoint nonce_path
#
# Same channel and the same argument as run-poc-local-stdin.sh; only the way
# the exploit accepts the command differs. One command string, because that is
# what this shape takes - the PoC runs it however it runs it.
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
command="cat $nonce_path; printf 'xentry-root-evidence:' > /dev/ttyS0; cat $nonce_path > /dev/ttyS0 2>&1"
exec "${runner[@]}" "./$entrypoint" "sh -c \"$command\""
