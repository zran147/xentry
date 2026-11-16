#!/usr/bin/env bash
# Run a LOCAL privesc PoC that needs a terminal, and carry the proof out
# through the host's serial console.
# Runs as xentry-guest ON THE TARGET. Args: poc_dir entrypoint nonce_path
#
# The fourth shape. stdin-shell pipes into a root shell, which works whenever
# the exploit execs a shell that inherits its stdin - but a PoC that calls
# isatty(), or runs an interactive program, gets a pipe and does nothing. This
# one gives it a real PTY with util-linux's `script`, which is in the base
# image, and feeds the same two commands into it.
#
# Everything else is identical to run-poc-local-stdin.sh: the nonce is
# readable only by root, /dev/ttyS0 is writable only by root, readiness has
# already asserted both are shut to this actor, and the serial log is read on
# the host side where nothing in this VM can reach it.
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
command -v script >/dev/null || {
  echo "this shape needs util-linux's script and the image has none" >&2; exit 1; }

cd "$poc_dir"
case "$entrypoint" in
  *.py|*.sh|*.rb|*.pl|*.js|*.php) test -f "./$entrypoint" || {
    echo "no such file: ./$entrypoint" >&2; exit 2; } ;;
  *) [ -x "./$entrypoint" ] || { echo "not runnable: ./$entrypoint" >&2; exit 2; } ;;
esac
runner=""
case "$entrypoint" in
  *.py) runner="python3 " ;;
  *.sh) runner="bash " ;;
esac

# -q quiet, -e return the child's exit status, -c the command. The typescript
# goes to /dev/null: the decisive channel is the serial console, and the
# transcript this step prints is the step's own stdout.
printf 'cat %s\nprintf "xentry-root-evidence:" > /dev/ttyS0; cat %s > /dev/ttyS0 2>&1\nexit\n' \
  "$nonce_path" "$nonce_path" \
  | script -qec "${runner}./$entrypoint" /dev/null
