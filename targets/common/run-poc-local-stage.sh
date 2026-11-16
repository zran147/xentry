#!/usr/bin/env bash
# Run a LOCAL privesc PoC that needs a helper running first, then carry the
# proof out through the host's serial console.
# Runs as xentry-guest ON THE TARGET.
# Args: poc_dir entrypoint nonce_path command
#
# The sixth shape, and CVE-2023-0386 is why: its README says
#
#   ./fuse ./ovlcap/lower ./gc        <- a FUSE mount that must stay up
#   ./exp                             <- the exploit, which gives a root shell
#
# so neither half alone is the PoC. `command` is the first line, quoted from
# the artifact and verified present in it, which is what keeps this inside the
# rule that no command comes from the app or the model: the harness runs text
# the PoC's own documentation contains, and nothing else.
#
# It is validated here as well as at admission, because a step script is the
# last place that can refuse: letters, digits, dot, slash, dash, underscore
# and spaces only, so word-splitting it is safe and no metacharacter can
# survive. It must also start with ./ - a helper is a file in this repository,
# never a program from PATH.
set -euo pipefail
poc_dir="${1:?poc_dir}"
entrypoint="${2:?entrypoint}"
nonce_path="${3:?nonce_path}"
command="${4:?command}"

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
[[ "$command" =~ ^\./[A-Za-z0-9._/-]+([[:space:]]+[A-Za-z0-9._/-]+)*$ ]] || {
  echo "refused stage command: $command" >&2; exit 2; }
case "$command" in
  *..*) echo "refused stage command: $command" >&2; exit 2 ;;
esac
[ "${#command}" -le 200 ] || { echo "stage command too long" >&2; exit 2; }

cd "$poc_dir"
case "$entrypoint" in
  *.py|*.sh|*.rb|*.pl|*.js|*.php) test -f "./$entrypoint" || {
    echo "no such file: ./$entrypoint" >&2; exit 2; } ;;
  *) [ -x "./$entrypoint" ] || { echo "not runnable: ./$entrypoint" >&2; exit 2; } ;;
esac

# Detached, with its own file descriptors: a helper that held this step's
# stdout would keep the step running for as long as the helper lived, and the
# step would time out with the exploit never tried.
stage_log=/tmp/xentry-stage.log
# shellcheck disable=SC2086 - validated above and must word-split
( setsid nohup $command >"$stage_log" 2>&1 </dev/null & ) >/dev/null 2>&1
sleep 3
printf 'stage 1 started: %s\n' "$command"
head -c 400 "$stage_log" 2>/dev/null || true

runner=()
case "$entrypoint" in
  *.py) runner=(python3) ;;
  *.sh) runner=(bash) ;;
esac
printf 'cat %s\nprintf "xentry-root-evidence:" > /dev/ttyS0; cat %s > /dev/ttyS0 2>&1\nexit\n' \
  "$nonce_path" "$nonce_path" | "${runner[@]}" "./$entrypoint"
