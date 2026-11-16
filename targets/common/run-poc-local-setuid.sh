#!/usr/bin/env bash
# Run a LOCAL privesc PoC that leaves a setuid-root binary behind, then use
# that binary to carry the proof out through the host's serial console.
# Runs as xentry-guest ON THE TARGET. Args: poc_dir entrypoint nonce_path
#
# The fifth shape. The exploit itself returns without giving the caller
# anything: what it leaves is a file owned by root with the setuid bit, and
# running THAT is what runs as root. CVE-2021-22555 and several container
# escapes are this shape.
#
# The dropped file is found, not named: exactly one file under the PoC
# directory that is setuid AND owned by root AND did not exist before the
# exploit ran. More than one, or none, and this refuses - the same rule the
# fixed-command shape uses for locating its file, and for the same reason: a
# harness that picks between candidates is choosing what "the PoC" means.
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

before="$(find . -perm -4000 -user root -type f 2>/dev/null | sort || true)"
# A non-zero exit is not fatal here: this shape's exploit is expected to run
# and return, and what matters is what it left behind.
"${runner[@]}" "./$entrypoint" || true
after="$(find . -perm -4000 -user root -type f 2>/dev/null | sort || true)"

mapfile -t dropped < <(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") \
  | grep -v '^$' || true)
if [ "${#dropped[@]}" -ne 1 ]; then
  echo "the exploit left ${#dropped[@]} new setuid-root files, not one:" >&2
  printf '  %s\n' "${dropped[@]-none}" >&2
  exit 1
fi
printf 'setuid-root dropped: %s\n' "${dropped[0]}"

# Through the dropped binary, which is the only thing here that runs as root.
printf 'cat %s\nprintf "xentry-root-evidence:" > /dev/ttyS0; cat %s > /dev/ttyS0 2>&1\nexit\n' \
  "$nonce_path" "$nonce_path" | "${dropped[0]}"
