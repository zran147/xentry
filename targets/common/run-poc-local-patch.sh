#!/usr/bin/env bash
# Run a LOCAL privesc PoC that embeds the command root will execute, by
# replacing that command with the relay and nothing else.
# Runs as xentry-guest ON THE TARGET.
# Args: poc_dir entrypoint nonce_path command span
#
# The third shape. stdin-shell pipes into a root shell and argv-command passes
# one string; this one hands the caller no way to run anything - aishee's exim
# CVE-2019-10149 PoC sends a crafted recipient address and root executes a
# command the PoC itself contains. So the proof has to be substituted INTO the
# PoC's own text, which is what the quoted-command path already does for a
# curl line in a README.
#
# `command` is a quote the harness verified against the artifact, so it is
# evidence rather than text a model wrote, and it is used here only to LOCATE
# the file - the one file containing it, or this refuses. `span` is the part of
# it that names the command root runs, and only that span is replaced. The
# replacement carries no quotes of its own, because the span usually sits
# inside a quoted string in someone else's source.
set -euo pipefail
poc_dir="${1:?poc_dir}"
entrypoint="${2:?entrypoint}"
nonce_path="${3:?nonce_path}"
command="${4:?command}"
span="${5:?span}"

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
[ -n "$span" ] || { echo "no span to replace" >&2; exit 2; }

cd "$poc_dir"
mapfile -t holders < <(grep -rlF -- "$command" . 2>/dev/null || true)
if [ "${#holders[@]}" -ne 1 ]; then
  echo "the quoted command is in ${#holders[@]} files, not one: ${holders[*]-none}" >&2
  exit 1
fi
target_file="${holders[0]}"

# One occurrence of the span inside that one line, replaced with a command
# that contains no quotes: `cat /root/xentry-nonce >/dev/ttyS0`. Writing the
# console is the half of the proof the unprivileged actor cannot do.
NONCE_PATH="$nonce_path" SPAN="$span" FILE="$target_file" python3 - <<'PATCH'
import os

path = os.environ["FILE"]
span = os.environ["SPAN"]
relay = f"cat {os.environ['NONCE_PATH']} >/dev/ttyS0"
text = open(path, encoding="utf-8", errors="surrogateescape").read()
if text.count(span) != 1:
    raise SystemExit(f"the span appears {text.count(span)} times in {path}, not once")
open(path, "w", encoding="utf-8", errors="surrogateescape").write(
    text.replace(span, relay, 1)
)
print(f"patched {path}: {span!r} -> {relay!r}")
PATCH

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
exec "${runner[@]}" "./$entrypoint"
