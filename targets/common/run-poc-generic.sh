#!/usr/bin/env bash
# Run a derived target's PoC against the target. Runs as xentry-guest on the
# attacker. Args: poc_dir entrypoint target_ip port nonce_path
#
# The nonce path is passed as an argument because a read primitive has to be
# told what to read. Whether the PoC prints what it read is the PoC's business;
# if it does not, the nonce never reaches this transcript and the job ends
# nonce_not_observed, which is the correct answer.
set -euo pipefail
poc_dir="${1:?poc_dir}"
entrypoint="${2:?entrypoint}"
target_ip="${3:?target_ip}"
port="${4:?port}"
nonce_path="${5:?nonce_path}"
poc_args="${6-}"

[[ "$target_ip" =~ ^[0-9.]+$ ]] || { echo "bad target_ip" >&2; exit 2; }
[[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo "bad port" >&2; exit 2; }
case "$entrypoint" in
  /*|*..*) echo "refused entrypoint: $entrypoint" >&2; exit 2 ;;
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
# Three positionals are this harness's own convention, and a PoC with named
# flags cannot be driven by it: kozmer/log4j-shell-poc answered
#   poc.py: error: unrecognized arguments: 10.42.1.10 8080 /var/lib/xentry/nonce
#   usage: poc.py [-h] [--userip userip] [--webport webport] [--lport lport]
# after seventeen steps had passed. poc_args carries the invocation the PoC
# actually documents, as TOKENS - every one checked here before it reaches the
# command line, and the three placeholders substituted from the arguments this
# step already has. No token may contain a space, a quote or a shell
# metacharacter, so the list cannot become a second command.
argv=()
if [ -n "${poc_args// /}" ]; then
  for tok in $poc_args; do
    case "$tok" in
      "{ip}") argv+=("$target_ip") ;;
      "{port}") argv+=("$port") ;;
      "{nonce}") argv+=("$nonce_path") ;;
      # ONE argv element, quoting preserved by the array: a flag like redis's
      # -x takes a command, and "cat <path>" is two words. Expanded here rather
      # than accepted as a token, because a token containing a space is what
      # would let the argv list become a second command.
      "{read_nonce}") argv+=("cat $nonce_path") ;;
      *)
        [[ "$tok" =~ ^(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*|[A-Za-z0-9][A-Za-z0-9._/:=-]*)$ ]] || {
          echo "refused poc_args token: $tok" >&2; exit 2; }
        argv+=("$tok") ;;
    esac
  done
else
  argv=("$target_ip" "$port" "$nonce_path")
fi
# SAY WHETHER THE TARGET IS EVEN REACHABLE, BEFORE BLAMING THE PoC.
#
# A PoC that cannot connect usually prints nothing and exits non-zero, so the
# step's whole detail becomes the invoking line and nothing else. That is what
# CVE-2021-41773 did here, twice, after eighteen steps had passed - and the
# first thing anyone needs to know is whether the port was open from THIS
# machine, which only this machine can answer.
#
# Three seconds, bounded, no dependency on curl or nc being installed.
if timeout 3 bash -c "exec 3<>/dev/tcp/$target_ip/$port" 2>/dev/null; then
  echo "reachable: $target_ip:$port accepted a connection from here" >&2
else
  echo "UNREACHABLE: $target_ip:$port refused or dropped from here." >&2
  echo "  The PoC is about to run anyway, but if it prints nothing this is" >&2
  echo "  why. Check the attacker's route to the target and the forward" >&2
  echo "  rules for the locked phase - the two guests are on separate" >&2
  echo "  bridges, so their traffic is routed and filtered, not switched." >&2
  ip route get "$target_ip" 2>&1 | head -1 | sed 's/^/  route: /' >&2 || true
fi
printf 'invoking: %s %s' "./$entrypoint" "${argv[*]}" >&2; echo >&2
exec "${runner[@]}" "./$entrypoint" "${argv[@]}"
