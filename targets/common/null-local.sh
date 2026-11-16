#!/usr/bin/env bash
# Null actor for a local privesc job: try both halves of the proof with no
# exploit, and be denied both. Runs as xentry-guest ON THE TARGET.
# Args: nonce_path
#
# This is the control the whole observation rests on. If the nonce were
# readable, or the console writable, by the unprivileged actor, then the real
# run would prove nothing at all - and the job must fail here rather than
# later, with the nonce never reaching the serial log.
set -euo pipefail
nonce_path="${1:?nonce_path}"
case "$nonce_path" in
  /*) ;;
  *) echo "nonce_path must be absolute" >&2; exit 2 ;;
esac

if cat "$nonce_path" 2>/dev/null; then
  echo "the unprivileged actor can already read $nonce_path" >&2
  exit 1
fi
if printf 'xentry-null-actor' > /dev/ttyS0 2>/dev/null; then
  echo "the unprivileged actor can already write the serial console" >&2
  exit 1
fi
printf 'local-null-actor-denied-both\n'
