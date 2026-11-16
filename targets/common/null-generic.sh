#!/usr/bin/env bash
# Null actor for a derived target: reach the service the ordinary way and never
# run the exploit. Runs as xentry-guest on the attacker.
# Args: target_ip port
set -euo pipefail
target_ip="${1:?target_ip}"
port="${2:?port}"
[[ "$target_ip" =~ ^[0-9.]+$ ]] || { echo "bad target_ip" >&2; exit 2; }
[[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo "bad port" >&2; exit 2; }
# A plain request, and whatever it returns. The point is that this output must
# not contain the nonce: the file is on the target and nothing serves it.
curl -sS --max-time 10 "http://$target_ip:$port/" 2>&1 | head -c 4096 || true
printf '\ngeneric-null-actor-no-nonce\n'
