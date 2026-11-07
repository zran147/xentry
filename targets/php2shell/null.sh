#!/usr/bin/env bash
# Null actor for PHP2Shell: make a benign request and never run the exploit.
# Args: target_ip
set -euo pipefail
target_ip="${1:?target_ip}"
curl -fsS --max-time 10 "http://$target_ip:8088/" >/dev/null
printf 'php2shell-null-actor-no-nonce\n'
