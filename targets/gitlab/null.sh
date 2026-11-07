#!/usr/bin/env bash
# Null actor for GitLab: benign sign-in request, never the PoC.
# Args: target_ip
set -euo pipefail
target_ip="${1:?target_ip}"
curl -fsS --max-time 10 "http://$target_ip/users/sign_in" >/dev/null
printf 'gitlab-null-actor-no-nonce\n'
