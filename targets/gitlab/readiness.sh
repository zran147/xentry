#!/usr/bin/env bash
# GitLab readiness. Runs as xentry-guest.
set -euo pipefail
version="$(dpkg-query -W -f='${Version}' gitlab-ce)"
case "$version" in
  19.2.5*) ;;
  *) echo "unexpected gitlab version: $version" >&2; exit 1 ;;
esac
test -f /var/lib/xentry/setup-gitlab.done
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://10.42.0.10/users/sign_in)"
case "$code" in
  200|302) ;;
  *) echo "gitlab http status: $code" >&2; exit 1 ;;
esac
printf 'gitlab=%s http=%s ready\n' "$version" "$code"
