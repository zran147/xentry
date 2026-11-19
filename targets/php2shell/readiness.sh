#!/usr/bin/env bash
# A pipeline ending in `grep -q` is a trap under `set -o pipefail`: grep exits
# at its first match and closes the pipe, the writer dies of SIGPIPE, and
# pipefail reports 141 for a pipeline that FOUND what it was looking for. It
# only bites once the writer exceeds the 64KB pipe buffer, so it is invisible
# on small inputs and intermittent on growing ones. `grep -c` reads to the end,
# so there is no early close and no signal.
# PHP2Shell readiness. Runs as xentry-guest.
set -euo pipefail
version="$(php -r 'echo PHP_VERSION;')"
test "$version" = "8.4.26"
[ "$(apache2ctl -M 2>/dev/null | grep -c php_module || true)" -gt 0 ]
test "$(curl -fsS --max-time 5 http://127.0.0.1:8088/)" = "ok"
test -f /var/lib/xentry/setup-php.done
printf 'php=%s ready\n' "$version"
