#!/usr/bin/env bash
# PHP2Shell readiness. Runs as xentry-guest.
set -euo pipefail
version="$(php -r 'echo PHP_VERSION;')"
test "$version" = "8.4.26"
apache2ctl -M 2>/dev/null | grep -q php_module
test "$(curl -fsS --max-time 5 http://127.0.0.1:8088/)" = "ok"
test -f /var/lib/xentry/setup-php.done
printf 'php=%s ready\n' "$version"
