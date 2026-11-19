#!/usr/bin/env bash
# Dirty Frag readiness after the kernel reboot. Runs as xentry-guest.
set -euo pipefail
kernel="$(uname -r)"
test "$kernel" = "6.17.0-23-generic"
test -f /var/lib/xentry/setup-dirtyfrag.done
command -v gcc >/dev/null
command -v make >/dev/null
printf 'kernel=%s ready\n' "$kernel"
