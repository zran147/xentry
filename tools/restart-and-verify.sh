#!/usr/bin/env bash
# RESTART BOTH SERVICES, AND PROVE THEY ACTUALLY RESTARTED.
#
# Installs nothing. The files from install-reread-placed-config.sh are already
# on disk and correct - both trees carry setup-generic.sh at 2c4b810b2599 and
# steps.yaml pins that same digest. The problem is that the PROCESSES are
# older than the files:
#
#     xentry-broker  pid 1543975  started 02:33:51
#     xentry         pid 1549664  started 02:55:26
#     targets/steps.yaml                  03:04:10
#
# The broker caches its step registry at first use, so it was holding the OLD
# steps.yaml - whose pin is the OLD digest - and comparing it against the NEW
# script on disk. That is exactly the failure blasty got at step 7:
#
#     artifact_hash_mismatch: step script changed: setup-generic
#
# which is the integrity gate doing its job, on a mismatch I created.
#
# My install script ran `systemctl restart` and then checked `is-active`, and
# is-active passed - so it reported success. ACTIVE IS NOT RESTARTED: a service
# that never went down is active too. The same gap produced the bogus
# "WARNING: the app lost XENTRY_GITHUB_TOKEN", because MainPID came back empty
# and the check read /proc//environ.
#
# So this script asserts the thing that actually matters: each process's start
# time must be LATER than the newest file it is meant to have read. It refuses
# to report success otherwise.
set -euo pipefail

APP=/opt/xentry
BROKER=/opt/xentry
PORT=8000
BIND=192.168.137.10

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

echo "=== no job in flight"
inflight=$("$APP/.venv/bin/python" - <<'PY'
import sqlite3
db = sqlite3.connect("file:/var/lib/xentry/xentry.db?mode=ro", uri=True)
print(db.execute("SELECT COUNT(*) FROM jobs WHERE outcome IS NULL").fetchone()[0])
PY
)
[ "$inflight" = "0" ] || { echo "  $inflight job(s) running - wait or cancel" >&2; exit 1; }
echo "  none"

echo
echo "=== before"
newest=0
for f in "$BROKER/targets/steps.yaml" "$BROKER/targets/common/setup-generic.sh" \
         "$APP/targets/steps.yaml" "$APP/targets/common/setup-generic.sh" \
         "$APP/src/xentry/runner.py"; do
  m=$(stat -c %Y "$f")
  [ "$m" -gt "$newest" ] && newest=$m
  printf '  %s  %s\n' "$(date -u -d "@$m" '+%H:%M:%S')" "${f#/opt/}"
done
echo "  newest file: $(date -u -d "@$newest" '+%H:%M:%S') UTC"
for u in xentry-broker xentry; do
  p=$(systemctl show "$u.service" -p MainPID --value)
  if [ -n "$p" ] && [ "$p" != 0 ]; then
    printf '  %s  %s pid %s (started BEFORE the files: %s)\n' \
      "$(date -u -d "@$(stat -c %Y /proc/"$p")" '+%H:%M:%S')" "$u" "$p" \
      "$([ "$(stat -c %Y /proc/"$p")" -lt "$newest" ] && echo yes || echo no)"
  else
    printf '  %s is not running\n' "$u"
  fi
done

echo
echo "=== restarting"
systemctl restart xentry-broker.service
systemctl restart xentry.service

echo
echo "=== after: each process must have started AFTER the newest file"
failed=0
for u in xentry-broker xentry; do
  # MainPID can be empty for a moment after a restart, which is what made the
  # last script read /proc//environ. Wait for it rather than warning about it.
  pid=
  for _ in $(seq 1 30); do
    pid=$(systemctl show "$u.service" -p MainPID --value)
    [ -n "$pid" ] && [ "$pid" != 0 ] && break
    sleep 0.5
  done
  if [ -z "$pid" ] || [ "$pid" = 0 ]; then
    echo "  FAIL $u has no main process after 15s" >&2
    journalctl -u "$u" -n 30 --no-pager >&2
    failed=1
    continue
  fi
  started=$(stat -c %Y /proc/"$pid")
  if [ "$started" -lt "$newest" ]; then
    echo "  FAIL $u pid $pid started $(date -u -d "@$started" '+%H:%M:%S'), BEFORE the newest file" >&2
    failed=1
  else
    printf '  ok   %s pid %s started %s, after the newest file\n' \
      "$u" "$pid" "$(date -u -d "@$started" '+%H:%M:%S')"
  fi
done
[ "$failed" -eq 0 ] || { echo "  the restart did not take - NOT safe to run a job" >&2; exit 1; }

echo
echo "=== the broker now holds the digest that is on disk"
"$BROKER/.venv/bin/python" - <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path("/opt/xentry")
text = (root / "targets/steps.yaml").read_text()
start = text.index("script: common/setup-generic.sh")
pinned = text[start : start + 200].split("sha256:")[1].split()[0]
actual = hashlib.sha256(
    (root / "targets/common/setup-generic.sh").read_bytes()
).hexdigest()
print(f"  pinned {pinned[:12]}  on disk {actual[:12]}")
if pinned != actual:
    print("  still mismatched - a job would fail at provision", file=sys.stderr)
    sys.exit(1)
print("  ok  they match, so the integrity gate will pass")
PY

echo
echo "=== the restart kept the token (retrying MainPID, not warning on a race)"
pid=$(systemctl show xentry.service -p MainPID --value)
# grep -c, not -q: -q closes the pipe at the first match and tr dies of
# SIGPIPE, which pipefail then reports as failure for a successful match.
if [ "$(tr '\0' '\n' < "/proc/$pid/environ" | grep -c '^XENTRY_GITHUB_TOKEN=' || true)" -gt 0 ]; then
  echo "  ok  XENTRY_GITHUB_TOKEN is set in the running app"
else
  echo "  WARNING: the app has no XENTRY_GITHUB_TOKEN" >&2
fi

code=$(curl -sS -o /dev/null -m 10 -w '%{http_code}' -H 'Host: 127.0.0.1' \
  "http://${BIND}:${PORT}/" 2>/dev/null || true)
echo "  GET / -> $code"
