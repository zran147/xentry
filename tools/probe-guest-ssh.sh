#!/usr/bin/env bash
# THE GUEST HAS AN ADDRESS NOW. SO WHY CAN'T THE BROKER REACH ITS SSH?
#
# Diagnosis only. Installs nothing, changes nothing, restarts nothing.
#
# WHERE WE ARE
#
#   DHCPDISCOVER -> DHCPOFFER -> DHCPACK, 10.43.1.10 to the target. Done.
#   stage_approved: guest SSH did not become ready: Connection lost
#   /var/lib/xentry/jump.log: EMPTY, even with -v installed
#
# An empty -v log with a failing tunnel is contradictory: either the proxy
# never runs, or it runs and cannot write its log. "Connection lost" cannot
# tell those apart, and neither can I from here.
#
# So this submits apache and, the moment the lease appears, probes the exact
# same path three ways while the guest is still alive - the readiness loop
# keeps retrying for 60s, so there is a real window:
#
#   A  from the VM:     can anything reach 10.43.1.10:22 at all?
#   B  from the host:   the broker's exact proxy command, by hand
#   C  from the host:   direct, via the route the jumphost was meant to retire
#
#   A fails            -> the guest's sshd is not up; nothing else matters
#   A ok, B fails      -> the tunnel is the problem, and C will say so
#   A ok, B ok         -> the tunnel works by hand and the broker's use of it
#                         differs; that narrows it to asyncssh's invocation
#   A ok, B ok, C ok   -> everything works and the 60s window is just short
#
# It also prints the guest's serial console, under BOTH names, since
# target-serial.log has been 0 bytes every time and the qemu-side log may not.
set -euo pipefail

APP=/opt/xentry
KEY=/etc/xentry/proxy-vm.key
PROXY=10.44.0.2
BIND=192.168.137.10
GUEST=10.43.1.10
LOG=/var/lib/xentry/jump.log
SSHOPT="-i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=6 -o BatchMode=yes -o LogLevel=ERROR"
SSH="ssh $SSHOPT root@$PROXY"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

n=$("$APP/.venv/bin/python" -c "
import sqlite3
db = sqlite3.connect('file:/var/lib/xentry/xentry.db?mode=ro', uri=True)
print(db.execute('SELECT COUNT(*) FROM jobs WHERE outcome IS NULL').fetchone()[0])")
[ "$n" = "0" ] || { echo "$n job(s) running - wait" >&2; exit 1; }

: > "$LOG"; chmod 600 "$LOG"
echo "  jump log cleared ($(stat -c '%A %U' "$LOG"))"

echo
echo "=== submitting apache"
JAR=$(mktemp)
curl -sS -c "$JAR" -m 20 -o /dev/null -H 'Host: 127.0.0.1' "http://${BIND}:8000/"
TOK=$(awk '/xentry_token/{print $7}' "$JAR")
CVE=https://cveawg.mitre.org/api/cve/CVE-2021-41773
POC=https://github.com/blasty/CVE-2021-41773
CHECK=$(curl -sS -b "$JAR" -m 300 -X POST -H 'Host: 127.0.0.1' \
  -H "X-Xentry-CSRF: $TOK" -H 'Content-Type: application/json' \
  --data-binary "{\"cve_url\":\"$CVE\",\"poc_url\":\"$POC\"}" \
  "http://${BIND}:8000/api/links/check" \
  | "$APP/.venv/bin/python" -I -c 'import json,sys; print(json.load(sys.stdin).get("check_id",""))')
JOB=$(curl -sS -b "$JAR" -m 120 -X POST -H 'Host: 127.0.0.1' \
  -H "X-Xentry-CSRF: $TOK" -H 'Content-Type: application/json' \
  --data-binary "{\"cve_url\":\"$CVE\",\"poc_url\":\"$POC\",\"check_id\":\"$CHECK\"}" \
  "http://${BIND}:8000/api/jobs" \
  | "$APP/.venv/bin/python" -I -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
rm -f "$JAR"
echo "  job $JOB"

# The guest key is PER JOB - runtime.py:1392, jobs_root/<job>/keys/root - not
# the proxy key. Probing with the wrong one would fail on authentication and
# look exactly like a broken tunnel.
GKEY="/var/lib/xentry/jobs/$JOB/keys/root"
for _ in $(seq 1 30); do [ -f "$GKEY" ] && break; sleep 1; done
if [ -f "$GKEY" ]; then
  echo "  guest key: $GKEY  $(stat -c '%A %U:%G' "$GKEY")"
else
  echo "  guest key MISSING at $GKEY - probe B would fail on auth alone" >&2
fi

echo
echo "=== waiting for the lease (fast poll)"
for _ in $(seq 1 90); do
  if timeout 8 $SSH "grep -q $GUEST /var/lib/misc/dnsmasq.leases" 2>/dev/null; then
    echo "  $(date +%H:%M:%S)  the guest holds $GUEST"
    break
  fi
  sleep 2
done

echo
echo "=== PROBING, every 5s, while the broker is still retrying"
printf '  %-8s  %-22s  %-22s  %s\n' time "A: VM -> guest:22" "B: host -> tunnel" "C: host -> direct"
for i in $(seq 1 10); do
  a=$(timeout 10 $SSH "timeout 3 bash -c 'exec 3<>/dev/tcp/$GUEST/22' \
       >/dev/null 2>&1 && echo open || echo shut" 2>/dev/null || echo "vm-unreachable")
  if [ -f "$GKEY" ] && timeout 15 ssh -i "$GKEY" \
       -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o ConnectTimeout=6 -o BatchMode=yes -o LogLevel=ERROR \
       -o ProxyCommand="ssh $SSHOPT -W %h:%p root@$PROXY" \
       root@"$GUEST" true 2>/dev/null; then b=ok; else b=fail; fi
  c=$(timeout 6 bash -c "exec 3<>/dev/tcp/$GUEST/22" >/dev/null 2>&1 \
      && echo open || echo shut)
  printf '  %-8s  %-22s  %-22s  %s\n' "$(date +%H:%M:%S)" "$a" "$b" "$c"
  sleep 5
done

echo
echo "=== WHY B FAILS, in ssh's own words (one verbose attempt)"
if [ -f "$GKEY" ]; then
  timeout 25 ssh -i "$GKEY" -v \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=6 -o BatchMode=yes \
    -o ProxyCommand="ssh $SSHOPT -v -W %h:%p root@$PROXY" \
    root@"$GUEST" true 2>&1 | grep -viE "^debug[23]" \
    | grep -iE "connect|refused|denied|channel|auth|identity|banner|closed|open" \
    | head -16 | sed 's/^/  /'
else
  echo "  no guest key to try with"
fi

echo
echo "=== the VM's view of the guest"
timeout 20 $SSH "ip neigh show | grep '$GUEST' || echo '    no arp entry for the guest'
  echo '    --- and what the VM can see of its port 22:'
  timeout 3 bash -c 'exec 3<>/dev/tcp/$GUEST/22' 2>&1 && echo '      open' \
    || echo '      refused or unreachable'" 2>&1 | sed 's/^/  /'

echo
echo "=== THE TUNNEL'S OWN LOG, by hand this time"
if [ -s "$LOG" ]; then
  grep -iE "connect|refused|denied|channel|forward|auth" "$LOG" | sort -u | head -14 \
    | sed 's/^/  /'
else
  echo "  STILL EMPTY. Writing to it by hand to see whether the path works:"
  if ssh $SSHOPT -v -E "$LOG" -W 127.0.0.1:22 root@"$PROXY" </dev/null >/dev/null 2>&1; then
    :
  fi
  if [ -s "$LOG" ]; then
    echo "  the path is writable and -v logs fine, so the broker never ran the proxy:"
    tail -4 "$LOG" | sed 's/^/    /'
  else
    echo "  -v -E wrote nothing even by hand: the flag is not doing what I expected"
  fi
fi

echo
echo "=== the job's outcome"
"$APP/.venv/bin/python" - "$JOB" <<'DB'
import sqlite3, sys
db = sqlite3.connect("file:/var/lib/xentry/xentry.db?mode=ro", uri=True)
job = sys.argv[1]
outcome, reason = db.execute(
    "SELECT outcome, reason_code FROM jobs WHERE id = ?", (job,)).fetchone()
print(f"  outcome: {outcome or 'still running'}  reason: {reason or ''}")
attempt = db.execute(
    "SELECT attempt_id FROM job_steps WHERE job_id = ? ORDER BY rowid DESC LIMIT 1",
    (job,)).fetchone()
for seq, name, st, detail, rc in db.execute(
    "SELECT seq, name, state, detail, reason_code FROM job_steps"
    " WHERE job_id = ? AND attempt_id = ? ORDER BY seq",
    (job, attempt[0] if attempt else "")):
    if st != "passed":
        print(f"  FAIL seq{seq} {name}: {str(detail or rc)[:300]}")
DB

echo
echo "=== THE GUEST'S CONSOLE, both names"
for f in $(find /var/lib/xentry/jobs -name '*serial*' -newermt '-10 min' 2>/dev/null); do
  echo "  $f: $(stat -c %s "$f") bytes"
  if [ -s "$f" ]; then
    echo "  --- ssh, cloud-init, network:"
    grep -iE "sshd|cloud-init|dhcp|10\.43|authorized" "$f" | tail -12 | sed 's/^/      /'
    echo "  --- last 10 lines:"
    tail -10 "$f" | sed 's/^/      /'
  fi
done
