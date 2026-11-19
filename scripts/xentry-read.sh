#!/usr/bin/env bash
# Read-only diagnosis, for a sudoers grant that is NOT root-equivalent.
#
# WHY THIS EXISTS. The obvious sudoers entry -
#
#   seclab ALL=(root) NOPASSWD: /usr/bin/virsh, /usr/sbin/nft, \
#     /opt/xentry/.venv/bin/python, /usr/bin/ssh -i /etc/xentry/proxy-vm.key *
#
# - is root. Not "nearly root": `python` runs anything, `ssh -i key root@host
# <cmd>` runs anything in the VM, `nft` rewrites the firewall and `virsh` can
# define a domain with any disk attached. A wildcard argument makes it worse,
# because sudo matches globs and `*` spans spaces.
#
# This script is the narrow alternative. Every subcommand is a fixed command
# line with no caller-supplied arguments except a job id, which is checked
# against ^[0-9a-f]{32}$ before use. It reads; it never writes, installs,
# restarts, submits or deletes. Install it root-owned and not writable by the
# caller, so the surface is what you reviewed:
#
#   sudo install -o root -g root -m 755 scripts/xentry-read.sh \
#     /usr/local/sbin/xentry-read
#   printf '%s\n' 'seclab ALL=(root) NOPASSWD: /usr/local/sbin/xentry-read' \
#     | sudo tee /etc/sudoers.d/xentry-read
#   sudo chmod 440 /etc/sudoers.d/xentry-read
#   sudo visudo -cf /etc/sudoers.d/xentry-read     # ALWAYS check before trusting it
#
# Installs keep going through reviewed scripts. That was the right call and
# this does not change it: nothing here can alter the system.
set -euo pipefail

DB=/var/lib/xentry/xentry.db
JOBS=/var/lib/xentry/jobs
KEY=/etc/xentry/proxy-vm.key
PROXY=10.44.0.2
PY=/opt/xentry/.venv/bin/python
VM="ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=8 -o BatchMode=yes -o LogLevel=ERROR root@$PROXY"

usage() {
  cat <<'USAGE'
xentry-read <subcommand> [job_id]

  jobs                 the last 20 jobs, newest first
  job <id>             one job: outcome, steps, failure details, validation
  files <id>           the attempt directory's files, with sizes
  serial <id>          the target's serial console, last 80 lines
  transcript <id>      the step command transcripts recorded for the job
  journal              xentry-broker and xentry, last 60 lines each
  jump                 /var/lib/xentry/jump.log, the ssh tunnel's own reasons
  nft                  the host's full nftables ruleset
  virt                 libvirt domains, networks and their bridges
  net                  host bridges, their ports and the routes to the guests
  vm                   the proxy VM: filter, phase, dnsmasq, leases, sockets
  vm-journal           the proxy VM's unit logs
  all                  journal, nft, virt, net, vm
USAGE
}

job_id() {
  local id="${1:-}"
  [[ "$id" =~ ^[0-9a-f]{32}$ ]] || {
    # A prefix is allowed, resolved against the database rather than globbed.
    [[ "$id" =~ ^[0-9a-f]{6,32}$ ]] || { echo "bad job id: ${id:-missing}" >&2; exit 2; }
    id=$("$PY" - "$id" <<'SQL'
import sqlite3, sys
db = sqlite3.connect(f"file:{'/var/lib/xentry/xentry.db'}?mode=ro", uri=True)
rows = [r[0] for r in db.execute("SELECT id FROM jobs").fetchall()
        if r[0].startswith(sys.argv[1])]
if len(rows) != 1:
    sys.exit(f"{len(rows)} jobs match that prefix")
print(rows[0])
SQL
)
  }
  printf '%s' "$id"
}

case "${1:-}" in
  jobs)
    "$PY" - <<'SQL'
import sqlite3
db = sqlite3.connect("file:/var/lib/xentry/xentry.db?mode=ro", uri=True)
for row in db.execute(
    "SELECT id, cve_id, outcome, reason_code, created_at FROM jobs"
    " ORDER BY created_at DESC LIMIT 20"):
    print(f"  {row[0][:12]}  {str(row[1]):18} {str(row[2] or 'running'):10}"
          f" {str(row[3] or ''):28} {row[4]}")
SQL
    ;;
  job)
    id=$(job_id "${2:-}")
    "$PY" - "$id" <<'SQL'
import sqlite3, sys
db = sqlite3.connect("file:/var/lib/xentry/xentry.db?mode=ro", uri=True)
job = sys.argv[1]
row = db.execute(
    "SELECT cve_id, outcome, reason_code, created_at, finished_at, attempt_dir"
    " FROM jobs WHERE id = ?", (job,)).fetchone()
print(f"  job {job}")
print(f"  cve {row[0]}  outcome {row[1] or 'running'}  reason {row[2] or '-'}")
print(f"  {row[3]} -> {row[4] or '(open)'}")
print(f"  dir {row[5]}")
attempt = db.execute(
    "SELECT attempt_id FROM job_steps WHERE job_id = ? ORDER BY rowid DESC LIMIT 1",
    (job,)).fetchone()
for seq, name, state, detail, rc in db.execute(
    "SELECT seq, name, state, detail, reason_code FROM job_steps"
    " WHERE job_id = ? AND attempt_id = ? ORDER BY seq",
    (job, attempt[0] if attempt else "")):
    print(f"  {'     ' if state == 'passed' else 'FAIL '}seq{seq:<3} {name:16} {state}")
    if state != "passed" and (detail or rc):
        for line in str(detail or rc).splitlines():
            print(f"        {line}")
for v in db.execute(
    "SELECT verdict, authority, reason_code, runner_nonce_observed,"
    " null_actor_observed_nonce FROM validations WHERE job_id = ?", (job,)):
    print(f"  validation: {v[0]} | {v[1]} | {v[2]} | runner saw {v[3]},"
          f" null actor saw {v[4]}")
for seq, verb, status in db.execute(
    "SELECT seq, verb, status FROM broker_calls WHERE job_id = ? ORDER BY seq", (job,)):
    print(f"  broker {seq:<3} {verb:20} {status}")
SQL
    ;;
  files)   id=$(job_id "${2:-}"); find "$JOBS/$id" -type f -printf '  %10s  %p\n' | sort -k2 ;;
  serial)  id=$(job_id "${2:-}")
           for f in "$JOBS/$id"/*/*serial*.log; do
             [ -s "$f" ] || continue
             echo "  == $f"; tail -80 "$f" | sed 's/^/    /'
           done ;;
  transcript) id=$(job_id "${2:-}")
           for f in "$JOBS/$id"/*/*commands.txt "$JOBS/$id"/*/*.response.txt; do
             [ -s "$f" ] || continue
             echo "  == $f ($(wc -c <"$f") bytes)"; tail -60 "$f" | sed 's/^/    /'
           done ;;
  journal) journalctl -u xentry-broker -n 60 --no-pager
           echo; journalctl -u xentry -n 60 --no-pager ;;
  jump)    [ -s /var/lib/xentry/jump.log ] \
             && sort -u /var/lib/xentry/jump.log | tail -40 \
             || echo "  the jump log is empty" ;;
  nft)     nft -s list ruleset ;;
  virt)    virsh -c qemu:///system list --all
           virsh -c qemu:///system net-list --all
           for n in xentry-wan xentry-target xentry-attacker; do
             virsh -c qemu:///system net-dumpxml "$n" 2>/dev/null | grep -E "name|bridge|ip " \
               | sed "s/^/  $n /" || true
           done ;;
  net)     ip -br addr
           for b in xentrywan0 xentrytgt0 xentryatk0; do
             echo "  $b: $(ls /sys/class/net/$b/brif 2>/dev/null | tr '\n' ' ')" \
               "fd=$(cat /sys/class/net/$b/bridge/forward_delay 2>/dev/null)"
           done
           ip route show | grep -E "10\.4[34]\." || echo "  no routes to the job subnets"
           ip neigh show | grep -E "10\.4[34]\." || true ;;
  vm)      $VM "nft -s list ruleset; echo '--- phase.json:'; cat /etc/xentry-mirror/phase.json 2>/dev/null; \
             echo '--- job.json:'; cat /etc/xentry-mirror/job.json 2>/dev/null; \
             echo '--- resolv.conf:'; cat /etc/resolv.conf; \
             echo '--- leases:'; cat /var/lib/misc/dnsmasq.leases 2>/dev/null; \
             echo '--- listening:'; ss -ulnp -tlnp | grep -E ':(53|67|80|808[0-9]) '; \
             echo '--- addresses:'; ip -br addr; echo '--- neighbours:'; ip neigh" ;;
  vm-journal) $VM "journalctl -u xentry-mirror -n 60 --no-pager; \
             echo '--- dnsmasq:'; journalctl -u dnsmasq -n 40 --no-pager" ;;
  all)     for sub in journal nft virt net vm; do
             echo "===== $sub"; "$0" "$sub" 2>&1 | sed 's/^/  /' || true
           done ;;
  ""|-h|--help|help) usage ;;
  *)       echo "unknown subcommand: $1" >&2; usage >&2; exit 2 ;;
esac
