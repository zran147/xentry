#!/usr/bin/env bash
# Load this job's phase rules. Runs inside the mirror VM (ADR 0002 stage 2).
#
# The host used to carry these: nothing between the guests during
# provisioning, only the target's declared ports once locked. It could,
# because it had an address on their bridge. Stage 2 takes that address away -
# the guests' only neighbour is this VM - so the rules come here with it.
#
# Read from /etc/xentry-mirror/phase.json, written by the broker over ssh:
#
#   {"phase": "provisioning" | "locked",
#    "target_ip": "10.42.1.10", "attacker_ip": "10.42.2.20",
#    "target_ports": [8080], "mirror_ports": [80, 8082, 8083, 8084, 8086]}
#
# SCOPED BY SUBNET, NOT BY INTERFACE NAME. Interface names depend on PCI slots
# and have already cost two cycles in this VM's bring-up. Addresses are what
# the broker knows and what libvirt pins.
#
# PRIORITY -10, ten before the mirror table's 0, because xentry_mirror accepts
# 10.42.0.0/16 wholesale: the locked phase has to DROP the mirror ports and be
# consulted first. A drop in any table wins, but only if it is reached.
set -euo pipefail

CONFIG=/etc/xentry-mirror/phase.json
# Quoted: bash reads TABLE=inet xentry_phase as an assignment followed by
# a command, and runs xentry_phase.
TABLE="inet xentry_phase"
JOBS="{ 10.43.1.0/24, 10.43.2.0/24 }"

[ -f "$CONFIG" ] || { echo "refusing: $CONFIG does not exist" >&2; exit 1; }

# ONE VALUE PER LINE, not whitespace-separated.
#
# `read -r PHASE TARGET ... <<EOF` split on whitespace, and an nft port set is
# "{ 80, 8082 }" - which contains spaces. The fields tore apart and produced
# rules like `tcp dport 8080, 8443 } { 80, ... } accept`, which nft would have
# rejected at load time with a syntax error about the wrong thing entirely.
mapfile -t FIELDS < <(python3 - "$CONFIG" <<'PY'
import json
import sys

with open(sys.argv[1]) as fh:
    c = json.load(fh)
phase = c.get("phase", "")
if phase not in ("provisioning", "locked"):
    print(f"bad phase {phase!r}", file=sys.stderr)
    raise SystemExit(1)


def ports(key):
    got = [int(p) for p in (c.get(key) or []) if 0 < int(p) < 65536]
    if not got:
        return "-"
    return "{ " + ", ".join(str(p) for p in sorted(set(got))) + " }"


for value in (phase, c.get("target_ip") or "-", c.get("attacker_ip") or "-",
              ports("target_ports"), ports("mirror_ports")):
    print(value)
PY
)
[ "${#FIELDS[@]}" -eq 5 ] || {
  echo "refusing: $CONFIG did not yield five fields" >&2; exit 1; }
PHASE="${FIELDS[0]}"
TARGET="${FIELDS[1]}"
ATTACKER="${FIELDS[2]}"
TPORTS="${FIELDS[3]}"
MPORTS="${FIELDS[4]}"

rules=""
if [ "$PHASE" = "provisioning" ] && [ "$MPORTS" != "-" ]; then
  # Fetching is allowed. Crossing between the guests is not - that is the
  # forward chain below, which drops it in both phases unless locked opens one
  # path.
  rules="    ip saddr ${JOBS} tcp dport ${MPORTS} accept"
else
  # Locked: no tcp from a guest to this VM at all. An explicit drop, because
  # the mirror table admits the job subnets wholesale and would otherwise let
  # a PoC fetch during the phase that is supposed to forbid it. DHCP and DNS
  # are udp and are accepted above.
  rules="    ip saddr ${JOBS} meta l4proto tcp drop"
fi

cross=""
if [ "$PHASE" = "locked" ] && [ "$TPORTS" != "-" ] \
   && [ "$TARGET" != "-" ] && [ "$ATTACKER" != "-" ]; then
  cross="    ip saddr ${ATTACKER} ip daddr ${TARGET} tcp dport ${TPORTS} accept"
fi

tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
cat > "$tmp" <<NFT
table ${TABLE}
delete table ${TABLE}

table ${TABLE} {
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr ${JOBS} udp dport { 53, 67 } accept

    # THE BROKER'S CONTROL CHANNEL, WHICH THE LOCK USED TO CUT.
    #
    # Every guest command is tunnelled through this VM, so when the locked
    # phase dropped all tcp from the job subnets it dropped the replies from
    # the guest's own sshd to a connection this VM had opened. copy_poc -
    # the first step after lock_network - failed with
    #
    #     guest SSH did not become ready: Login timeout expired
    #
    # The forward chain below has carried this exemption from the start; the
    # input chain never did, because before the mirrors moved into a VM the
    # control channel did not pass through one.
    #
    # sport 22 AND established: only a reply, from a guest's sshd, on a flow
    # this VM initiated. A guest cannot fabricate conntrack state, so it
    # cannot use this to reach a mirror port - and the mirror ports are
    # 8081-8086 regardless.
    ip saddr ${JOBS} tcp sport 22 ct state established,related accept
${rules}
  }

  chain forward {
    type filter hook forward priority -10; policy accept;
${cross}
    ip saddr ${JOBS} ct state established,related accept
    ip saddr ${JOBS} drop
  }
}
NFT

if ! out=$(nft -f "$tmp" 2>&1); then
  echo "nft rejected the ${PHASE} rules:" >&2
  echo "$out" >&2
  cat -n "$tmp" >&2
  exit 1
fi
echo "phase ${PHASE} loaded"
nft list table ${TABLE}
