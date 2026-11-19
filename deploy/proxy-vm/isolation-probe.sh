#!/usr/bin/env bash
# Run INSIDE the mirror VM. Proves the isolation that ADR 0002 claims.
#
# This is the test the ADR says to write first, and the reason is asymmetry:
# getting the mirror rules wrong breaks installs loudly, within one job.
# Getting the egress rules wrong gives this VM a quiet route to the operator's
# LAN, and nothing about a working job would ever reveal it. So the quiet
# failure is the one that gets a test.
#
# Exits non-zero on the first thing that should be unreachable and is not.
set -uo pipefail

FAIL=0
HOST_LAN=192.168.137.10      # the host this VM runs on
OPERATOR=192.168.136.1       # the workstation that drives it
DOCKER=172.17.0.1            # the host's docker bridge
GATEWAY=10.44.0.1            # this VM's own default gateway, i.e. the host

# Ports worth naming rather than scanning: a full sweep is slow and proves no
# more than a list of what actually runs there. 8000 is the xentry web app,
# which has no authentication - it is the single most valuable thing on the
# host and the first thing this VM must not be able to reach.
PORTS=(22 80 443 8000 5432 6379 9090 11211)

closed() {  # closed <host> <port>
  timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && return 1 || return 0
}

echo "=== the host must be unreachable on every port that matters"
for host in "$HOST_LAN" "$OPERATOR" "$DOCKER" "$GATEWAY"; do
  for port in "${PORTS[@]}"; do
    if closed "$host" "$port"; then
      printf '  ok      %s:%s refused\n' "$host" "$port"
    else
      printf '  REACHED %s:%s - THIS VM CAN TALK TO IT\n' "$host" "$port" >&2
      FAIL=1
    fi
  done
done

echo
echo "=== and must not answer a ping either"
for host in "$HOST_LAN" "$OPERATOR" "$GATEWAY"; do
  if timeout 3 ping -c1 -W2 "$host" >/dev/null 2>&1; then
    echo "  REACHED $host answers icmp" >&2
    FAIL=1
  else
    echo "  ok      $host does not answer icmp"
  fi
done

echo
echo "=== the internet must work, or this VM is pointless"
reached=0
for probe in 1.1.1.1:443 snapshot.debian.org:443 deb.debian.org:80; do
  host="${probe%:*}"; port="${probe##*:}"
  if closed "$host" "$port"; then
    echo "  unreachable  $probe"
  else
    echo "  ok           $probe"
    reached=$((reached + 1))
  fi
done
if [ "$reached" -eq 0 ]; then
  echo "  NOTHING on the internet is reachable - the mirrors cannot work" >&2
  FAIL=1
fi

echo
echo "=== the egress filter is actually loaded"
if nft list table inet xentry_mirror >/dev/null 2>&1; then
  drops=$(nft list table inet xentry_mirror | grep -c "drop")
  echo "  ok      table inet xentry_mirror present, $drops drop rules"
else
  echo "  the in-VM egress filter is NOT loaded" >&2
  echo "  the host still refuses this VM, but the second layer is missing" >&2
  FAIL=1
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "PASS  this VM reaches the internet and nothing private."
else
  echo "FAIL  isolation is not what ADR 0002 claims. Do not run jobs." >&2
fi
exit "$FAIL"
