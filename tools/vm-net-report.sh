#!/usr/bin/env bash
# WHY THE VM CANNOT REACH 1.1.1.1. Read-only, bounded, fast.
#
# resolv.conf already said 1.1.1.1 and 9.9.9.9, so the resolver address was
# never the problem - my earlier diagnosis was wrong. The VM cannot reach that
# address at all, and `getent hosts` takes about twenty seconds to admit it
# (two names, two servers, five seconds each), which is why it looked like a
# hang rather than a failure.
#
# This gathers the facts FIRST and in parallel-ish order, each with a short
# bound, so nothing waits on a timeout to tell you something.
#
# The isolation probe passed earlier with "1.1.1.1:443 ok" and
# "snapshot.debian.org:443 ok", so this worked at 02:47 and does not now.
# What changed since: job-nics.sh addressed two more NICs and turned on
# forwarding, the VM's own ruleset was reloaded for 10.43, and the host's
# permanent table was reloaded. Each is checked below.
set -uo pipefail

KEY=/etc/xentry/proxy-vm.key
PROXY=10.44.0.2
SSH="ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR root@$PROXY"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

say() { printf '\n=== %s\n' "$1"; }

say "1. the VM's addresses and routes"
timeout 15 $SSH 'ip -4 -br addr show; echo "--- routes"; ip route' 2>&1 | sed 's/^/  /'
echo "  (a default route via 10.44.0.1 is what reaching 1.1.1.1 depends on)"

say "2. can it reach anything at all, by address?"
timeout 20 $SSH '
  for t in 10.44.0.1 1.1.1.1 9.9.9.9; do
    if ping -c1 -W2 "$t" >/dev/null 2>&1; then echo "  ping $t: reply"
    else echo "  ping $t: no reply"; fi
  done
  for t in 1.1.1.1:53 1.1.1.1:443 199.232.18.132:80; do
    h=${t%:*}; p=${t##*:}
    if timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then
      echo "  tcp $t: open"
    else echo "  tcp $t: no answer"; fi
  done' 2>&1

say "3. one name, with a six-second bound"
timeout 8 $SSH "getent hosts deb.debian.org" 2>&1 | sed 's/^/  /' \
  || echo "  no answer within the bound"

say "4. the VM's own ruleset - is it dropping its own egress?"
timeout 15 $SSH 'nft list table inet xentry_mirror 2>&1 | grep -E "chain|accept|drop|policy"' \
  2>&1 | sed 's/^/  /'

say "5. counters: which rule is actually eating packets?"
timeout 15 $SSH 'nft -a list table inet xentry_mirror 2>/dev/null | grep -E "counter|drop"' \
  2>&1 | sed 's/^/  /' || echo "  (no counters on these rules)"

say "6. the host side"
echo "  --- table inet xentry_wan"
nft list table inet xentry_wan 2>&1 | grep -E "chain|accept|drop|policy" | sed 's/^/    /'
echo "  --- is the host forwarding, and does it NAT this subnet?"
echo "    ip_forward=$(sysctl -n net.ipv4.ip_forward)"
nft list ruleset 2>/dev/null | grep -iE "masquerade|snat" | head -5 | sed 's/^/    /' \
  || echo "    (no masquerade rule found in nft; libvirt may use iptables)"
iptables -t nat -S 2>/dev/null | grep -iE "masquerade" | head -5 | sed 's/^/    /' \
  || true
echo "  --- the bridge"
ip -4 -br addr show xentrywan0 | sed 's/^/    /'

say "7. does the HOST itself have working egress?"
if timeout 6 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then
  echo "  the host reaches 1.1.1.1:443 - so the upstream is fine"
else
  echo "  THE HOST cannot reach 1.1.1.1:443 either. The VM is not the problem."
fi

say "what to look at"
cat <<'HINT'
    no default route in 1            -> the VM never got one, or lost it when
                                       job-nics.sh touched the interfaces
    ping 10.44.0.1 no reply          -> expected: the host drops it
    ping 1.1.1.1 no reply AND
      tcp 1.1.1.1:443 no answer      -> egress is blocked or unrouted
    masquerade absent in 6           -> libvirt's NAT for xentry-wan is gone,
                                       so replies never come back
    host cannot reach 1.1.1.1 in 7   -> nothing to do with any of this work
HINT
