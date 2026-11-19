#!/usr/bin/env bash
# WATCH THE PACKETS. Read-only, bounded, no guesses.
#
# The last report ruled out my theories: the VM has a default route, the host
# masquerades its subnet (222 udp packets counted), and the host's own egress
# works. So packets LEAVE and replies do not come back - or something drops
# them on return.
#
# Three measurements, in the order that narrows it fastest:
#
#   1. every nftables table on this host, and every forward policy. A drop in
#      ANY table kills a packet, so a stale per-job `xentry` table with
#      policy drop would block the VM's forwarded traffic while xentry_wan
#      looks perfectly correct.
#   2. tcpdump on BOTH interfaces while the VM pings - which tells us whether
#      the query reaches the uplink and whether a reply reaches the bridge.
#   3. the VM's loaded ruleset versus the file on disk, because the last
#      report showed it running an OLD one (10.42, and no tcp/22 rules).
set -uo pipefail

KEY=/etc/xentry/proxy-vm.key
PROXY=10.44.0.2
SSH="ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR root@$PROXY"
UPLINK=$(ip -4 route show default | awk '{print $5; exit}')

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
say() { printf '\n=== %s\n' "$1"; }

say "1. EVERY table on this host, and every forward policy"
nft list tables 2>&1 | sed 's/^/  /'
echo "  --- forward chains and their policies"
nft -a list ruleset 2>/dev/null \
  | awk '/table (inet|ip|ip6) /{t=$0} /chain .*\{/{c=$0} /hook forward/{print "  " t " | " c " | " $0}' \
  | sed 's/[{}]//g' | sed 's/  */ /g'
echo "  --- any drop rule that could match forwarded traffic from the VM"
nft list ruleset 2>/dev/null | grep -nE "policy drop|drop" | grep -iE "forward|xentry" \
  | head -12 | sed 's/^/    /'
echo "  (a stale per-job xentry table with a drop policy would do exactly this)"

say "1b. ZERO the counters, so what follows is about now"
# The masquerade counters read 222 udp packets, and I treated that as proof
# that egress works. Counters are CUMULATIVE: the isolation probe passed at
# 02:47, so those packets may be two hours old and prove nothing about the
# present. Reset, then measure.
nft reset counters >/dev/null 2>&1 || echo "  (could not reset nft counters)"
iptables -t nat -Z 2>/dev/null || true
echo "  counters zeroed"

say "1c. policy routing, which would bypass the default route entirely"
ip rule show 2>&1 | sed 's/^/  /'
echo "  --- conntrack entries for the VM, if any"
conntrack -L 2>/dev/null | grep -c "10.44.0.2" | sed 's/^/  flows: /' \
  || echo "  (conntrack tool not installed)"

say "2. the packets, while the VM pings 1.1.1.1 and resolves a name"
echo "  uplink is $UPLINK"
tcpdump -ni "$UPLINK" -c 20 -w /tmp/up.pcap 'host 1.1.1.1 or udp port 53' \
  >/dev/null 2>&1 &
up=$!
tcpdump -ni xentrywan0 -c 20 -w /tmp/br.pcap 'icmp or udp port 53' >/dev/null 2>&1 &
br=$!
sleep 1
timeout 12 $SSH 'ping -c3 -W2 1.1.1.1 >/dev/null 2>&1; getent hosts deb.debian.org' \
  >/dev/null 2>&1 || true
sleep 2
kill "$up" "$br" 2>/dev/null || true
wait "$up" "$br" 2>/dev/null || true
echo "  --- on the bridge (what the VM sent, and what came back to it)"
tcpdump -nr /tmp/br.pcap 2>/dev/null | head -12 | sed 's/^/    /' \
  || echo "    nothing captured"
echo "  --- on the uplink (what left this host, and what the internet answered)"
tcpdump -nr /tmp/up.pcap 2>/dev/null | head -12 | sed 's/^/    /' \
  || echo "    nothing captured"
rm -f /tmp/up.pcap /tmp/br.pcap
echo "  --- masquerade counters SINCE the reset above"
nft list ruleset 2>/dev/null | grep -iE "masquerade" | grep "10.44" \
  | sed 's/^/    /' || true
echo "  (zero here means nothing was forwarded during the test)"

say "3. the VM's loaded ruleset versus the file it should have loaded"
echo "  --- loaded (input chain)"
timeout 15 $SSH 'nft list chain inet xentry_mirror input 2>&1' | sed 's/^/    /'
echo "  --- on disk, /etc/nftables.conf (input chain)"
timeout 15 $SSH 'sed -n "/chain input/,/}/p" /etc/nftables.conf 2>&1 | grep -vE "^\s*#"' \
  | sed 's/^/    /'
echo "  (10.42 loaded while the file says 10.43 means nft -f never succeeded)"

say "what each outcome means"
cat <<'HINT'
    a drop in 1 under another table   -> that table is the cause; clear it
    nothing on the uplink in 2        -> the host is not forwarding the query
    query on the uplink, no reply     -> upstream drops it (NAT or provider)
    reply on the uplink, none on the
      bridge                          -> the host drops the return path
    reply on the bridge, VM still
      silent                          -> the VM's own input chain drops it
HINT
