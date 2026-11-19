#!/usr/bin/env bash
# A pipeline ending in `grep -q` is a trap under `set -o pipefail`: grep exits
# at its first match and closes the pipe, the writer dies of SIGPIPE, and
# pipefail reports 141 for a pipeline that FOUND what it was looking for. It
# only bites once the writer exceeds the 64KB pipe buffer, so it is invisible
# on small inputs and intermittent on growing ones. `grep -c` reads to the end,
# so there is no early close and no signal.
# WHY THE MIRROR VM IS NOT ANSWERING. Read-only: changes nothing.
#
# Shell, so no line budget. Run it when proxy-vm-up.sh cannot reach the VM.
# It reports every layer in order, so the first thing that is wrong is the
# first thing you see - rather than guessing between cloud-init, the network
# config, the NIC name and the firewall, which is what cost us the last cycle.
set -uo pipefail

RUN=/var/lib/xentry/proxy-vm
KEY=/etc/xentry/proxy-vm.key
NET=xentry-wan
BRIDGE=xentrywan0
VM=xentry-mirror
PROXY_IP=10.44.0.2
MAC=52:54:00:4d:49:52

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

say() { printf '\n=== %s\n' "$1"; }

say "1. does the domain exist and is it running?"
if virsh dominfo "$VM" 2>/dev/null | sed 's/^/    /'; then :; else
  echo "    NOT DEFINED - proxy-vm-up.sh did not get as far as defining it"
fi

say "2. what is it attached to?"
virsh domiflist "$VM" 2>/dev/null | sed 's/^/    /' \
  || echo "    (cannot list interfaces)"
echo "    expecting one interface on network $NET with mac $MAC"

say "3. is the wan network up, and does it have the bridge?"
virsh net-info "$NET" 2>/dev/null | sed 's/^/    /' || echo "    $NET is NOT defined"
ip -br addr show "$BRIDGE" 2>/dev/null | sed 's/^/    /' \
  || echo "    the bridge $BRIDGE does not exist on this host"

say "4. has the VM taken an address? (static, so a lease is NOT expected)"
virsh net-dhcp-leases "$NET" 2>/dev/null | sed 's/^/    /'
echo "    arp/neighbour table on $BRIDGE:"
ip neigh show dev "$BRIDGE" 2>/dev/null | sed 's/^/      /' \
  || echo "      (none - the VM has sent no traffic at all)"
if [ "$(ip neigh show dev "$BRIDGE" 2>/dev/null | grep -ci "$MAC" || true)" -gt 0 ]; then
  echo "    the VM's MAC is visible: it is booting and talking"
else
  echo "    the VM's MAC is NOT visible: it has sent nothing, so look at 6"
fi

say "5. can the host reach it at all?"
if ping -c2 -W2 "$PROXY_IP" >/dev/null 2>&1; then
  echo "    ping $PROXY_IP: up"
else
  echo "    ping $PROXY_IP: NO REPLY"
fi
if timeout 5 bash -c "exec 3<>/dev/tcp/$PROXY_IP/22" 2>/dev/null; then
  echo "    tcp 22: open"
else
  echo "    tcp 22: closed or filtered"
fi

say "5b. libvirt's own log - why a domain refuses to start"
# This is where qemu writes a permission error, and it is the file that
# would have ended the last cycle in one minute: the domain was "shut off"
# because the disk lived in a 750 root:root directory that the qemu user
# cannot traverse.
LOG=/var/log/libvirt/qemu/$VM.log
if [ -f "$LOG" ]; then
  echo "    $(wc -l < "$LOG") lines in $LOG"
  grep -iE "error|denied|permission|failed|cannot" "$LOG" | tail -12 | sed 's/^/      /' || echo "      (no error lines)"
  echo "    --- the last 12 lines"
  tail -12 "$LOG" | sed 's/^/      /'
else
  echo "    no $LOG - libvirt has never tried to start this domain"
fi

say "5c. can the qemu user actually reach the disk?"
echo "    the run directory and its contents:"
ls -la "$RUN" 2>/dev/null | sed 's/^/      /' || echo "      $RUN does not exist"
owner=$(ls -1 /var/lib/xentry/images/*-generic.qcow2 2>/dev/null | head -1)
if [ -n "$owner" ]; then
  echo "    an image libvirt already opens is owned by $(stat -c %U:%G "$owner") ($(stat -c %u:%g "$owner"))"
  echo "    $RUN is owned by $(stat -c %U:%G "$RUN" 2>/dev/null) mode $(stat -c %a "$RUN" 2>/dev/null)"
  if [ "$(stat -c %u "$RUN" 2>/dev/null)" != "$(stat -c %u "$owner")" ]; then
    echo "    MISMATCH: qemu runs as the image owner and cannot traverse a"
    echo "    directory owned by someone else with no group or other access."
  fi
fi

say "5e. the host's PERMANENT rules for this bridge"
# Without this table the VM can reach this host whenever no job is
# running, which is most of the time: the per-job table that used to
# carry the rule is created and cleared with each job.
if nft list table inet xentry_wan >/dev/null 2>&1; then
  echo "    present:"
  nft list table inet xentry_wan | sed 's/^/      /'
else
  echo "    MISSING. Between jobs, nothing on this host stops the mirror VM"
  echo "    reaching it - including port 8000, which has no authentication."
  echo "    Fix: sudo nft -f /etc/xentry/host-wan.nft"
  echo "         sudo systemctl enable --now xentry-wan-firewall"
fi
if systemctl is-enabled xentry-wan-firewall.service >/dev/null 2>&1; then
  echo "    xentry-wan-firewall.service: $(systemctl is-enabled xentry-wan-firewall.service), $(systemctl is-active xentry-wan-firewall.service)"
else
  echo "    xentry-wan-firewall.service is NOT enabled: the rules vanish on reboot"
fi

say "5d. apparmor denials mentioning this VM"
journalctl -k --since "-30 min" 2>/dev/null | grep -i apparmor \
  | grep -iE "xentry|proxy-vm|mirror" | tail -10 | sed 's/^/      /' || echo "      (none in the last 30 minutes)"

say "6. the guest's serial output - what the VM itself printed"
# Two files: serial.log is what the guest wrote to its serial port, and
# console.log is libvirt's own log of that chardev. Only the first has the
# boot. Both were empty until the domain XML got serial_path as well as
# serial_log_path - with the log path alone libvirt gives the domain a pty and
# writes nothing anywhere.
for f in serial.log console.log; do
  if [ -s "$RUN/$f" ]; then
    echo "    --- $RUN/$f ($(wc -l < "$RUN/$f") lines), cloud-init and network"
    grep -iE "cloud-init|datasource|nocloud|dhcp|10\.44\.0\.2|ssh-ed25519|login:" \
      "$RUN/$f" | tail -20 | sed 's/^/      /'
    echo "    --- its last 20 lines"
    tail -20 "$RUN/$f" | sed 's/^/      /'
  elif [ -f "$RUN/$f" ]; then
    echo "    $RUN/$f exists but is EMPTY"
  else
    echo "    $RUN/$f does not exist"
  fi
done

say "6b. the console log - cloud-init's own account"
if [ -f "$RUN/console.log" ]; then
  echo "    $(wc -l < "$RUN/console.log") lines in $RUN/console.log"
  echo "    --- datasource and seed"
  grep -iE "datasource|nocloud|cidata|no instance data" "$RUN/console.log" \
    | tail -12 | sed 's/^/      /' || echo "      (nothing about a datasource)"
  echo "    --- network"
  grep -iE "mirror0|eth0|enp|dhcp|static|10\.44\.0\.2" "$RUN/console.log" \
    | tail -12 | sed 's/^/      /' || echo "      (nothing about an address)"
  echo "    --- ssh keys"
  grep -iE "ssh-ed25519|authorized_keys|ssh.*key" "$RUN/console.log" \
    | tail -6 | sed 's/^/      /' || echo "      (no key was installed)"
  echo "    --- the last 25 lines"
  tail -25 "$RUN/console.log" | sed 's/^/      /'
else
  echo "    THERE IS NO CONSOLE LOG at $RUN/console.log"
  echo "    The domain was defined before the script asked for one. Re-run"
  echo "    proxy-vm-up.sh: it now redefines the domain every time."
fi

say "7. what is in the seed the VM was given?"
for f in meta-data user-data network-config; do
  if [ -f "$RUN/$f" ]; then
    echo "    --- $f"
    sed 's/^/      /' "$RUN/$f"
  else
    echo "    $f IS MISSING - cloud-init ignores a NoCloud seed with no meta-data"
  fi
done
if [ -f "$RUN/seed.iso" ]; then
  echo "    --- files actually inside seed.iso"
  if command -v isoinfo >/dev/null 2>&1; then
    isoinfo -f -i "$RUN/seed.iso" | sed 's/^/      /'
  else
    echo "      (install genisoimage's isoinfo to list it)"
  fi
fi

say "8. the key"
if [ -f "$KEY" ]; then
  echo "    $KEY present, $(stat -c %a "$KEY") $(stat -c %U:%G "$KEY")"
  echo "    public: $(cut -c1-60 "${KEY}.pub")..."
  if [ -f "$RUN/user-data" ] && grep -qF "$(cut -d' ' -f2 "${KEY}.pub")" "$RUN/user-data"; then
    echo "    and the seed carries this exact key"
  else
    echo "    THE SEED DOES NOT CARRY THIS KEY - it was regenerated after the"
    echo "    seed was built. Re-run proxy-vm-up.sh."
  fi
else
  echo "    $KEY is missing"
fi

say "9. a verbose ssh attempt"
timeout 20 ssh -i "$KEY" -vv \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=8 -o BatchMode=yes \
  "root@$PROXY_IP" true 2>&1 | tail -20 | sed 's/^/    /'

say "what this usually means"
cat <<'HINT'
    domain "shut off", no console log        -> it never started: read 5b, and
                                                check 5c for a directory the
                                                qemu user cannot traverse
    no MAC in the arp table, no console log  -> the domain never started
    console log but no datasource lines      -> meta-data missing from the seed
    datasource found, no address             -> the network-config did not match
                                                the NIC; it matches by MAC now
    address but tcp 22 filtered              -> the VM's own nftables loaded
                                                before the host was allowed in
    everything up, ssh permission denied     -> the seed carries an older key
HINT
