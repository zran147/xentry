#!/usr/bin/env bash
# A pipeline ending in `grep -q` is a trap under `set -o pipefail`: grep exits
# at its first match and closes the pipe, the writer dies of SIGPIPE, and
# pipefail reports 141 for a pipeline that FOUND what it was looking for. It
# only bites once the writer exceeds the 64KB pipe buffer, so it is invisible
# on small inputs and intermittent on growing ones. `grep -c` reads to the end,
# so there is no early close and no signal.
# BRING UP THE MIRROR VM (ADR 0002, stage 1).
#
# Shell, so it costs no line budget. Reviewable, idempotent, and it refuses to
# finish green unless the isolation probe passes from inside the VM.
#
# WHAT THIS BUILDS
#
#   xentry-wan        a persistent NAT network, 10.44.0.0/24
#   xentry-mirror     a persistent VM at 10.44.0.2 running the five mirrors
#
# and leaves the host's rules untouched until you set two environment
# variables, which the script prints at the end. Until then every job runs
# exactly as it does today, with the mirrors on the host. That is deliberate:
# a lab with six reproduced CVEs should not be cut over by a script that has
# never run.
#
# I HAVE NOT RUN THIS. I cannot: libvirt here needs privileges this account
# does not have, so every virsh call below is written from the broker's own
# code paths and the libvirt documentation, not from a successful execution.
# Read it before you run it. The probe at the end is what decides whether it
# worked - not the absence of errors.
set -euo pipefail

APP=/opt/xentry
# ONE TREE NOW. This said /opt/xentry-broker, which was retired when the
# duplicate clone was collapsed - and it is not overridable, so the moment that
# directory went away this script could no longer render a network XML or a
# domain XML. The collapse broke it and nothing noticed until the README was
# rewritten against the new layout.
BROKER=/opt/xentry
BROKER_PY="$BROKER/.venv-broker/bin/python"
# The files copied into the VM come from the tree, not from a developer's
# home: this was hardcoded to /home/seclab/xentry-work/env, so an installed
# copy read its payload out of one person's work tree and a from-zero clone
# would fail at the first scp. Overridable, because iterating on the VM's
# files is exactly when you want to point it elsewhere.
SRC="${SRC:-/opt/xentry}"
IMAGES=/var/lib/xentry/images
RUN=/var/lib/xentry/mirror-vm
KEY=/etc/xentry/proxy-vm.key

NET=xentry-wan
BRIDGE=xentrywan0
GATEWAY=10.44.0.1
PROXY_IP=10.44.0.2
MAC=52:54:00:4d:49:52          # "MIR"
# ADR 0002 stage 2: one bridge for the target, one for the attacker,
# neither with an address on this host. The proxy VM gets a NIC on each
# and routes between them, carrying the phase rules the host used to.
#
# PERSISTENT and fixed, not per job, because gate G8 runs one job at a
# time: two jobs never want these subnets at once. That also means the
# VM's three NICs are defined once instead of hotplugged per job.
TNET=xentry-target
TBRIDGE=xentrytgt0
TMAC=52:54:00:4d:49:54
ANET=xentry-attacker
ABRIDGE=xentryatk0
AMAC=52:54:00:4d:49:41
STAGE2="${STAGE2:-1}"
VM=xentry-mirror
MEM_MB=2048
VCPU=2
# The PRISTINE cloud image, not debian-11-generic.qcow2. The generic images
# are built artifacts that have already booted: cloud-init recorded an
# instance-id and marked itself done, so a new seed can be ignored
# entirely. This file is qcow2 despite the .img name - qemu-img says so.
# Overridable: BASE=ubuntu-24.04-base.img retires both the end-of-life
# bullseye pool (its packages are only on archive.debian.org now) and
# Python 3.9, which is what broke the mirrors on import.
BASE="${BASE:-debian-11-base-image.img}"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

echo "=== preconditions"
for tool in virsh qemu-img genisoimage ssh-keygen; do
  command -v "$tool" >/dev/null || {
    echo "  $tool is not installed" >&2
    [ "$tool" = genisoimage ] && echo "  (apt-get install genisoimage)" >&2
    exit 1; }
done
echo "  tools present"

inflight=$("$APP/.venv/bin/python" - <<'DB'
import sqlite3

# A MISSING DATABASE IS NOT AN ERROR HERE.
#
# This opens the index read-only to refuse while a job is running. On a fresh
# install - or after a reset that cleared the state - the file does not exist
# yet, because the app has never started and has not applied its migrations.
# sqlite3 then raised, the command substitution failed, and set -euo pipefail
# killed step 11 with
#
#     sqlite3.OperationalError: unable to open database file
#
# which reads as a broken bring-up rather than "there is nothing to wait for".
# No database, or no jobs table, means no job can be in flight.
try:
    db = sqlite3.connect("file:/var/lib/xentry/xentry.db?mode=ro", uri=True)
    print(db.execute("SELECT COUNT(*) FROM jobs WHERE outcome IS NULL").fetchone()[0])
except sqlite3.Error:
    print(0)
DB
)
[ "$inflight" = "0" ] || { echo "  $inflight job(s) running - wait" >&2; exit 1; }
echo "  no job in flight"

[ -f "$IMAGES/$BASE" ] || { echo "  $IMAGES/$BASE is missing" >&2; exit 1; }
echo "  base image $BASE"

mkdir -p "$RUN" /etc/xentry

# WHO QEMU RUNS AS. This is why the first attempt never started: the
# directory was 750 root:root, and a qemu process running as another user
# cannot traverse it - so libvirt failed to open the disk and the domain
# stayed "shut off". runtime.py chowns every per-job VM file to this same
# user for exactly this reason (see _ensure_keys/overlay there).
#
# Three sources, in order of authority, and the one used is printed.
QEMU_OWNER=
for envfile in /etc/xentry/broker.env /etc/xentry/app.env; do
  [ -f "$envfile" ] || continue
  v=$(sed -n "s/^XENTRY_QEMU_USER=//p" "$envfile" | tr -d \"\' | head -1)
  [ -n "$v" ] && { QEMU_OWNER="$v"; SOURCE="$envfile"; break; }
done
if [ -z "$QEMU_OWNER" ]; then
  # The images libvirt already opens are the best available evidence.
  probe=$(ls -1 "$IMAGES"/*-generic.qcow2 2>/dev/null | head -1)
  if [ -n "$probe" ]; then
    QEMU_OWNER="$(stat -c %u:%g "$probe")"
    SOURCE="the owner of $(basename "$probe")"
  fi
fi
if [ -z "$QEMU_OWNER" ] && [ -r /etc/libvirt/qemu.conf ]; then
  u=$(sed -n "s/^user *= *\"\(.*\)\"/\1/p" /etc/libvirt/qemu.conf | head -1)
  g=$(sed -n "s/^group *= *\"\(.*\)\"/\1/p" /etc/libvirt/qemu.conf | head -1)
  if [ -n "$u" ]; then
    QEMU_OWNER="$(id -u "$u"):$(getent group "${g:-$u}" | cut -d: -f3)"
    SOURCE=/etc/libvirt/qemu.conf
  fi
fi
[ -n "$QEMU_OWNER" ] || {
  echo "  cannot determine the user qemu runs as." >&2
  echo "  Set XENTRY_QEMU_USER=uid:gid in /etc/xentry/broker.env and re-run." >&2
  exit 1; }
echo "  qemu runs as $QEMU_OWNER (from $SOURCE)"
chown "$QEMU_OWNER" "$RUN"
chmod 2750 "$RUN"

echo
echo "=== the key the broker will use to configure this VM per job"
if [ -f "$KEY" ]; then
  echo "  $KEY exists, reusing it"
else
  ssh-keygen -t ed25519 -N "" -C "xentry-proxy-vm" -f "$KEY" >/dev/null
  chmod 600 "$KEY"; chown root:root "$KEY"
  echo "  generated $KEY"
fi
PUB=$(cat "${KEY}.pub")

# APT SOURCES FOR THE BASE, decided here rather than discovered later.
#
# Debian 11's LTS has ended: security.debian.org still publishes an index for
# bullseye but has emptied the pool behind it, so a fresh VM cannot install
# anything - dnsmasq included - and the failure reads as a 404 on a version
# apt correctly asked for. archive.debian.org has both the index and the bytes.
#
# An Ubuntu base is in support and needs nothing.
APT_SOURCES=""
case "$BASE" in
  debian-11-*)
    APT_SOURCES="  - path: /etc/apt/sources.list
    content: |
      deb http://archive.debian.org/debian bullseye main
      deb http://archive.debian.org/debian-security bullseye-security main
  - path: /etc/apt/apt.conf.d/99xentry-archive
    content: |
      Acquire::Check-Valid-Until \"false\";
"
    echo "  sources: archive.debian.org (bullseye is past end of life)"
    ;;
  *)
    echo "  sources: the image's own (in support)"
    ;;
esac

echo
echo "=== the wan network"
# Rendered by the broker's own builder, so the XML this installs is the XML
# its tests cover - not a second copy written in shell.
"$BROKER_PY" - "$NET" "$BRIDGE" "$MAC" "$PROXY_IP" "$GATEWAY" \
  > "$RUN/network.xml" <<'PYX'
import sys
sys.path.insert(0, "/opt/xentry")
from broker.libvirt_ops import network_xml

name, bridge, mac, ip, gateway = sys.argv[1:6]
sys.stdout.write(
    network_xml(
        name=name, bridge=bridge, target_mac=mac, target_ip=ip,
        gateway=gateway, forward="nat",
    )
)
PYX
grep -q "mode='nat'" "$RUN/network.xml" || {
  echo "  the rendered network is not NAT - refusing" >&2; exit 1; }
echo "  rendered $RUN/network.xml"
sed 's/^/    /' "$RUN/network.xml"

if virsh net-info "$NET" >/dev/null 2>&1; then
  echo "  $NET is already defined"
else
  virsh net-define "$RUN/network.xml" >/dev/null
  virsh net-autostart "$NET" >/dev/null
  echo "  defined and set to autostart"
fi
virsh net-start "$NET" >/dev/null 2>&1 || true
virsh net-info "$NET" | sed 's/^/    /'

echo
if [ "$STAGE2" = "1" ]; then
echo "=== the job bridges, with no address on this host"
for pair in "$TNET $TBRIDGE" "$ANET $ABRIDGE"; do
  set -- $pair
  "$BROKER_PY" - "$1" "$2" > "$RUN/$1.xml" <<'PYX'
import sys
sys.path.insert(0, "/opt/xentry")
from broker.libvirt_ops import network_xml

name, bridge = sys.argv[1:3]
# gateway="" -> no <ip> element at all: no address for this host, no dnsmasq,
# no route. The proxy VM is the only thing on the bridge besides the guest.
sys.stdout.write(
    network_xml(name=name, bridge=bridge, target_mac="", target_ip="",
                gateway="")
)
PYX
  if grep -q "<ip " "$RUN/$1.xml"; then
    echo "  $1 was rendered WITH a host address - refusing" >&2
    exit 1
  fi
  # A network defined by an EARLIER version keeps that version's XML, and
  # "already defined" hid the difference. The kernel reported
  # forward_delay=200 on both bridges although network_xml renders
  # delay='0' - two seconds of LISTENING plus two of LEARNING before a new
  # port forwards, which silently eats whatever a guest says while booting.
  if virsh net-info "$1" >/dev/null 2>&1; then
    if [ "$(virsh net-dumpxml "$1" | grep -c "delay='0'" || true)" -gt 0 ]; then
      echo "  $1 already defined, with delay='0'"
    else
      echo "  $1 is defined from an older XML (no delay='0') - redefining"
      virsh net-destroy "$1" >/dev/null 2>&1 || true
      virsh net-undefine "$1" >/dev/null 2>&1 || true
      virsh net-define "$RUN/$1.xml" >/dev/null
      virsh net-autostart "$1" >/dev/null
      echo "    redefined"
    fi
  else
    virsh net-define "$RUN/$1.xml" >/dev/null
    virsh net-autostart "$1" >/dev/null
    echo "  $1 defined ($2), no host address"
  fi
  virsh net-start "$1" >/dev/null 2>&1 || true
  # And set it on the live bridge too, so this takes effect without waiting
  # for the next redefinition.
  ip link set "$2" type bridge forward_delay 0 2>/dev/null || true
  fd=$(cat "/sys/class/net/$2/bridge/forward_delay" 2>/dev/null || echo "?")
  echo "    $2 forward_delay=$fd (0 means a new port forwards at once)"
done
for b in "$TBRIDGE" "$ABRIDGE"; do
  addr=$(ip -4 -o addr show "$b" 2>/dev/null | awk '{print $4}')
  if [ -n "$addr" ]; then
    echo "  $b HAS an address on this host ($addr) - stage 2 is not met" >&2
    exit 1
  fi
  echo "  $b: no address on this host"
done
fi

echo
echo "=== the VM's disk"
if [ -f "$RUN/$VM.qcow2" ] && [ "${REBUILD:-0}" != "1" ]; then
  echo "  $RUN/$VM.qcow2 exists, keeping it (and its cache)"
  # Which base it is actually on. A disk built by an earlier run of this
  # script is backed by whatever BASE said then, so changing BASE here
  # does nothing until the disk is rebuilt. Say so rather than imply the
  # current BASE is in use.
  backing=$(qemu-img info "$RUN/$VM.qcow2" 2>/dev/null \
            | sed -n "s/^backing file: //p" | head -1)
  echo "  backed by: ${backing:-(none)}"
  case "$backing" in
    *"$BASE") : ;;
    "") echo "  (no backing file - a full copy)" ;;
    *) echo "  NOTE: that is not $BASE. To rebuild from the pristine"
       echo "        image: sudo REBUILD=1 \$0" ;;
  esac
else
  [ "${REBUILD:-0}" = "1" ] && [ -f "$RUN/$VM.qcow2" ] && {
    echo "  REBUILD=1: discarding the existing disk and its cache"
    virsh destroy "$VM" >/dev/null 2>&1 || true
    rm -f "$RUN/$VM.qcow2"; }
  # Read the backing format with a JSON parser, not a regex.
  #
  # The regex version matched the first "format" in the json, which is
  # the PROTOCOL layer's:
  #
  #    line 10:  "format": "file"      <- the protocol, matched first
  #    line 24:  "format": "qcow2"     <- the image, what was wanted
  #
  # so the overlay was created with backing_fmt=file: qemu then read a
  # qcow2 image as raw bytes and the VM booted garbage. It presented as
  # ssh never coming up, with a disk that looked fine in the listing.
  fmt=$(qemu-img info --output=json "$IMAGES/$BASE" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['format'])" \
        2>/dev/null)
  if [ -z "$fmt" ]; then
    # Plain text names it unambiguously: "file format: qcow2".
    fmt=$(qemu-img info "$IMAGES/$BASE" | sed -n "s/^file format: //p" | head -1)
  fi
  case "$fmt" in
    qcow2|raw) : ;;
    "") echo "  cannot read the format of $BASE" >&2; exit 1 ;;
    *) echo "  $BASE reports format \"$fmt\", which is not an image format." >&2
       echo "  Refusing: this is what produced a VM that booted nothing." >&2
       exit 1 ;;
  esac
  echo "  backing format: $fmt"
  qemu-img create -f qcow2 -F "$fmt" -b "$IMAGES/$BASE" "$RUN/$VM.qcow2" 20G \
    | sed 's/^/    /'

  # And verify the overlay that came out, rather than trusting the create.
  got=$(qemu-img info --output=json "$RUN/$VM.qcow2" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('backing-filename-format',''))" 2>/dev/null)
  if [ "$got" != "$fmt" ]; then
    echo "  the overlay records its backing format as \"$got\", not \"$fmt\"" >&2
    qemu-img info "$RUN/$VM.qcow2" | sed 's/^/    /' >&2
    exit 1
  fi
  qemu-img check "$RUN/$VM.qcow2" >/dev/null 2>&1 \
    || { echo "  qemu-img check refuses the new overlay" >&2; exit 1; }
  echo "  overlay verified: backing format $got, image consistent"
fi

echo
echo "=== cloud-init: static address, public resolver, no path to the host"
# Static, not DHCP, and this is load-bearing: the host drops EVERYTHING
# arriving from this bridge at its input hook, DHCP and DNS included. A VM
# that needed either could not be isolated that cleanly. Packets to the
# internet are addressed THROUGH the gateway and so hit forward, not input,
# which is why routing still works with that drop in place.
# meta-data is NOT optional. The NoCloud datasource looks for it, and
# without it the seed is ignored wholesale - no ssh key, no addresses, no
# cloud-init at all - which presents exactly as "ssh times out" with
# nothing in any log on the host. Its absence was the first bug.
#
# The instance-id changes every run on purpose: cloud-init re-runs its
# first-boot stages when it sees an id it has not seen, so re-running this
# script re-provisions instead of silently doing nothing.
cat > "$RUN/meta-data" <<EOF
instance-id: xentry-mirror-$(date -u +%Y%m%dT%H%M%SZ)
local-hostname: xentry-mirror
EOF

# NO network-config AT ALL, and this is deliberate.
#
# The evidence: libvirt's lease table showed 10.44.0.2 handed to this VM
# with hostname xentry-mirror, so the image's own DHCP works and the
# <host mac=.../> entry in the network pins the address. Then cloud-init
# applied a static block naming the interface mirror0 - a rename - and
# the VM stopped answering ARP at all.
#
# Renaming a NIC to satisfy a config file is a bet on the renderer, and
# Debian's cloud image ships no netplan: version 2 may do nothing and
# version 1 renames. DHCP needs neither. The address is pinned by
# libvirt, which is the mechanism every job VM already uses.
#
# DNS is the one thing DHCP gets wrong here - dnsmasq advertises the host
# as the resolver, and the host drops what this VM sends it - so dhclient
# is told to supersede it, below.
cat > "$RUN/user-data" <<EOF
#cloud-config
hostname: xentry-mirror
preserve_hostname: false
users:
  - name: root
    ssh_authorized_keys:
      - ${PUB}
  - name: xentry-mirror
    system: true
    shell: /usr/sbin/nologin
packages:
  - nftables
  - python3
# true, not false. The pristine cloud image ships no package index, so apt
# could not install nftables and cloud-init moved on - leaving a VM that
# answered ssh and then said "nft: command not found".
#
# This apt is the real internet, not a pinned mirror, and that is correct
# here: this VM is infrastructure, not evidence. Nothing a job is judged on
# comes from it.
package_update: true
write_files:
${APT_SOURCES}  # dhclient must not take the resolver DHCP offers: that is the host, and
  # the host drops everything this VM sends it except DHCP itself.
  # /etc/dhcp/dhclient.conf, NOT dhclient.conf.d - dhclient does not read
  # that directory on Debian, so this line was ignored, dhclient took the
  # resolver DHCP offered (the host), and both firewalls drop traffic to it.
  # DNS then HUNG rather than failed, and apt-get update hung with it.
  - path: /etc/dhcp/dhclient.conf
    append: true
    content: |
      supersede domain-name-servers 1.1.1.1, 9.9.9.9;
  - path: /etc/resolv.conf
    content: |
      nameserver 1.1.1.1
      nameserver 9.9.9.9
  - path: /etc/xentry-mirror/README
    content: |
      job.json is written here by the broker before each job and read fresh on
      every restart of xentry-proxy.service. serve.py refuses to start
      without a pinned snapshot serial.
runcmd:
  - [ mkdir, -p, /opt/xentry-mirror/broker, /var/cache/xentry-mirror, /etc/xentry-mirror ]
  - [ chown, -R, 'xentry-mirror:xentry-mirror', /var/cache/xentry-mirror ]
  - [ systemctl, enable, nftables ]
EOF
genisoimage -quiet -output "$RUN/seed.iso" -volid cidata -joliet -rock \
  "$RUN/user-data" "$RUN/meta-data"
echo "  $RUN/seed.iso"

# The console log must exist and be writable BEFORE the domain starts:
# libvirt opens it as the qemu user, and a missing or root-owned file is
# one more way to fail to start with nothing written down.
: > "$RUN/console.log"
: > "$RUN/serial.log"
chown "$QEMU_OWNER" "$RUN/console.log" "$RUN/serial.log" \
  "$RUN/seed.iso" "$RUN/$VM.qcow2"
chmod 0640 "$RUN/console.log" "$RUN/serial.log"
echo "  disk, seed and console log handed to $QEMU_OWNER"

echo
NICS=""
[ "$STAGE2" = "1" ] && NICS="$TNET,$TMAC $ANET,$AMAC"
echo "=== the domain"
"$BROKER_PY" - "$VM" "$MEM_MB" "$VCPU" "$RUN/$VM.qcow2" \
  "$RUN/seed.iso" "$NET" "$MAC" $NICS > "$RUN/domain.xml" <<'PYX'
import sys
from pathlib import Path
sys.path.insert(0, "/opt/xentry")
from broker.libvirt_ops import domain_xml

name, mem, vcpu, disk, seed, net, mac = sys.argv[1:8]
# network,mac pairs for the job bridges. Empty with STAGE2=0.
extra = tuple(tuple(a.split(",", 1)) for a in sys.argv[8:] if "," in a)
sys.stdout.write(
    domain_xml(
        name=name, memory_mb=int(mem), vcpu=int(vcpu),
        disk_path=Path(disk), seed_path=Path(seed),
        network_name=net, mac=mac,
        extra_nics=extra,
        # BOTH paths. libvirt_ops only honours serial_log_path inside the
        # `elif serial_path:` branch - with the log path alone it falls
        # through to a pty, which is why console.log stayed 0 bytes while
        # qemu reported 'char device redirected to /dev/pts/8'. runtime.py
        # passes both for every job VM; this did not.
        serial_path=Path("/var/lib/xentry/mirror-vm/serial.log"),
        serial_log_path=Path("/var/lib/xentry/mirror-vm/console.log"),
    )
)
PYX
echo "  rendered $RUN/domain.xml"
# Always redefine. A domain from an earlier run carries the OLD seed iso
# and no console log, and "already defined" quietly kept it - so fixing
# this script would change nothing until the domain was removed by hand.
if virsh dominfo "$VM" >/dev/null 2>&1; then
  virsh destroy "$VM" >/dev/null 2>&1 || true
  virsh undefine "$VM" >/dev/null 2>&1 || true
  echo "  removed the previous definition"
fi
virsh define "$RUN/domain.xml" >/dev/null
echo "  defined"
# NOT `|| echo (already running)`. That reported success for every
# possible failure - a permission error, a missing disk, an AppArmor
# denial - and then waited five minutes for ssh to a domain that was
# never running. The state is checked, and libvirt's own log is printed.
state=$(virsh domstate "$VM" 2>/dev/null || echo unknown)
if [ "$state" = "running" ]; then
  echo "  already running"
else
  if out=$(virsh start "$VM" 2>&1); then
    echo "$out" | sed 's/^/    /'
  else
    echo "  virsh start FAILED:" >&2
    echo "$out" | sed 's/^/    /' >&2
    log=/var/log/libvirt/qemu/$VM.log
    if [ -f "$log" ]; then
      echo "  --- last 30 lines of $log" >&2
      tail -30 "$log" | sed 's/^/    /' >&2
    fi
    echo "  --- what the files look like" >&2
    ls -la "$RUN" | sed 's/^/    /' >&2
    echo "  --- apparmor denials in the last two minutes" >&2
    journalctl -k --since "-2 min" 2>/dev/null | grep -i apparmor \
      | tail -10 | sed 's/^/    /' >&2 || echo "    (none)" >&2
    exit 1
  fi
  state=$(virsh domstate "$VM" 2>/dev/null || echo unknown)
  [ "$state" = "running" ] || {
    echo "  the domain is $state after a start that reported no error" >&2
    exit 1; }
  echo "  running"
fi

echo
echo "=== waiting for ssh on $PROXY_IP"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 -o LogLevel=ERROR root@$PROXY_IP"
up=
for i in $(seq 1 60); do
  if $SSH true 2>/dev/null; then up=1; break; fi
  sleep 5
  [ $((i % 6)) -eq 0 ] && echo "    still waiting ($((i * 5))s)"
done
[ -n "$up" ] || {
  echo >&2
  echo "  no ssh after 5 minutes. The console says:" >&2
  if [ -f "$RUN/console.log" ]; then
    echo "  --- last 40 lines of $RUN/console.log" >&2
    tail -40 "$RUN/console.log" | sed 's/^/    /' >&2
    echo "  --- cloud-init and network lines" >&2
    grep -iE "cloud-init|datasource|nocloud|mirror0|eth0" "$RUN/console.log" \
      | tail -25 | sed 's/^/    /' >&2
  else
    echo "  (no console log yet - re-run, the domain is redefined each time)" >&2
  fi
  echo >&2
  echo "  Then:  sudo $SRC/scripts/proxy-vm-doctor.sh" >&2
  exit 1; }
echo "  reachable"

echo
echo "=== waiting for cloud-init to finish"
# ssh answers before cloud-init has run its package installs, so copying
# files in at the first open port raced the provisioning that creates the
# directories and installs nftables. "nft: command not found" was that
# race, not a missing package list.
if $SSH "command -v cloud-init >/dev/null" 2>/dev/null; then
  $SSH "cloud-init status --wait" 2>&1 | tail -3 | sed 's/^/    /' || true
  status=$($SSH "cloud-init status" 2>/dev/null | head -1)
  echo "  $status"
  case "$status" in
    *done*) : ;;
    *error*)
      echo "  cloud-init reports an error. What it logged:" >&2
      $SSH "tail -40 /var/log/cloud-init-output.log" 2>&1 | sed 's/^/    /' >&2
      ;;
    *) echo "  (cloud-init did not report done; continuing and checking by hand)" ;;
  esac
else
  echo "  no cloud-init in this image; checking the tools directly"
fi

echo
echo "=== the VM's resolver, taken out of systemd-resolved's hands"
# THE LAST VERSION OF THIS WROTE INTO A SYMLINK AND WAS OVERWRITTEN.
#
# On an Ubuntu base /etc/resolv.conf is a symlink into /run/systemd/resolve/,
# so `printf > /etc/resolv.conf` wrote through it into resolved's own stub
# file. resolved put 127.0.0.53 back, and took its real upstream per-link
# from DHCP on the wan NIC - which libvirt answers with 10.44.0.1, the host,
# the single address this VM's egress filter exists to drop.
#
# So the mirrors resolved nothing and provision failed with
#   [Errno -3] Temporary failure in name resolution
# while every check in this script still passed.
#
# Replace the symlink with a REAL file and put dnsmasq first: it runs here, it
# has explicit public upstreams, and it is the resolver the guests already
# use. 1.1.1.1 and 9.9.9.9 follow it, so a dnsmasq that is not up yet refuses
# instantly and glibc moves on instead of hanging.
$SSH "grep -q 'supersede domain-name-servers' /etc/dhcp/dhclient.conf 2>/dev/null \
  || echo 'supersede domain-name-servers 1.1.1.1, 9.9.9.9;' >> /etc/dhcp/dhclient.conf"
$SSH "rm -f /etc/resolv.conf && printf '%s\n%s\n%s\n' \
  'nameserver 127.0.0.1' 'nameserver 1.1.1.1' 'nameserver 9.9.9.9' \
  > /etc/resolv.conf && chmod 644 /etc/resolv.conf"
$SSH "systemctl disable --now systemd-resolved >/dev/null 2>&1 || true"
echo "  resolv.conf is a real file now:"
timeout 15 $SSH "ls -l /etc/resolv.conf; cat /etc/resolv.conf" 2>&1 | sed 's/^/    /'
if timeout 20 $SSH "getent hosts deb.debian.org" 2>/dev/null | sed 's/^/  /'; then
  echo "  resolution works"
else
  echo "  the VM cannot resolve deb.debian.org. What it is using:" >&2
  timeout 15 $SSH "cat /etc/resolv.conf; ip route" 2>&1 | sed 's/^/    /' >&2
  exit 1
fi

echo
echo "=== the tools the VM needs, installed or installed now"
# Checked rather than assumed: cloud-init can finish green with a failed
# package install, and the next thing to touch nft would be the operator.
# dnsmasq IS IN THIS LIST, and that is the fix for a real failure.
#
# It used to be installed 70 lines further down, AFTER the config files were
# copied - so on a VM without it, the scp of
#
#   dnsmasq-jobs.conf -> /etc/dnsmasq.d/xentry-jobs.conf
#
# failed with "No such file or directory" (the DIRECTORY, not the file),
# set -e killed the script mid-copy, and the VM was left half-provisioned:
# some files in, phase.sh never made executable, job-nics.sh never run. The
# next job then failed with
#
#   /opt/xentry-mirror/phase.sh: No such file or directory
#
# which is a true statement about a symptom four steps downstream.
#
# Installing it before anything is copied removes the whole class.
for tool in python3 nft dnsmasq; do
  if $SSH "command -v $tool >/dev/null"; then
    echo "  $tool: present"
    continue
  fi
  echo "  $tool: MISSING - installing it"
  pkg="$tool"; [ "$tool" = nft ] && pkg=nftables
  # timeout, and apt's own: a dropped packet makes apt wait, not fail, and
  # a script with no bound on that just stops.
  # The lists are cleared first and -qq is NOT used for the update: with it,
  # apt-get returns 0 even when one source fails to refresh, so a stale
  # security.debian.org index stayed in place and the install 404'd on
  # versions Debian had already removed.
  if ! timeout 420 $SSH "rm -rf /var/lib/apt/lists/* && \
             DEBIAN_FRONTEND=noninteractive apt-get update \
             -o Acquire::http::Timeout=20 -o Acquire::Retries=2 2>&1 \
             | grep -E '^(Err|E:)' && exit 1 || \
             DEBIAN_FRONTEND=noninteractive apt-get -y -qq \
             -o Acquire::http::Timeout=20 install $pkg" \
       2>&1 | tail -5 | sed 's/^/    /'; then
    echo "  apt-get failed inside the VM. It reaches the internet through" >&2
    echo "  the host NAT, so check that first:" >&2
    $SSH "ip -br addr; ip route; getent hosts deb.debian.org" 2>&1 | sed 's/^/    /' >&2
    exit 1
  fi
  $SSH "command -v $tool >/dev/null" || {
    echo "  $pkg installed but $tool is still not on PATH" >&2; exit 1; }
  echo "  $tool: installed"
done

# The unit runs as this user. cloud-init creates it, but cloud-init can
# be raced or can fail a stage and still finish, so it is checked here -
# the alternative is a chown that fails with nothing but a uid.
if $SSH "id xentry-mirror >/dev/null 2>&1"; then
  echo "  user xentry-mirror: present"
else
  $SSH "useradd --system --shell /usr/sbin/nologin xentry-mirror" \
    || { echo "  cannot create the xentry-mirror user" >&2; exit 1; }
  echo "  user xentry-mirror: created"
fi

echo
echo "=== copying the mirrors in"
# /etc/dnsmasq.d too: the package creates it, but a missing directory is
# what aborted this script once already, and mkdir -p costs nothing.
$SSH "mkdir -p /opt/xentry-mirror/broker /etc/xentry-mirror \
      /var/cache/xentry-mirror /etc/dnsmasq.d"
SCP="scp -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR"
for f in aptproxy ociproxy registryproxy; do
  $SCP "$SRC/broker/$f.py" "root@$PROXY_IP:/opt/xentry-mirror/broker/$f.py"
  echo "  broker/$f.py"
done
$SSH "touch /opt/xentry-mirror/broker/__init__.py"
$SCP "$SRC/deploy/proxy-vm/serve.py" "root@$PROXY_IP:/opt/xentry-mirror/serve.py"
$SCP "$SRC/deploy/proxy-vm/isolation-probe.sh" "root@$PROXY_IP:/opt/xentry-mirror/"
$SCP "$SRC/deploy/proxy-vm/firewall.nft" "root@$PROXY_IP:/etc/nftables.conf"
if [ "$STAGE2" = "1" ]; then
  $SCP "$SRC/deploy/proxy-vm/job-nics.sh" "$SRC/deploy/proxy-vm/phase.sh" \
    "root@$PROXY_IP:/opt/xentry-mirror/"
  $SCP "$SRC/deploy/proxy-vm/dnsmasq-jobs.conf" \
    "root@$PROXY_IP:/etc/dnsmasq.d/xentry-jobs.conf"
  $SCP "$SRC/deploy/proxy-vm/xentry-job-nics.service" \
    "root@$PROXY_IP:/etc/systemd/system/xentry-job-nics.service"
  echo "  job-nics.sh, phase.sh, dnsmasq config, the unit"
fi
$SCP "$SRC/deploy/proxy-vm/xentry-proxy.service" \
  "root@$PROXY_IP:/etc/systemd/system/xentry-proxy.service"
echo "  serve.py, the probe, the egress filter, the unit"

echo
echo "=== loading the egress filter and installing the unit"
# One step at a time, so a rejected ruleset is reported as a rejected
# ruleset rather than as whichever command in a long && chain exited.
$SSH "chmod +x /opt/xentry-mirror/isolation-probe.sh" \
  || { echo "  cannot mark the probe executable" >&2; exit 1; }
$SSH "chown -R xentry-mirror:xentry-mirror /var/cache/xentry-mirror" \
  || { echo "  cannot hand the cache to xentry-mirror" >&2; exit 1; }

# A DEAD-MAN SWITCH, BECAUSE THIS STEP HUNG ONCE AND WILL AGAIN.
#
# Loading nftables is what loads nf_conntrack, so the ssh session doing
# the loading is not in the conntrack table and a ruleset that admits ssh
# only by state drops it - silently, since a drop is not a refusal. The
# ruleset now admits tcp/22 unconditionally, but ANY future mistake in
# that file has the same shape, and the VM is then unreachable until
# someone finds virsh console.
#
# So: arm a flush 90 seconds out, load, prove we can still get in, then
# cancel it. Lock yourself out and the VM lets you back in by itself.
echo "  arming a 90s rollback inside the VM"
$SSH "setsid sh -c 'sleep 90; nft flush ruleset' </dev/null \
      >/dev/null 2>&1 & echo armed" >/dev/null 2>&1 || true

if ! out=$(timeout 30 $SSH "nft -f /etc/nftables.conf" 2>&1); then
  echo "  nft did not accept the ruleset (or the load hung):" >&2
  echo "$out" | sed 's/^/    /' >&2
  echo "  the file it was given:" >&2
  timeout 20 $SSH "cat -n /etc/nftables.conf" 2>&1 | tail -40 | sed 's/^/    /' >&2
  echo "  the VM will flush its ruleset within 90 seconds." >&2
  exit 1
fi

# The load returned. That is not the same as still being reachable.
if timeout 20 $SSH "nft list table inet xentry_mirror >/dev/null" 2>/dev/null; then
  $SSH "pkill -f 'nft flush ruleset' >/dev/null 2>&1; true" >/dev/null 2>&1 || true
  echo "  loaded, still reachable, rollback cancelled"
else
  echo "  the ruleset loaded and then locked us out." >&2
  echo "  Do nothing for 90 seconds: the VM flushes it and ssh returns." >&2
  echo "  Then read $SRC/deploy/proxy-vm/firewall.nft before retrying." >&2
  exit 1
fi
$SSH "systemctl enable nftables >/dev/null 2>&1; systemctl daemon-reload"

if [ "$STAGE2" = "1" ]; then
  echo
  echo "=== the VM routes the job bridges and serves DHCP on them"
  # dnsmasq is the one package stage 2 adds. Checked rather than assumed,
  # as python3 and nft are: cloud-init can finish green with a failed
  # install, and the next thing to notice would be a guest with no lease.
  if ! $SSH "command -v dnsmasq >/dev/null"; then
    echo "  dnsmasq: installing"
    $SSH "DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
          DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsmasq" \
      2>&1 | tail -4 | sed 's/^/    /' || { echo "  apt-get failed in the VM" >&2; exit 1; }
  fi
  $SSH "command -v dnsmasq >/dev/null" \
    || { echo "  dnsmasq is still not installed" >&2; exit 1; }
  echo "  dnsmasq: present"
  $SSH "chmod +x /opt/xentry-mirror/job-nics.sh /opt/xentry-mirror/phase.sh"
  $SSH "systemctl daemon-reload && systemctl enable xentry-job-nics >/dev/null 2>&1"
  if ! out=$(timeout 60 $SSH "/opt/xentry-mirror/job-nics.sh" 2>&1); then
    echo "  the VM could not address its job bridges:" >&2
    echo "$out" | sed 's/^/    /' >&2
    echo "  its interfaces:" >&2
    $SSH "ip -br addr; ip -o link" 2>&1 | sed 's/^/    /' >&2
    exit 1
  fi
  echo "$out" | sed 's/^/    /'

  # Start in the provisioning phase, which is the state a job begins in.
  echo "  loading the provisioning phase"
  $SSH "install -D -m 0644 /dev/stdin /etc/xentry-mirror/phase.json" <<JSON
{"phase": "provisioning", "proxy_ports": [80, 8082, 8083, 8084, 8086]}
JSON
  if ! out=$(timeout 60 $SSH "/opt/xentry-mirror/phase.sh" 2>&1); then
    echo "  the phase rules did not load:" >&2
    echo "$out" | sed 's/^/    /' >&2
    exit 1
  fi
  echo "$out" | head -4 | sed 's/^/    /'
fi
# NOT enabled: with no job.json, serve.py refuses by design, and an enabled
# unit would restart-loop against that refusal. The broker starts it per job.
echo "  loaded; xentry-proxy.service installed but not enabled"
$SSH "nft list table inet xentry_mirror | head -20" | sed 's/^/    /'

echo
echo "=== resolution STILL works, now that dnsmasq owns 127.0.0.1:53"
# The old check ran before dnsmasq was installed, so it could never see a
# break that installing dnsmasq caused. This one runs after it.
for host in deb.debian.org snapshot.debian.org; do
  if timeout 20 $SSH "getent hosts $host" >/dev/null 2>&1; then
    echo "  ok  $host"
  else
    echo "  $host does NOT resolve - the mirrors fail with EAI_AGAIN" >&2
    timeout 20 $SSH "cat /etc/resolv.conf; ss -ulnp | grep ':53 '; \
      systemctl is-active dnsmasq" 2>&1 | sed 's/^/    /' >&2
    exit 1
  fi
done

echo "=== the host's PERMANENT rules for this bridge"
# The per-job table is applied in create_network and cleared in cleanup,
# so between jobs it does not exist - and the rule that stops this VM
# reaching the host was in it. The VM is persistent and has internet
# access, so for most of its life nothing stood between it and port 8000.
#
# A separate, permanent table fixes that. A job's table comes and goes
# underneath it, and a drop in either kills the packet.
install -D -o root -g root -m 644 "$SRC/deploy/proxy-vm/host-wan.nft" \
  /etc/xentry/host-wan.nft
install -D -o root -g root -m 644 \
  "$SRC/deploy/proxy-vm/xentry-wan-firewall.service" \
  /etc/systemd/system/xentry-wan-firewall.service
if ! out=$(nft -f /etc/xentry/host-wan.nft 2>&1); then
  echo "  the host rejected its own permanent ruleset:" >&2
  echo "$out" | sed 's/^/    /' >&2
  cat -n /etc/xentry/host-wan.nft | sed 's/^/    /' >&2
  exit 1
fi
systemctl daemon-reload
systemctl enable --now xentry-wan-firewall.service >/dev/null 2>&1 || true
echo "  table inet xentry_wan loaded, and enabled at boot:"
nft list table inet xentry_wan | sed 's/^/    /'

# ROUTES to the job subnets, through the VM. Without these the broker cannot
# ssh into a guest at all: the host has no address on those bridges, so
# 10.43.1.10 resolves via the default gateway and the connection leaves for
# the internet. create_target then waits for an ssh that can never arrive.
for subnet in 10.43.1.0/24 10.43.2.0/24; do
  ip route replace "$subnet" via "$PROXY_IP"
  echo "  route: $subnet via $PROXY_IP"
done
# The VM's own job-side addresses prove the route works before any guest
# exists - if these do not answer, no guest on those bridges will either.
for addr in 10.43.1.1 10.43.2.1; do
  if ping -c1 -W2 "$addr" >/dev/null 2>&1; then
    echo "  ok  $addr answers through the route"
  else
    echo "  $addr does not answer - the broker will not reach a guest" >&2
    ip route get "$addr" | sed 's/^/    /' >&2
    exit 1
  fi
done

# Prove it from the host's side before the probe proves it from the VM's:
# the rules must not have cost us ssh to the VM.
if timeout 10 $SSH true 2>/dev/null; then
  echo "  ssh to the VM still works with the permanent rules loaded"
else
  echo "  the permanent rules broke ssh to the VM. Removing them:" >&2
  nft delete table inet xentry_wan 2>/dev/null || true
  echo "  removed. Read /etc/xentry/host-wan.nft before retrying." >&2
  exit 1
fi

echo
echo "=== THE PROBE. This is what decides whether any of the above worked."
if $SSH "/opt/xentry-mirror/isolation-probe.sh"; then
  echo
  echo "Isolation holds."
else
  echo >&2
  echo "The probe FAILED. The VM is up but not isolated as ADR 0002 claims." >&2
  echo "Do not set the environment variables below until it passes." >&2
  exit 1
fi

echo
echo "================================================================"
echo "The VM is up and isolated. Nothing is cut over yet."
echo
echo "To move the mirrors off the host, add to the BROKER's environment"
echo "(/etc/xentry/broker.env or the unit's EnvironmentFile) and restart it:"
echo
echo "    XENTRY_WAN_BRIDGE=$BRIDGE"
echo "    XENTRY_PROXY_IP=$PROXY_IP"
echo
echo "With those set, provisioning_rules stops opening the host's own ports to"
echo "the guests and opens one crossing to $PROXY_IP instead. With them unset,"
echo "every rule is exactly what it is today."
echo
if [ "$STAGE2" = "1" ]; then
  echo "Stage 2 is in place: $TBRIDGE and $ABRIDGE have no address on this"
  echo "host, the VM routes between them, serves their DHCP, and holds the"
  echo "phase rules. The runtime does NOT use them yet - it still creates a"
  echo "per-job network with a host gateway. That switch is the last step."
  echo
fi
echo "Still missing before a job can use it (next increment): the broker does"
echo "not yet write /etc/xentry-mirror/job.json or restart the unit, so the"
echo "mirrors have no serial and will refuse to serve. Do not cut over until"
echo "that lands."
echo "================================================================"
