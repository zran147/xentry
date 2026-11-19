#!/usr/bin/env bash
# Give the mirror VM its two job-side addresses and serve those bridges.
# Runs inside the VM, at boot, from xentry-job-nics.service.
#
# ADR 0002 stage 2: the target and the attacker sit on bridges this host has
# NO address on, so their only neighbour is this VM. That makes this VM their
# router, their DHCP server and their DNS - jobs that worked with libvirt's
# dnsmasq keep working, they just get their lease from here instead.
#
# MATCHED BY MAC, NEVER BY NAME. Interface names depend on PCI slots; a config
# naming enp1s0 configured nothing when the slot moved, and a cloud-init
# rename left the VM answering nothing at all. The MACs below are set by
# scripts/proxy-vm-up.sh, so they are the one thing that cannot be wrong.
set -euo pipefail

TARGET_MAC=52:54:00:4d:49:54
ATTACKER_MAC=52:54:00:4d:49:41
TARGET_ADDR=10.43.1.1/24
ATTACKER_ADDR=10.43.2.1/24

dev_for() {  # dev_for <mac>
  ip -o link show | awk -v mac="$1" 'tolower($0) ~ tolower(mac) {
    name = $2; sub(/:$/, "", name); sub(/@.*/, "", name); print name; exit }'
}

configure() {  # configure <mac> <cidr> <label>
  local mac="$1" cidr="$2" label="$3" dev
  dev="$(dev_for "$mac")"
  if [ -z "$dev" ]; then
    echo "no interface has mac $mac - the $label bridge is not attached" >&2
    return 1
  fi
  ip link set "$dev" up
  ip addr replace "$cidr" dev "$dev"
  echo "$label: $dev $cidr"
}

configure "$TARGET_MAC" "$TARGET_ADDR" target
configure "$ATTACKER_MAC" "$ATTACKER_ADDR" attacker

# Routing between the two job bridges is this VM's whole purpose in stage 2:
# the phase rules decide what may cross, and nothing crosses without it.
sysctl -qw net.ipv4.ip_forward=1
echo "ip_forward=1"

# dnsmasq serves both bridges. Restarted rather than started, so re-running
# this script after a config change takes effect.
if systemctl list-unit-files dnsmasq.service >/dev/null 2>&1; then
  systemctl restart dnsmasq
  echo "dnsmasq: $(systemctl is-active dnsmasq)"
else
  echo "dnsmasq is not installed - the guests will get no lease" >&2
  exit 1
fi
