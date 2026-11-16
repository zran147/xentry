#!/usr/bin/env bash
# Install the xentry AppArmor deny drop-in for libvirt's per-domain QEMU
# profiles.
#
# QEMU confinement comes from libvirt's AppArmor security driver: with
# security_driver = "apparmor" in /etc/libvirt/qemu.conf, libvirtd runs
# virt-aa-helper and switches each domain's QEMU into a generated
# libvirt-<uuid> profile built from that domain's own XML. A profile attached
# to /usr/bin/qemu-system-x86_64 is never entered in that configuration, so
# there is no static emulator profile to load. This script installs deny rules
# that the distro abstraction pulls into every generated domain profile.
set -euo pipefail

source_file="${1:-$(dirname "$0")/../deploy/apparmor/local-libvirt-qemu}"
target=/etc/apparmor.d/local/abstractions/libvirt-qemu
abstraction=/etc/apparmor.d/abstractions/libvirt-qemu
local_include='include if exists <local/abstractions/libvirt-qemu>'

if [[ $EUID -ne 0 ]]; then
  echo "install-apparmor: run as root" >&2
  exit 2
fi
if [[ ! -f "$source_file" ]]; then
  echo "install-apparmor: missing drop-in: $source_file" >&2
  exit 2
fi
if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "install-apparmor: apparmor_parser is not installed" >&2
  exit 2
fi
if [[ ! -f "$abstraction" ]]; then
  echo "install-apparmor: missing $abstraction (is libvirt-daemon installed?)" >&2
  exit 2
fi
if ! grep -qF "$local_include" "$abstraction"; then
  echo "install-apparmor: $abstraction does not pull in the local drop-in" >&2
  echo "install-apparmor: expected: $local_include" >&2
  exit 3
fi

# Syntax-check the drop-in in a throwaway profile before installing it, so a
# bad rule cannot break every VM on the host.
check=$(mktemp)
trap 'rm -f "$check"' EXIT
cat > "$check" <<PROFILE
abi <abi/4.0>,
include <tunables/global>
profile xentry-dropin-syntax-check /usr/bin/qemu-system-x86_64 flags=(attach_disconnected) {
  include <abstractions/base>
  include "$(readlink -f "$source_file")"
}
PROFILE
if ! apparmor_parser -QT "$check" >/dev/null; then
  echo "install-apparmor: drop-in failed to parse; nothing installed" >&2
  exit 4
fi

install -d -m 0755 "$(dirname "$target")"
install -m 0644 -o root -g root "$source_file" "$target"

# Reparse the profiles that include the abstraction.
systemctl reload apparmor

echo "install-apparmor: installed $target"
echo "install-apparmor: running domains keep their current profile; the rules"
echo "install-apparmor: apply to domains started from now on."
