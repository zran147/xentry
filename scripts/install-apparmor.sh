#!/usr/bin/env bash
# Install a tested AppArmor profile for the QEMU process.
#
# The checked-in deploy/apparmor/xentry-vm is a placeholder and is refused.
# Gate B requires a host-specific profile that allows only the job image,
# overlay, ISO, and libvirt socket paths. Run this as root on the deployment
# host after replacing the placeholder.
set -euo pipefail

profile="${1:-$(dirname "$0")/../deploy/apparmor/xentry-vm}"

if [[ $EUID -ne 0 ]]; then
  echo "install-apparmor: run as root" >&2
  exit 2
fi
if [[ ! -f "$profile" ]]; then
  echo "install-apparmor: missing profile: $profile" >&2
  exit 2
fi
if grep -q "Gate B TODO" "$profile"; then
  echo "install-apparmor: refusing the unchecked placeholder profile" >&2
  echo "install-apparmor: replace it with a tested host-specific profile first" >&2
  exit 3
fi
if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "install-apparmor: apparmor_parser is not installed" >&2
  exit 2
fi

apparmor_parser -r "$profile"
echo "install-apparmor: loaded $profile"
