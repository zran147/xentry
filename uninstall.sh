#!/usr/bin/env bash
# Take a host back to before install.sh step 1.
#
#   sudo ./uninstall.sh              show what would be destroyed, change nothing
#   sudo ./uninstall.sh --really     destroy it, after a typed confirmation
#   sudo ./uninstall.sh --really --yes --no-backup
#
# DRY RUN IS THE DEFAULT. Without --really this prints the inventory and exits
# 0 having touched nothing, because the list is the part worth reading twice:
# it names things no re-install can bring back.
#
# WHAT CANNOT BE RECOVERED
#
#   /etc/xentry/app.env        your DEEPSEEK_API_KEY and any NVD key
#   /var/lib/xentry/jobs       every job's evidence and hash-chained events
#   /var/lib/xentry/index      the SQLite record of which CVEs reproduced
#   /var/lib/xentry/artifacts  pinned PoCs and packages at their digests
#
# That last one deserves a warning. The artifacts are pinned by digest to URLs
# recorded weeks ago, and an upstream pool can empty out from under you - this
# project has already lost a Debian snapshot that way. If a URL has rotted
# since, a re-install cannot refetch it and that target is gone for good.
# Unless --no-backup, /etc/xentry and the artifact manifest are tarred into
# /root first, which is outside everything this script removes.
#
# WHAT IT DOES NOT TOUCH, DELIBERATELY
#
#   /home/*                    your work trees and clones are yours to delete
#   ~/.local/bin/uv            a user's own uv, which predates this project
#   git, curl, ca-certificates, apparmor, nftables, openssh-client
#
# Those six packages stay whatever apt thinks. You need git to clone the repo
# again and curl to install uv, so removing them would strand the very host
# you are about to rebuild; apparmor and nftables are Ubuntu's own security
# and firewall machinery and this project does not get to decide they go.
# Everything else install.sh installed is offered for removal, and apt makes
# the final call: packages another package still needs are kept, by its
# dependency resolution rather than by a list maintained here.
set -euo pipefail

REALLY=0
ASSUME_YES=0
BACKUP=1
for arg in "$@"; do
  case "$arg" in
    --really) REALLY=1 ;;
    --yes) ASSUME_YES=1 ;;
    --no-backup) BACKUP=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

APP=/opt/xentry
STATE=/var/lib/xentry
ETC=/etc/xentry
UVPY=/opt/uv-python
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

# Installed by install.sh step 1. The six above are not in this list.
PACKAGES="qemu-system-x86 qemu-utils libvirt-daemon-system
          libvirt-daemon-driver-qemu libvirt-clients cloud-image-utils
          genisoimage xorriso apparmor-utils tshark sqlite3"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
act() { if [ "$REALLY" = 1 ]; then eval "$@"; else echo "    would: $*"; fi; }

################################################################################
say "INVENTORY"
################################################################################

echo "  services"
for unit in xentry.service xentry-broker.service; do
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  [ -n "$state" ] && printf '    %-28s %s\n' "$unit" "$state"
done
ls /etc/systemd/system/xentry*.service /etc/systemd/system/xentry*.service.d \
  2>/dev/null | sed 's/^/    /' || true

echo "  virtual machines"
vms=$(virsh -q -c qemu:///system list --all 2>/dev/null | awk '{print $2}' \
      | grep -E '^xentry' || true)
[ -n "$vms" ] && echo "$vms" | sed 's/^/    /' || echo "    none"

echo "  libvirt networks"
nets=$(virsh -q -c qemu:///system net-list --all 2>/dev/null | awk '{print $1}' \
       | grep -E '^xentry' || true)
[ -n "$nets" ] && echo "$nets" | sed 's/^/    /' || echo "    none"

echo "  nftables tables"
for t in xentry xentry_mirror xentry_phase xentry_wan; do
  nft list table inet "$t" >/dev/null 2>&1 && echo "    inet $t"
done

echo "  directories"
for d in "$APP" "$STATE" "$ETC" /run/xentry "$UVPY"; do
  [ -e "$d" ] || continue
  printf '    %-24s %s\n' "$d" "$(du -sh "$d" 2>/dev/null | cut -f1)"
done
# A glob loop, not `ls ... | while`. With no match, ls exits 2, pipefail
# propagates it, and set -e kills the script - which is exactly what happened:
# the inventory stopped after this line and never printed the irreversible
# section, the users, the packages, or the DRY RUN footer. An unexpanded glob
# is handled by the -e test instead.
for d in /opt/xentry-broker.retired.*; do
  [ -e "$d" ] || continue
  printf '    %-24s %s\n' "$d" "$(du -sh "$d" 2>/dev/null | cut -f1)"
done

echo "  the irreversible part"
for d in "$STATE/jobs" "$STATE/index" "$STATE/artifacts" "$STATE/evidence"; do
  [ -e "$d" ] || continue
  printf '    %-24s %s in %s entries\n' "$d" \
    "$(du -sh "$d" 2>/dev/null | cut -f1)" \
    "$(find "$d" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
done
# Name the keys without reading the file: the variable names are public, the
# values are not, and this script never prints them.
if [ -f "$ETC/app.env" ]; then
  # Only keys that actually HOLD something. Listing an empty XENTRY_POC_API_KEY
  # as a thing to copy sends you looking for a value that was never set. The
  # names are printed, never the values - the pattern requires at least one
  # character after the = and then prints only the part before it.
  set_keys=$(grep -oE '^(DEEPSEEK_API_KEY|XENTRY_NVD_API_KEY|XENTRY_POC_API_KEY)=.+' \
    "$ETC/app.env" 2>/dev/null | cut -d= -f1 || true)
  if [ -n "$set_keys" ]; then
    echo "    $ETC/app.env - these hold a value you cannot regenerate:"
    printf '%s\n' "$set_keys" | sed 's/^/      /'
    echo "      (values not shown. Copy them out before --really:)"
    echo "      sudo grep -E '^($(printf '%s' "$set_keys" | paste -sd'|' -))=' \\"
    echo "        $ETC/app.env"
  else
    echo "    $ETC/app.env holds no API keys with values set"
  fi
fi

echo "  users, groups, and sudoers"
for u in xentry xentry-vm; do
  id -u "$u" >/dev/null 2>&1 && echo "    user $u"
done
for g in xentry xentry-vm xentry-dev; do
  getent group "$g" >/dev/null 2>&1 && echo "    group $g ($(getent group "$g" | cut -d: -f4))"
done
ls /etc/sudoers.d/xentry* 2>/dev/null | sed 's/^/    /' || true
[ -e /usr/local/sbin/xentry-read ] && echo "    /usr/local/sbin/xentry-read" || true
[ -e /etc/apparmor.d/local/abstractions/libvirt-qemu ] &&
  echo "    /etc/apparmor.d/local/abstractions/libvirt-qemu" || true

echo "  packages offered to apt for removal (it decides)"
printf '    %s\n' $PACKAGES | paste -sd' ' - | fold -s -w 72 | sed 's/^/    /'

if [ "$REALLY" != 1 ]; then
  cat <<'EOF'

  DRY RUN. Nothing was changed.

  Copy your keys out first, then:
    sudo ./uninstall.sh --really
EOF
  exit 0
fi

################################################################################
say "CONFIRM"
################################################################################

if [ "$ASSUME_YES" != 1 ]; then
  echo "  This destroys the job evidence, the index, the pinned artifacts and"
  echo "  the secrets listed above. Type DESTROY to continue."
  printf '  > '
  read -r answer
  [ "$answer" = "DESTROY" ] || { echo "  aborted; nothing changed"; exit 1; }
fi

if [ "$BACKUP" = 1 ] && [ -d "$ETC" ]; then
  tarball="/root/xentry-secrets-$STAMP.tar.gz"
  tar czf "$tarball" -C / etc/xentry \
    $([ -f "$STATE/artifacts/manifest.json" ] && echo "var/lib/xentry/artifacts/manifest.json") \
    2>/dev/null || true
  chmod 600 "$tarball"
  say "BACKUP"
  echo "  $tarball  ($(du -h "$tarball" | cut -f1), mode 600)"
  echo "  Holds your env files. Outside everything removed below."
fi

################################################################################
say "STOPPING SERVICES"
################################################################################
for unit in xentry.service xentry-broker.service; do
  systemctl is-enabled "$unit" >/dev/null 2>&1 && act "systemctl disable $unit" || true
  systemctl is-active "$unit" >/dev/null 2>&1 && act "systemctl stop $unit" || true
done

################################################################################
say "VMS AND NETWORKS"
################################################################################
for vm in $vms; do
  act "virsh -c qemu:///system destroy '$vm' >/dev/null 2>&1 || true"
  # Undefine the NVRAM too, or a UEFI domain leaves a varstore behind.
  act "virsh -c qemu:///system undefine '$vm' --nvram --remove-all-storage >/dev/null 2>&1 \
       || virsh -c qemu:///system undefine '$vm' >/dev/null 2>&1 || true"
  echo "    $vm"
done
for net in $nets; do
  act "virsh -c qemu:///system net-destroy '$net' >/dev/null 2>&1 || true"
  act "virsh -c qemu:///system net-undefine '$net' >/dev/null 2>&1 || true"
  echo "    $net"
done
for t in xentry xentry_mirror xentry_phase xentry_wan; do
  nft list table inet "$t" >/dev/null 2>&1 && { act "nft delete table inet $t"; echo "    inet $t"; }
done

# Routes the mirror VM's bring-up added to the host.
for cidr in 10.43.1.0/24 10.43.2.0/24; do
  route=$(ip route show "$cidr" 2>/dev/null || true)
  [ -n "$route" ] && act "ip route del '$cidr' || true" || true
done

################################################################################
say "LIBVIRT CONFIGURATION"
################################################################################
if [ -f /etc/libvirt/qemu.conf.orig ]; then
  act "cp -a /etc/libvirt/qemu.conf.orig /etc/libvirt/qemu.conf"
  act "systemctl restart libvirtd || true"
  echo "    qemu.conf restored from .orig"
else
  echo "    no /etc/libvirt/qemu.conf.orig; qemu.conf left as it is"
  echo "    (user/group/security_driver may still name xentry-vm)"
fi

if [ -f /etc/apparmor.d/local/abstractions/libvirt-qemu ]; then
  act "rm -f /etc/apparmor.d/local/abstractions/libvirt-qemu"
  act "apparmor_parser -r /etc/apparmor.d/abstractions/libvirt-qemu 2>/dev/null || true"
  echo "    AppArmor drop-in removed"
fi

################################################################################
say "UNITS, FILES, AND STATE"
################################################################################
for f in /etc/systemd/system/xentry*.service; do
  [ -e "$f" ] || continue
  act "rm -f '$f'"; echo "    $f"
done
for d in /etc/systemd/system/xentry*.service.d; do
  [ -e "$d" ] || continue
  act "rm -rf '$d'"; echo "    $d"
done
act "systemctl daemon-reload"

for f in /etc/sudoers.d/xentry-read /etc/sudoers.d/xentry-dev \
         /usr/local/sbin/xentry-read; do
  [ -e "$f" ] || continue
  act "rm -f '$f'"; echo "    $f"
done

for d in "$APP" "$STATE" "$ETC" /run/xentry "$UVPY"; do
  [ -e "$d" ] || continue
  act "rm -rf '$d'"; echo "    $d"
done
for d in /opt/xentry-broker.retired.*; do
  [ -e "$d" ] || continue
  act "rm -rf '$d'"; echo "    $d"
done

# Root's uv, from step 3. A user's own ~/.local/bin/uv is left alone.
for f in /root/.local/bin/uv /root/.local/bin/uvx /usr/local/bin/uv; do
  [ -e "$f" ] || continue
  act "rm -f '$f'"; echo "    $f"
done

################################################################################
say "USERS AND GROUPS"
################################################################################
for u in xentry xentry-vm; do
  id -u "$u" >/dev/null 2>&1 || continue
  act "userdel '$u' 2>/dev/null || true"; echo "    user $u"
done
for g in xentry xentry-vm xentry-dev; do
  getent group "$g" >/dev/null 2>&1 || continue
  act "groupdel '$g' 2>/dev/null || true"; echo "    group $g"
done

################################################################################
say "PACKAGES"
################################################################################
# Mark them auto and let apt's own resolution decide. Anything another package
# needs stays - that judgement is not duplicated in a list here.
installed=""
for p in $PACKAGES; do
  # Same SIGPIPE trap as above, and here it would silently SKIP a package
  # rather than fail loudly, because of the || true.
  status=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true)
  [[ $status == *"install ok installed"* ]] && installed="$installed $p" || true
done
if [ -z "$installed" ]; then
  echo "    none of them are installed"
elif [ "$REALLY" != 1 ]; then
  echo "  installed, and would be marked auto:"
  printf '    %s\n' $installed
  echo "  apt then decides which of them nothing else needs. The simulation is"
  echo "  only meaningful after that mark, so it runs under --really."
else
  # The preview only means anything AFTER the mark, and the mark is a write.
  # Running the simulation in a dry run would list whatever is already auto and
  # removable on this host - unrelated packages, presented as if this script
  # had chosen them.
  act "apt-mark auto$installed >/dev/null"
  echo "  apt would remove:"
  env DEBIAN_FRONTEND=noninteractive apt-get -s autoremove 2>/dev/null \
    | grep -E '^Remv' | awk '{print "    " $2}' || echo "    (nothing)"
  if [ "$ASSUME_YES" != 1 ]; then
    echo "  Remove these? [y/N]"
    printf '  > '
    read -r answer
    case "$answer" in [yY]*) ;; *) echo "    packages kept"; answer=no ;; esac
  else
    answer=y
  fi
  case "$answer" in
    [yY]*) act "env DEBIAN_FRONTEND=noninteractive apt-get -y autoremove" ;;
  esac
fi

################################################################################
say "WHAT IS LEFT"
################################################################################
for d in "$APP" "$STATE" "$ETC" "$UVPY"; do
  [ -e "$d" ] && echo "    STILL THERE: $d" || true
done
echo "    your trees under /home are untouched, as intended"
[ "$BACKUP" = 1 ] && [ -f "/root/xentry-secrets-$STAMP.tar.gz" ] &&
  echo "    secrets backup: /root/xentry-secrets-$STAMP.tar.gz"
echo
echo "  To install again:"
echo "    sudo git clone https://github.com/zran147/xentry /opt/xentry"
echo "    sudo /opt/xentry/install.sh"
