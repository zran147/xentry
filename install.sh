#!/usr/bin/env bash
#
# xentry V1 deployment installer for Ubuntu 26.04 (24.04+ also works).
#
#   sudo ./install.sh
#
# Every command here used to be a numbered section of README.md; this is a
# move, not a redesign. The script announces each step as it starts it, and
# re-running is safe: users, groups, directories and files are created only
# when they are missing.
#
# THE TREE MUST ALREADY BE CLONED. This script configures a host around the
# code at /opt/xentry; it does not fetch it:
#
#   sudo git clone https://github.com/zran147/xentry /opt/xentry
#   sudo nano /etc/xentry/app.env      # after step 7 creates it
#   sudo /opt/xentry/install.sh
#
# Optional, all off by default:
#   XENTRY_BIND_ADDR=10.0.0.5   serve the app on a routable address (step 10)
#   XENTRY_ADMIN_IPS="a b"      addresses allowed to reach that port
#   DEV=1                       developer access to the code tree (step 12)
#
# One tree, two virtualenvs: /opt/xentry/.venv is the app (app + dev groups)
# and /opt/xentry/.venv-broker is the broker (broker group). There is no
# /opt/xentry-broker.

set -euo pipefail

TOTAL=13
STEP=0

step() {
	STEP=$((STEP + 1))
	printf '\n==> step %d/%d  %s\n' "$STEP" "$TOTAL" "$1"
}

note() { printf '      %s\n' "$*"; }

die() {
	printf '\nstep %d/%d failed: %s\n' "$STEP" "$TOTAL" "$*" >&2
	exit 1
}

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh must run as root: sudo $0" >&2
	exit 1
fi

APP=/opt/xentry
UV=/usr/local/bin/uv
UVPY=/opt/uv-python
STATE=/var/lib/xentry
ETC=/etc/xentry

BIND_ADDR="${XENTRY_BIND_ADDR:-}"
ADMIN_IPS="${XENTRY_ADMIN_IPS:-}"
DEV="${DEV:-0}"
DEV_USER="${DEV_USER:-${SUDO_USER:-}}"

# Set key=value in an environment file: rewrite the line if the key is there,
# append it if it is not.
env_set() {
	local file=$1 key=$2 val=$3
	if grep -qE "^[[:space:]]*${key}=" "$file"; then
		sed -i -E "s|^[[:space:]]*${key}=.*|${key}=${val}|" "$file"
	else
		printf '%s=%s\n' "$key" "$val" >>"$file"
	fi
}

# Same, but leave a value the operator has already filled in alone.
env_default() {
	local file=$1 key=$2 val=$3 cur
	cur=$(sed -nE "s|^[[:space:]]*${key}=(.*)$|\1|p" "$file" | tail -n1)
	[ -n "$cur" ] || env_set "$file" "$key" "$val"
}

env_value() {
	sed -nE "s|^[[:space:]]*$2=(.*)$|\1|p" "$1" | tail -n1
}

# Set key = value in /etc/libvirt/qemu.conf, uncommenting the shipped line.
qemu_conf_set() {
	local key=$1 val=$2 file=/etc/libvirt/qemu.conf
	if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
		sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|" "$file"
	elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "$file"; then
		sed -i -E "0,/^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=.*\$/s||${key} = ${val}|" "$file"
	else
		printf '%s = %s\n' "$key" "$val" >>"$file"
	fi
}

################################################################################
step "host packages"
################################################################################

apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get install -y \
	qemu-system-x86 qemu-utils \
	libvirt-daemon-system libvirt-daemon-driver-qemu libvirt-clients \
	cloud-image-utils genisoimage xorriso \
	nftables apparmor apparmor-utils \
	tshark openssh-client \
	curl ca-certificates git \
	sqlite3

note "tshark may ask about non-superuser capture; answer no. The broker runs"
note "as root and does not need the wireshark group."

################################################################################
step "users, groups, and directories"
################################################################################

# Host service users. These are not the guest account xentry-guest, which is
# created inside each VM by cloud-init.
groupadd -f --system xentry
groupadd -f --system xentry-vm
id -u xentry >/dev/null 2>&1 || useradd --system \
	--gid xentry --home-dir "$STATE" --create-home \
	--shell /usr/sbin/nologin xentry
id -u xentry-vm >/dev/null 2>&1 || useradd --system \
	--gid xentry-vm --home-dir /var/lib/xentry-vm --create-home \
	--shell /usr/sbin/nologin xentry-vm
usermod -aG kvm xentry-vm

# App-owned state: SQLite index, app job attempts, broker job directories, and
# the broker mirror. Broker-created subdirectories remain root-owned.
install -d -m 0750 -o xentry -g xentry "$STATE"
install -d -m 0750 -o xentry -g xentry "$STATE/jobs"
install -d -m 0750 -o xentry -g xentry "$STATE/mirror"
# Read-only build inputs: images are read by QEMU; artifacts are read by the
# root broker and the app preflight, so the app group gets read access.
install -d -m 0755 -o root -g root "$STATE/images"
install -d -m 0750 -o root -g xentry "$STATE/artifacts"
install -d -m 0750 -o root -g xentry "$ETC"

################################################################################
step "uv and a private Python 3.12"
################################################################################

if [ -x "$UV" ]; then
	note "$UV is already installed"
else
	curl -LsSf https://astral.sh/uv/install.sh | sh
	install -m 0755 "${HOME:-/root}/.local/bin/uv" "$UV"
fi

# Ubuntu 26.04's system Python may be newer than 3.12, so uv keeps a private
# 3.12 under /opt/uv-python that both virtualenvs point at.
env UV_PYTHON_INSTALL_DIR="$UVPY" "$UV" python install 3.12
chmod -R a+rX "$UVPY"

################################################################################
step "code and the two virtualenvs"
################################################################################

# This script does not clone. It configures a host around a tree that is
# already there, so a missing or wrong tree is a hard stop rather than a
# silent fetch of something the operator did not choose.
for needed in pyproject.toml src/xentry broker targets config migrations; do
	[ -e "$APP/$needed" ] && continue
	echo
	echo "  $APP/$needed is missing, so this is not an xentry tree."
	echo
	echo "  Clone it first, then re-run this script from inside it:"
	echo "    sudo git clone https://github.com/zran147/xentry $APP"
	echo "    sudo $APP/install.sh"
	echo
	die "no tree at $APP"
done
note "configuring the host around the tree at $APP"

chown -R root:root "$APP"
chmod -R go-w "$APP"
chmod -R a+rX "$APP"

cd "$APP"

note "building $APP/.venv (app + dev)"
env UV_PYTHON_INSTALL_DIR="$UVPY" UV_PROJECT_ENVIRONMENT="$APP/.venv" \
	"$UV" sync --python 3.12 --extra app --extra dev
chmod -R a+rX "$APP/.venv"

note "building $APP/.venv-broker (broker: asyncssh, pyyaml)"
env UV_PYTHON_INSTALL_DIR="$UVPY" UV_PROJECT_ENVIRONMENT="$APP/.venv-broker" \
	"$UV" sync --python 3.12 --extra broker

# The app import must resolve under /opt/xentry/src; the broker import is the
# /opt/xentry/broker directory, reached through the unit's WorkingDirectory.
"$APP/.venv/bin/python" -c 'import xentry; print(xentry.__file__)'
(cd "$APP" && ./.venv-broker/bin/python -c 'import broker; print(broker.__file__)')

note "Do not put a .env file in $APP; the services read $ETC/app.env and"
note "$ETC/broker.env."

################################################################################
step "pinned artifacts and the three images"
################################################################################

cd "$APP"
env UV_BIN="$UV" UV_PYTHON_INSTALL_DIR="$UVPY" \
	XENTRY_ARTIFACT_DIR="$STATE/artifacts" \
	scripts/fetch-artifacts.sh --download

# build-images.sh needs /dev/kvm, so this must be the KVM-capable host.
env UV_BIN="$UV" UV_PYTHON_INSTALL_DIR="$UVPY" \
	XENTRY_IMAGE_DIR="$STATE/images" \
	scripts/build-images.sh --execute

chown -R root:root "$STATE/images"
chmod -R a+rX "$STATE/images"
chown -R root:xentry "$STATE/artifacts"
chmod -R g+rX,o-rwx "$STATE/artifacts"

################################################################################
step "QEMU user and libvirt"
################################################################################

systemctl enable --now apparmor
systemctl enable --now libvirtd

[ -e /etc/libvirt/qemu.conf.orig ] ||
	cp /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.orig

# QEMU runs as xentry-vm:kvm so it can open /dev/kvm; the broker chowns the
# overlay, seed and serial files to xentry-vm, so ownership still limits
# access to this job's files. security_driver=apparmor is what makes libvirt
# generate a per-domain profile (step 9).
qemu_conf_set user '"xentry-vm"'
qemu_conf_set group '"kvm"'
qemu_conf_set security_driver '"apparmor"'
grep -nE '^[[:space:]]*(user|group|security_driver)[[:space:]]*=' \
	/etc/libvirt/qemu.conf || true

systemctl restart libvirtd
virsh -c qemu:///system net-list --all || true
if runuser -u xentry-vm -- test -r /dev/kvm; then
	note "xentry-vm can read /dev/kvm"
else
	note "WARNING: xentry-vm cannot read /dev/kvm; check the kvm group"
fi

################################################################################
step "environment files"
################################################################################

if [ -e "$ETC/app.env" ]; then
	note "$ETC/app.env exists; updating the production paths in place"
else
	cp "$APP/.env.example" "$ETC/app.env"
fi
chown root:xentry "$ETC/app.env"
chmod 0640 "$ETC/app.env"

env_set "$ETC/app.env" XENTRY_DATA_DIR "$STATE"
env_set "$ETC/app.env" XENTRY_DB_PATH "$STATE/xentry.db"
env_set "$ETC/app.env" XENTRY_BROKER_SOCKET /run/xentry/broker.sock
env_set "$ETC/app.env" XENTRY_IMAGES_MANIFEST "$STATE/images/build-results.json"
env_set "$ETC/app.env" XENTRY_ARTIFACT_MANIFEST "$STATE/artifacts/manifest.json"
# These three were missed, and the result is a host where the app reads
# artifacts from ./var/artifacts - relative, so /opt/xentry/var - while its
# manifest says /var/lib/xentry/artifacts/manifest.json. Two directories, one
# of them 1.1G of files the broker never looks at, and a manifest describing
# the other. Every path in app.env is absolute now.
env_set "$ETC/app.env" XENTRY_ARTIFACT_DIR "$STATE/artifacts"
env_set "$ETC/app.env" XENTRY_IMAGE_DIR "$STATE/images"
env_set "$ETC/app.env" XENTRY_IMAGE_MANIFESTS "$APP/config/image-manifests.yaml"
env_set "$ETC/app.env" XENTRY_ARTIFACT_CATALOG "$APP/config/artifacts.yaml"
env_set "$ETC/app.env" XENTRY_STEPS_MANIFEST "$APP/targets/steps.yaml"
env_set "$ETC/app.env" XENTRY_TARGETS_DIR "$APP/targets"
env_default "$ETC/app.env" XENTRY_ALLOWED_HOSTS localhost,127.0.0.1

if [ -e "$ETC/broker.env" ]; then
	note "$ETC/broker.env exists; left as it is"
	grep -nE '^XENTRY_(WAN_BRIDGE|PROXY_IP)=' "$ETC/broker.env" || true
else
	cat >"$ETC/broker.env" <<'EOF'
XENTRY_BROKER_SOCKET=/run/xentry/broker.sock
XENTRY_DATA_DIR=/var/lib/xentry
XENTRY_IMAGE_DIR=/var/lib/xentry/images
XENTRY_ARTIFACT_MANIFEST=/var/lib/xentry/artifacts/manifest.json
XENTRY_ARTIFACT_CATALOG=/opt/xentry/config/artifacts.yaml
XENTRY_STEPS_MANIFEST=/opt/xentry/targets/steps.yaml
XENTRY_TARGETS_DIR=/opt/xentry/targets
XENTRY_APPLY_NFT=1
# The proxy VM's address. Not a switch: it is the broker's own default too,
# and an empty value does not fall back to running the proxies on the host -
# ADR 0002 removed that path and the code is now gone.
#
# There is no XENTRY_WAN_BRIDGE here, and no XENTRY_START_MIRROR. Both reached
# only the host-side rule builders and the host-side artifact mirror, which
# were deleted with that path; the bridge name is fixed in
# deploy/proxy-vm/host-wan.nft. A variable the code does not read is worse
# than no variable: it reads as configuration and changes nothing.
XENTRY_PROXY_IP=10.44.0.2
XENTRY_QEMU_USER=xentry-vm
# Both provisioning channels. Each is reachable from a guest while it
# provisions and is closed by lock_network before any PoC runs, so each is
# opted into here rather than assumed. Without the first, every derived apt
# target fails at provision; without the second, every ecosystem target does.
XENTRY_START_APT_PROXY=1
XENTRY_START_REGISTRY_PROXY=1
EOF
fi
chown root:root "$ETC/broker.env"
chmod 0600 "$ETC/broker.env"

# Never the DeepSeek key: it belongs in app.env only.
grep -n 'DEEPSEEK' "$ETC/broker.env" && die "remove the key from broker.env" || true

# Purely informational: with XENTRY_POC_MODEL empty the experimental tab just
# explains what to set. grep finding nothing must not end the run.
grep -nE '^XENTRY_POC_MODEL=.+' "$ETC/app.env" ||
	note "XENTRY_POC_MODEL is unset: the experimental tab is off (fine)"
# Not fine, and it fails in a way that does not look like a rate limit: without
# a token GitHub allows 60 requests an hour per address, a check spends one
# listing the PoC repository, and after the quota every check reads an empty
# listing - reported as "the PoC text does not name a file that runs the
# exploit", a verdict about content for a list never read.
grep -qE '^XENTRY_GITHUB_TOKEN=.+' "$ETC/app.env" ||
	{ note "XENTRY_GITHUB_TOKEN is unset. Fine for a few CVEs; a sweep will"
	  note "exhaust GitHub's 60-an-hour and the refusals will blame the PoC"
	  note "text instead of the quota. A no-scope token raises it to 5,000."; }

if [ -z "$(env_value "$ETC/app.env" DEEPSEEK_API_KEY)" ]; then
	cat <<EOF

Stopping here, with the host fully prepared and nothing started.

  DEEPSEEK_API_KEY is empty in $ETC/app.env.

  1. sudoedit $ETC/app.env
  2. set DEEPSEEK_API_KEY=<your-key>
  3. to reach the app from the network, set BOTH of these. They are not the
     same setting and one without the other does not work:

       XENTRY_BIND_ADDR     WHERE THE SOCKET LISTENS. Empty means 127.0.0.1
                            only, and nothing on the network can reach the
                            port at all.
       XENTRY_ALLOWED_HOSTS WHICH Host: HEADERS ARE ACCEPTED once a request
                            does arrive. A missing entry is not a startup
                            error: the app serves pages and then rejects
                            every POST with 403 host_invalid.

     Set only the first and every POST is refused. Set only the second and
     nothing reaches the app to be refused. This script copies BIND_ADDR into
     ALLOWED_HOSTS for you, so add a name here only for a hostname or reverse
     proxy you also use.

  4. XENTRY_BIND_ADDR also needs XENTRY_ADMIN_IPS - the source addresses
     allowed to reach that port - because the app has NO authentication.
     DEV=1 accepts any source when that list is empty, and says so.
  5. re-run: sudo $0

README.md explains what every variable in that file does. Steps 1-7 are
already done; re-running repeats them harmlessly and continues from step 8.
EOF
	exit 0
fi

################################################################################
step "systemd units and the services"
################################################################################

install -m 0644 "$APP/deploy/xentry-broker.service" \
	/etc/systemd/system/xentry-broker.service
install -m 0644 "$APP/deploy/xentry.service" \
	/etc/systemd/system/xentry.service

# The checked-in broker unit still names the retired second tree. Until it is
# updated in place, a drop-in points it at the one tree and its own venv.
# A drop-in used to override WorkingDirectory and ExecStart here, because the
# shipped unit still named the retired /opt/xentry-broker. The unit itself now
# carries the one-tree paths, so overriding them would be two sources of truth
# for the same two lines - the exact problem the collapse removed. Verify them
# instead: a drop-in silently reintroducing the old path is the failure this
# guards against.
for pair in "WorkingDirectory=/opt/xentry" \
            "ExecStart=/opt/xentry/.venv-broker/bin/python -m broker.main"; do
	grep -qxF "$pair" /etc/systemd/system/xentry-broker.service ||
		die "the broker unit is missing: $pair"
done

systemctl daemon-reload
systemctl enable --now xentry-broker.service
systemctl enable --now xentry.service
systemctl --no-pager status xentry-broker.service xentry.service || true

# The broker unit creates /run/xentry mode 0750 group xentry; the socket is
# 0660 root:xentry.
ls -l /run/xentry/broker.sock || true
curl -fsS http://127.0.0.1:8000/api/system || true

################################################################################
step "AppArmor deny rules and the deployment verifier"
################################################################################

# QEMU confinement comes from libvirt's AppArmor security driver, not from a
# hand-written profile: it must list apparmor among the host security models.
virsh -r -c qemu:///system capabilities | grep -A2 '<secmodel>' ||
	die "libvirt reports no apparmor secmodel; fix security_driver (step 6)"

"$APP/scripts/install-apparmor.sh"

cd "$APP"
./.venv/bin/python scripts/verify_deployment.py \
	--artifacts-manifest "$STATE/artifacts/manifest.json" \
	--images-manifest "$STATE/images/build-results.json" || true

note "The 'apparmor qemu confinement' check is advisory while the host is"
note "idle and a required gate once a VM is up. Re-run the verifier during a"
note "job, and check the locked phase at the same time:"
note "  sudo nft list table inet xentry"

################################################################################
step "optional: serve on a routable address"
################################################################################

# Both are read from app.env, which step 7 stops for, so publishing the app is
# one edit in one file rather than an environment variable remembered at the
# right moment. An argument still wins, for a one-off.
[ -n "$BIND_ADDR" ] || BIND_ADDR=$(env_value "$ETC/app.env" XENTRY_BIND_ADDR)
[ -n "$ADMIN_IPS" ] || ADMIN_IPS=$(env_value "$ETC/app.env" XENTRY_ADMIN_IPS)

if [ -z "$BIND_ADDR" ]; then
	note "XENTRY_BIND_ADDR is empty in $ETC/app.env: the app stays on"
	note "127.0.0.1 only. Nothing on the network can reach it - and that is"
	note "a bind, not a Host-header question, so XENTRY_ALLOWED_HOSTS does"
	note "not change it. Set it there and re-run to publish the app."
elif [ -z "$ADMIN_IPS" ] && [ "$DEV" != 1 ]; then
	die "XENTRY_BIND_ADDR needs XENTRY_ADMIN_IPS, or DEV=1 to accept any source"
else
	if [ -z "$ADMIN_IPS" ]; then
		# DEV=1 with no list. Said out loud, because it is the one default
		# that would otherwise put an unauthenticated port on every network
		# this host is attached to.
		ADMIN_IPS="0.0.0.0/0 ::/0"
		note "DEV=1 and XENTRY_ADMIN_IPS is empty: the port will accept ANY"
		note "source address. The app has no authentication, so anyone who"
		note "can route to $BIND_ADDR:8000 can submit a job that detonates a"
		note "real exploit on this host and can read every stored artifact."
	fi
	install -d -m 0755 /etc/systemd/system/xentry.service.d
	cat >/etc/systemd/system/xentry.service.d/10-bind.conf <<UNIT
[Service]
ExecStart=
ExecStart=/opt/xentry/.venv/bin/uvicorn xentry.web.app:app --host ${BIND_ADDR} --port 8000
UNIT
	env_set "$ETC/app.env" XENTRY_ALLOWED_HOSTS "$BIND_ADDR"
	# shellcheck disable=SC2086
	"$APP/scripts/install-webfilter.sh" $ADMIN_IPS
	systemctl daemon-reload
	systemctl restart xentry
	note "127.0.0.1:8000 no longer listens; reach the app at $BIND_ADDR."
	note "Deleting the drop-in and reloading returns it to loopback."
fi

################################################################################
step "the proxy VM"
################################################################################

# NOT OPTIONAL. This was gated on INSTALL_PROXY_VM=1, default off, which left
# a default install broken in a way nothing reported until a job ran:
#
#   broker/main.py:    proxy_ip = os.environ.get("XENTRY_PROXY_IP") or PROXY_VM_IP
#   broker/runtime.py: PROXY_VM_IP = "10.44.0.2"
#
# proxy_ip is therefore NEVER empty. Every `if self.proxy_ip:` branch in the
# runtime is taken - nine of them - and the two `if not self.proxy_ip:` guards
# are dead code. ADR 0002 removed the in-process mirrors; there is no value
# that brings them back. So the broker addresses 10.44.0.2 over xentrywan0
# whether or not that machine exists, and without it every job fails at
# provision because the package mirrors are not there.
#
# The bring-up is idempotent and refuses to finish unless its own isolation
# probe passes inside the VM, so re-running this step is safe and cheap.
# There is no flag to skip this. An install without the VM is not a working
# install, and a knob that produces a broken deployment is not a choice worth
# offering - it only moves the failure to the first job, where it looks like a
# provisioning bug instead of a missing machine.
if [ ! -x "$APP/.venv-broker/bin/python" ]; then
	die "the broker virtualenv is missing; re-run this script (step 4 builds it)"
else
	# A supported base: Ubuntu 24.04 ships the Python 3.12 the mirror code is
	# written against, and its pool is still served. REBUILD=1 discards the
	# existing disk; STAGE2=0 does the mirrors without the job bridges. The
	# run refuses to finish unless the isolation probe passes inside the VM.
	env BASE="${BASE:-ubuntu-24.04-base.img}" "$APP/scripts/proxy-vm-up.sh"
	# Step 7 already wrote both values into broker.env, and they are the
	# broker's defaults besides - there is no longer a value that runs the
	# mirrors on the host, so there is nothing left to "cut over".
	note "The broker already addresses the VM at 10.44.0.2 over xentrywan0."
	note "Restart it to pick up a VM built after it started:"
	note "  sudo systemctl restart xentry-broker"
	note "See deploy/proxy-vm/README.md for what each piece refuses to do."
fi

################################################################################
step "optional: developer access"
################################################################################

# Editing the installed tree, restarting the services, and reading the
# diagnostics - without a password prompt for each, and without handing over
# the secrets. The code trees become group-writable to xentry-dev; /etc/xentry,
# /var/lib/xentry and both virtualenvs are deliberately NOT touched, so app.env
# stays 640 root:xentry and a developer cannot read it.
if [ "$DEV" != 1 ]; then
	note "not requested; the tree stays root-owned and unwritable."
	note "To grant it: DEV=1 sudo $0   (or DEV=1 DEV_USER=someone)"
elif [ -z "$DEV_USER" ]; then
	die "DEV=1 needs a user: run under sudo, or pass DEV_USER=<name>."
elif ! id -u "$DEV_USER" >/dev/null 2>&1; then
	die "DEV_USER=$DEV_USER is not a user on this host."
else
	groupadd -f xentry-dev
	usermod -aG xentry-dev "$DEV_USER"
	for tree in "$APP/src" "$APP/tests" "$APP/broker" "$APP/targets"; do
		[ -d "$tree" ] || continue
		chgrp -R xentry-dev "$tree"
		# setgid on directories, so a file created later inherits the group
		# instead of silently reverting to root-only.
		find "$tree" -type d -exec chmod 2775 {} +
		find "$tree" -type f -exec chmod 664 {} +
		note "$tree -> xentry-dev, group-writable, setgid"
	done
	for keep in "$APP/.venv" "$APP/.venv-broker" "$ETC" "$STATE"; do
		[ -e "$keep" ] && stat -c '    untouched: %A %U:%G %n' "$keep" || true
	done

	# Two narrow sudo rules. A malformed file in /etc/sudoers.d can make sudo
	# refuse every command, locking the host's only administrator out, so each
	# is parsed on a temporary path BEFORE it is installed and the whole
	# configuration is re-parsed after - and removed again if either fails.
	# visudo -cf exits 0 for a rule that parses but is wrong. Drop the colon
	# after NOPASSWD and it reports
	#   Cmnd_Alias "NOPASSWD" referenced but not defined
	# on stdout, says "parsed OK", and exits 0 - so `visudo -cf f >/dev/null`
	# both misses it and hides the warning that would have shown it. The exit
	# status is not enough; the output has to be read.
	check_rule() {
		out=$(visudo -cf "$1" 2>&1) || return 1
		case "$out" in
			*"parsed OK"*) ;;
			*) printf '%s\n' "$out" | sed 's/^/      /'; return 1 ;;
		esac
		case "$out" in
			*"referenced but not defined"*|*"syntax error"*|*"unknown"*)
				printf '%s\n' "$out" | sed 's/^/      /'; return 1 ;;
		esac
		return 0
	}

	SYSTEMCTL=$(command -v systemctl)
	tmprule=$(mktemp)
	printf '%s\n' "$DEV_USER ALL=(root) NOPASSWD: \
$SYSTEMCTL restart xentry.service, \
$SYSTEMCTL restart xentry-broker.service, \
$SYSTEMCTL restart xentry.service xentry-broker.service" >"$tmprule"
	check_rule "$tmprule" ||
		{ rm -f "$tmprule"; die "the restart rule is not what it should be"; }
	install -o root -g root -m 0440 "$tmprule" /etc/sudoers.d/xentry-dev
	rm -f "$tmprule"

	if [ -x "$APP/scripts/xentry-read.sh" ]; then
		install -o root -g root -m 0755 "$APP/scripts/xentry-read.sh" \
			/usr/local/sbin/xentry-read
		tmprule=$(mktemp)
		printf '%s\n' \
			"$DEV_USER ALL=(root) NOPASSWD: /usr/local/sbin/xentry-read" >"$tmprule"
		check_rule "$tmprule" ||
			{ rm -f "$tmprule"; die "the xentry-read rule is not what it should be"; }
		install -o root -g root -m 0440 "$tmprule" /etc/sudoers.d/xentry-read
		rm -f "$tmprule"
		note "/usr/local/sbin/xentry-read installed (read-only diagnostics)"
	fi

	visudo -c >/dev/null 2>&1 || {
		rm -f /etc/sudoers.d/xentry-dev /etc/sudoers.d/xentry-read
		die "sudo's configuration no longer parses; both rules were removed"
	}
	note "sudo config still parses as a whole"

	# Parsing is not granting. Ask sudo itself what the user may now do - -l
	# lists privileges without running anything, so this restarts nothing.
	granted=$(sudo -u "$DEV_USER" sudo -n -l 2>/dev/null || true)
	case "$granted" in
		*"restart xentry.service"*)
			note "verified with sudo -l: $DEV_USER may restart the services" ;;
		*)
			note "WARNING: sudo -l does not show the restart rule for $DEV_USER."
			note "The file is installed and parses; check it by hand:"
			note "  sudo -u $DEV_USER sudo -n -l" ;;
	esac
	note ""
	note "$DEV_USER must start a NEW login shell before the group applies."
	note "Without logging out: sg xentry-dev -c 'touch $APP/src/.probe'"
fi

################################################################################
step "first job (manual)"
################################################################################

cat <<EOF

      Open http://127.0.0.1:8000${BIND_ADDR:+ (or http://$BIND_ADDR:8000)}
      and submit one of the pinned CVE/PoC pairs from docs/operations.md.

      Follow it with:
        sudo journalctl -u xentry-broker.service -f
        sudo journalctl -u xentry.service -f

install.sh finished all $TOTAL steps.
EOF
