#!/usr/bin/env bash
# A pipeline ending in `grep -q` is a trap under `set -o pipefail`: grep exits
# at its first match and closes the pipe, the writer dies of SIGPIPE, and
# pipefail reports 141 for a pipeline that FOUND what it was looking for. It
# only bites once the writer exceeds the 64KB pipe buffer, so it is invisible
# on small inputs and intermittent on growing ones. `grep -c` reads to the end,
# so there is no early close and no signal.
# Provision a derived target: install packages from the job's pinned apt
# snapshot and enable named units. Runs as root in the target VM.
# Args: apt_proxy_url suite packages units sources_format ports archive
#       check_valid_until artifact_path install
#
# This is the whole vocabulary. No command comes from the model or the app:
# they supply a package list and a unit list, each token checked here against
# a strict pattern, and anything else is refused. A wrong package is a failed
# provision, not an arbitrary command run as root.
#
# `ports` is what the advisory says the attacker will reach, and this script
# ends by proving that something is listening on each of them, reachable from
# off this host. Readiness checks the ports too, but it connects to 127.0.0.1
# and only after the attacker VM exists, so it passes a service bound to
# loopback alone - and then the PoC fails with a connection error that reads
# like a broken exploit. Checking the bind here names the real fault.
set -euo pipefail

proxy_url="${1:?apt_proxy_url}"
suite="${2:?suite}"
packages="${3-}"
units="${4-}"
sources_format="${5-deb822}"
ports="${6-}"
# Which archive the proxy is backed by. It decides the path under the proxy and
# the component list: Ubuntu has restricted and multiverse, Debian has contrib
# and non-free. Naming Ubuntu's components to a Debian archive makes apt
# download four index files that do not exist.
archive="${7-ubuntu}"
# The job's date-pinned PyPI index, and the distributions to take from it. Only
# the attacker ever needs these: it is the machine that runs the PoC, and the
# network is locked before the exploit, so an import the image lacks cannot be
# fetched later. The proxy filters every release by its upload-time, so this
# installs what PyPI held one day before the advisory - the same rule the apt
# side has always followed. Appended at 12 and 13 because both step entries
# bind the first eleven positionally.
registry_url="${12-}"
pip_packages="${13-}"
check_valid_until="${8-1}"
# The operator-approved downloads, as NAMES, space separated, in the order
# they were approved - which is the order they install, so a .deb lands before
# the config that configures it. Already fetched on the host, digest-checked
# there and again by the broker, and copied in before this runs. Each file's
# install is derived from its own suffix here and never supplied: a .deb has
# one install and a tarball has one. A name, not a path, resolved under one
# directory below. This is the last resort, offered only after both apt
# archives and the ecosystem path have been tried and failed.
artifacts="${9-}"
# An unpacked product has no systemd unit: the tarball IS the install, and what
# starts it is a shell script under its own bin/. `launch` is that script's
# NAME - never a path, never a command - resolved under the unpacked tree below
# and run from the directory it lives in. It is the same class of token as a
# unit name, which this script has always taken from the app and handed to
# systemctl: a name checked against a pattern, used by checked-in code that
# decides how it runs, as whom, and with what environment. Confluence's is
# start-confluence.sh, Tomcat's startup.sh, WSO2's wso2server.sh.
launch="${10-}"
# Where a placed file goes, by KIND. `file` is one file at one path, and the
# path is decided here rather than supplied: a config that makes the affected
# software vulnerable at all, or a web archive that IS the affected
# application. Same discipline as `launch` - the app names a kind, this script
# knows what that kind means.
place="${11-}"

[[ "$proxy_url" =~ ^http://[0-9.]+:[0-9]+$ ]] || { echo "bad apt_proxy_url" >&2; exit 2; }
[[ "$suite" =~ ^[a-z]+$ ]] || { echo "bad suite" >&2; exit 2; }
if [ -n "${pip_packages// /}" ]; then
  [[ "$registry_url" =~ ^http://[0-9.]+:[0-9]+$ ]] || {
    echo "pip packages were named but registry_url is not a proxy url" >&2; exit 2; }
  for name in $pip_packages; do
    # PEP 503 names, which are not apt names: any case, dots and underscores
    # allowed. Nothing that could be a path or a second argument.
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || {
      echo "bad pip package: $name" >&2; exit 2; }
  done
fi
case "$archive" in
  ubuntu) components="main restricted universe multiverse"; pockets=1 ;;
  debian) components="main contrib non-free"; pockets=0 ;;
  *) echo "bad archive: $archive" >&2; exit 2 ;;
esac
case "$check_valid_until" in 0|1) ;; *) echo "bad check_valid_until" >&2; exit 2 ;; esac
ARTIFACT_DIR=/var/lib/xentry/artifacts
# What each approved file's suffix means. Checked before anything is installed,
# so a set with one bad member fails before the first dpkg rather than halfway.
install_for() {
  case "$1" in
    *.deb) printf deb ;;
    *.tar.gz|*.tgz|*.tar.xz|*.tar.bz2) printf tarball ;;
    *.zip) printf zip ;;
    *.conf|*.war) printf file ;;
    *) return 1 ;;
  esac
}
placed=0
for name in $artifacts; do
  # A NAME: no separator, so it cannot be a path, and resolved only here.
  [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || {
    echo "refused artifact name: $name" >&2; exit 2; }
  case "$name" in *..*) echo "refused artifact name: $name" >&2; exit 2 ;; esac
  [ -f "$ARTIFACT_DIR/$name" ] || {
    echo "missing approved artifact: $ARTIFACT_DIR/$name" >&2; exit 2; }
  verb=$(install_for "$name") || {
    echo "no install for $name" >&2; exit 2; }
  if [ "$verb" = file ]; then
    placed=$((placed + 1))
    case "$place" in
      apache-site|nginx-site|tomcat-webapp) ;;
      *) echo "refused place for $name: ${place:-none}" >&2; exit 2 ;;
    esac
  fi
done
# `place` names ONE kind, so it can describe at most one file. Two would both
# be written to the same path and the second would silently win.
[ "$placed" -le 1 ] || { echo "$placed placed files, but place names one" >&2; exit 2; }
if [ -n "$place" ] && [ "$placed" -eq 0 ]; then
  echo "place was given but no approved file is one that gets placed" >&2
  exit 2
fi
if [ -n "$launch" ]; then
  # No slash and no dot-dot: the pattern is the whole defence, because the name
  # is resolved by find under one directory rather than used as a path.
  [[ "$launch" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "refused launch: $launch" >&2; exit 2; }
  case "$launch" in .|..) echo "refused launch: $launch" >&2; exit 2 ;; esac
  case "$install" in
    tarball|zip) ;;
    # A .deb brings its own unit and an empty install has nothing to start.
    *) echo "launch needs an unpacked artifact, not install=${install:-none}" >&2; exit 2 ;;
  esac
fi
case "$sources_format" in
  deb822|oneline) ;;
  *) echo "bad sources_format: $sources_format" >&2; exit 2 ;;
esac

check_tokens() {
  local kind="$1" pattern="$2" list="$3" token
  for token in $list; do
    [[ "$token" =~ $pattern ]] || { echo "refused $kind: $token" >&2; exit 2; }
  done
}
# Debian package names, optionally version-pinned with =.
check_tokens package '^[a-z0-9][a-z0-9+.-]*(=[A-Za-z0-9+.:~-]+)?$' "$packages"
check_tokens unit '^[A-Za-z0-9@._-]+$' "$units"
check_tokens port '^[0-9]{1,5}$' "$ports"

mkdir -p /var/lib/xentry

install -d -m 755 /etc/apt/sources.list.d /etc/apt/apt.conf.d
: > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/ubuntu.sources
# sid has no -updates or -security: unstable is where everything lands, and
# asking for pockets that do not exist fails the update.
#
# Neither does an EARLY UBUNTU SERIAL. snapshot.ubuntu.com began capturing the
# -updates and -security pockets around 2023-06; before that it has only the
# release pocket. Measured through this job's own proxy path:
#
#   20220217  dists/jammy/Release 200   dists/jammy-updates/Release 404
#   20230601  dists/jammy/Release 200   dists/jammy-updates/Release 200
#
# and the release index is byte-identical at both serials, because a release
# pocket is immutable once published. So an early serial is perfectly
# installable - it just has one pocket - and the broker used to refuse the
# whole job for it ("serial 20220217T000000Z is before this archive's floor
# 20230601T000000Z"), which cost every 2022 CVE: redis, cacti, icingaweb2,
# PwnKit, enlightenment.
#
# ASKED, not computed: the step is handed a suite and an archive but never the
# serial, so it cannot know which era it is in. One HEAD against the pocket's
# own Release file answers exactly the question that matters - does this
# serial carry it - and keeps working whatever the floor moves to. A guest
# with no route to the proxy fails the next line anyway.
if [ "$pockets" = "1" ]; then
  # 2>/dev/null, because a 404 here is the EXPECTED answer for an early
  # serial and curl -S prints "The requested URL returned error: 404" for it.
  # That line interleaved into apt's output and read as part of the failure.
  if curl -fsS -m 20 -o /dev/null \
      "${proxy_url}/${archive}/dists/${suite}-updates/Release" 2>/dev/null
  then
    suites="${suite} ${suite}-updates ${suite}-security"
    echo "the serial carries -updates and -security"
  else
    suites="$suite"
    echo "this serial predates -updates/-security: release pocket only"
  fi
else
  suites="$suite"
fi
case "$archive" in
  ubuntu) keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
  debian) keyring=/usr/share/keyrings/debian-archive-keyring.gpg ;;
esac
[ -f "$keyring" ] || { echo "the image has no $keyring" >&2; exit 2; }
if [ "$sources_format" = "deb822" ]; then
  cat > /etc/apt/sources.list.d/xentry-snapshot.sources <<EOF
Types: deb
URIs: ${proxy_url}/${archive}
Suites: ${suites}
Components: ${components}
Signed-By: ${keyring}
EOF
else
  # 18.04 ships apt 1.6, which does not read .sources files. The archive
  # signature is still checked, against the keyring apt already trusts.
  : > /etc/apt/sources.list
  for pocket in $suites; do
    echo "deb ${proxy_url}/${archive} ${pocket} ${components}" >> /etc/apt/sources.list
  done
fi

cat > /etc/apt/apt.conf.d/99xentry <<EOF
Acquire::Retries "3";
# 300, not 60. A cold proxy cache against a snapshot host is slow: the first
# fetch of a large index can exceed a minute, apt breaks the pipe, and the
# mirror logs BrokenPipeError while still completing the fetch. The retry then
# hits the warm cache and succeeds - so this recovered by luck, twice, 73
# seconds apart, and only because Retries is 3.
#
# The attacker is the worst case: its archive is unpinned, so its indices are
# fetched fresh the first time any job needs them. The cache in the VM
# persists across jobs, so this cost is paid once - but it should not be paid
# as a near-timeout.
Acquire::http::Timeout "300";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOF
# A snapshot Release expired the week it was made. Its signature is still
# verified - that is not relaxed here - but apt also refuses a Release whose
# Valid-Until has passed, which for a 2021 serial is every one of them.
# Ubuntu's snapshot service rewrites the field; Debian's serves the original.
if [ "$check_valid_until" = "0" ]; then
  echo 'Acquire::Check-Valid-Until "false";' >> /etc/apt/apt.conf.d/99xentry
fi

export DEBIAN_FRONTEND=noninteractive
# apt-listchanges prints the changelog and NEWS prose of every upgraded
# package. On the Debian path a job upgrades libc6, and glibc's NEWS entry
# alone is long enough to fill the 3000-character failure record: the redis
# job ran five minutes, failed, and reported nothing but
#   apt-listchanges: News
#   glibc (2.32-0experimental1) experimental; urgency=medium
# Silenced at the source rather than filtered afterwards. Filtering only moves
# the problem to whatever prints next - dpkg's percent counter took the window
# the moment the previous flood was dealt with.
export APT_LISTCHANGES_FRONTEND=none
# needrestart is the third thing to flood the failure record, after dpkg's
# percent counter and apt-listchanges. It prints a block per transaction -
# "Running kernel seems to be up-to-date", "No containers need to be
# restarted", "No VM guests are running outdated hypervisor binaries" - and on
# the attacker that pushed pip's actual error to the edge of the 3000-char
# detail.
#
# Silenced at the source, like the other two. Filtering only moves the problem
# to whatever prints next, which is exactly how this one arrived.
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
apt-get update
# Which kernels are here BEFORE the install, so the one this step adds can be
# named afterwards. The newest installed is not the answer: the base image
# ships its own kernel, and picking by version would silently assert the wrong
# one whenever the affected kernel is the older of the two.
kernels_before="$(dpkg-query -W -f '${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
  | sort || true)"
if [ -n "${packages// /}" ]; then
  # A target that expects a PORT installs the named packages as the
  # distribution intends, which means with their Recommends. Measured on two
  # jobs that got this far and died: Ubuntu noble's cacti declares BOTH the web
  # server and the database as Recommends -
  #   Recommends: apache2 | lighttpd | nginx | httpd, default-mysql-server | ...
  # - and roundcube-core declares its server the same way, so
  # --no-install-recommends installed the application files and nothing to
  # serve or store them. Both ended with "nothing is listening", cacti after
  # twelve minutes of provisioning.
  #
  # This is NOT a different package set from the one the reader approved:
  # `apt-get install cacti` resolves cacti's own closure either way. It is the
  # same names, installed the way the package says it needs to be.
  #
  # A local privesc target keeps --no-install-recommends. It expects no port,
  # nothing has to listen, and a minimal guest is both quicker to build and a
  # smaller surface around the thing being measured.
  recommends=--no-install-recommends
  [ -n "${ports// /}" ] && recommends=--install-recommends
  # socat, when a port is expected: Debian and Ubuntu ship most daemons bound
  # to localhost, and the expose step publishes those on the guest's address
  # rather than editing a config file per service. Installed from the SAME
  # dated archive as everything else and named in this step's parameters, so a
  # reader sees it - the same treatment build-essential gets for a privesc.
  [ -n "${ports// /}" ] && packages="$packages socat"
  echo "installing $packages with $recommends"
  # --allow-downgrades, because the BASE IMAGE IS NEWER THAN THE SNAPSHOT and
  # a dated lab is the archive's older state, downgrades included.
  #
  # The images are built from the CURRENT cloud image, so their installed libs
  # are newer than anything an older serial offers, and any dated package with
  # an exact-version dependency on one becomes unsatisfiable. Measured on the
  # sudo privesc job at serial 20241118T000000Z:
  #
  #   bzip2 : Depends: libbz2-1.0 (= 1.0.8-5.1build0.1)
  #           but 1.0.8-5.1ubuntu0.1 is to be installed
  #
  # noble at that serial publishes libbz2-1.0 1.0.8-5.1, noble-updates
  # publishes 1.0.8-5.1build0.1, and NEITHER publishes 1.0.8-5.1ubuntu0.1 -
  # that is the version the image already carried. apt would rather fail than
  # go backwards, and without this flag every privesc job died in dpkg
  # resolution while pulling build-essential.
  #
  # Downgrading is not a workaround here, it is the point: CVE-2023-4911 is a
  # bug in libc6, and provisioning it MEANS replacing the base image's newer
  # libc6 with the affected one. A lab that refused to go backwards could only
  # ever reproduce flaws newer than its own image.
  #
  # Not --allow-remove-essential: removing dpkg or libc6 outright would leave
  # a guest that cannot be provisioned at all, and that is a real failure
  # rather than a version to step back to.
  # shellcheck disable=SC2086 - the list is validated above and must word-split
  if ! apt-get install -y --allow-downgrades "$recommends" $packages; then
    # apt says "X is not going to be installed" and stops there, which is not
    # a reason. The redis job died on
    #   redis-server : Depends: redis-tools (= 5:5.0.7-2)
    #                  but it is not going to be installed
    # while every one of redis-tools' dependencies was present in the dated
    # index - measured, main carries adduser, libatomic1, libc6 and lsb-base,
    # universe carries libhiredis0.14, libjemalloc2, liblua5.1-0, lua-bitop
    # and lua-cjson - so the refusal came from apt's resolver, not from a
    # missing package, and nothing in the log said which constraint it could
    # not meet.
    #
    # So ask it. The solver's own trace names the package it gave up on and
    # what it was holding; apt-cache policy shows which version apt considers
    # a candidate, which is how a repository it has downloaded but will not
    # install from shows up. Diagnosis only - the step still fails.
    echo >&2
    echo "=== apt would not resolve this; its own reasoning follows" >&2
    for name in $packages; do
      echo "--- apt-cache policy $name" >&2
      apt-cache policy "$name" 2>&1 | sed 's/^/    /' >&2 || true
    done
    echo "--- apt-get install -s -o Debug::pkgProblemResolver=true" >&2
    # shellcheck disable=SC2086
    apt-get install -s -o Debug::pkgProblemResolver=true \
      --allow-downgrades "$recommends" $packages 2>&1 \
      | tail -40 | sed 's/^/    /' >&2 || true
    exit 1
  fi
fi

if [ -n "${pip_packages// /}" ]; then
  # pip3 itself, if the image does not carry it. The attacker manifest lists
  # python3-pip, but the image on disk was built 2026-11-10 and the manifest
  # gained that package afterwards, so the running VM had python3 and no pip:
  #   setup-attacker.sh: line 337: pip3: command not found
  # An image can always drift from the manifest that describes it - checking
  # here costs one command and removes a whole class of "the image is older
  # than the config" failures, without a 2.4 GB rebuild.
  #
  # From the job's own dated archive, like every other package this step
  # installs. pip is lab plumbing, not the software under test.
  if ! command -v pip3 >/dev/null 2>&1; then
    echo "pip3 is absent from this image; installing python3-pip"
    apt-get install -y --no-install-recommends python3-pip
  fi
  echo "installing $pip_packages from the job's dated PyPI index"
  # --index-url, so nothing is taken from pypi.org directly: the proxy is the
  # only index, and it shows only releases that existed before the advisory.
  # --break-system-packages matches the image build's reasoning: a disposable
  # VM with nothing in it to break, and a venv would be invisible to a PoC
  # that simply runs `python3 exploit.py`.
  # --trusted-host, because the proxy speaks plain HTTP and pip IGNORES an
  # untrusted index rather than failing on it:
  #   WARNING: The repository located at 10.42.1.1 is not a trusted or secure
  #   host and is being ignored.
  #   ERROR: Could not find a version that satisfies the requirement redis
  #          (from versions: none)
  # "from versions: none" reads like the package is absent from the index; it
  # means pip never looked. The index cannot be HTTPS: it is a per-job proxy on
  # the lab network with no certificate, and the job has no route off that
  # network to a real one.
  #
  # The host is taken from the URL the BROKER supplied, not from anything a
  # model wrote, and the scheme and path are stripped so only a bare host
  # reaches the flag.
  pip_host="${registry_url#*://}"
  pip_host="${pip_host%%/*}"
  pip_host="${pip_host%%:*}"
  # shellcheck disable=SC2086 - every name was validated above
  pip3 install --no-cache-dir --break-system-packages --disable-pip-version-check \
    --index-url "${registry_url%/}/pypi/" --trusted-host "$pip_host" $pip_packages
fi

# A kernel is not provisioned until the machine boots it, and that needs an
# initramfs and a boot entry. The runner reboots after this step and readiness
# asserts `uname -r` is what was installed here; without these two commands
# the new kernel sits on disk unreferenced and the reboot comes back on the old
# one, which would report a result about a kernel that never ran.
kernels_after="$(dpkg-query -W -f '${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
  | sort || true)"
added="$(comm -13 <(printf '%s\n' "$kernels_before") \
  <(printf '%s\n' "$kernels_after") | grep -v '^$' | sort -V | tail -1 || true)"
if [ -n "$added" ]; then
  update-initramfs -u -k all
  update-grub
  mkdir -p /var/lib/xentry
  printf 'kernel=%s\n' "${added#linux-image-}" > /var/lib/xentry/kernel.want
  printf 'installed kernel %s, grub updated\n' "${added#linux-image-}"
fi
# The approved files, after apt is configured and before the units start: a
# .deb's dependencies come from the archive, and an unpacked product may be
# what a unit runs.
#
# Three passes, in this order, rather than one loop over the list. The .debs go
# in TOGETHER because a set with interdependencies only resolves that way -
# installed one at a time, apache2 before apache2-bin fails and then -f install
# "fixes" it by pulling the archive's version instead of the approved one.
# Unpacking comes next, and placing last, so a config lands on a product that
# already exists.
if [ -n "$artifacts" ]; then
  PREFIX=/opt/xentry-artifact
  rm -rf "$PREFIX"
  mkdir -p "$PREFIX"

  debs=""
  for name in $artifacts; do
    [ "$(install_for "$name")" = deb ] && debs="$debs $ARTIFACT_DIR/$name"
  done
  if [ -n "$debs" ]; then
    # shellcheck disable=SC2086 - every name was validated above
    dpkg -i $debs || apt-get install -y -f
    # NOTE: this only asserts SOME package is installed, true of any Debian
    # system - close to vacuous. Left as it is rather than silently changing
    # what the step verifies; the bug fixed here is the SIGPIPE.
    [ "$(dpkg -l | grep -c "^i" || true)" -gt 0 ] ||
      { echo "the debs did not install" >&2; exit 1; }
    printf 'installed %s\n' "$debs"
  fi

  unpacked=0
  for name in $artifacts; do
    path="$ARTIFACT_DIR/$name"
    case "$(install_for "$name")" in
      tarball) tar -C "$PREFIX" -xf "$path"; unpacked=1 ;;
      zip)
        apt-get install -y --no-install-recommends unzip
        unzip -q -d "$PREFIX" "$path"
        unpacked=1
        ;;
    esac
  done

  for name in $artifacts; do
    [ "$(install_for "$name")" = file ] || continue
    # Before the units start, so the service reads it on its first boot rather
    # than needing a reload nothing would have issued.
    case "$place" in
      apache-site)
        dest=/etc/apache2/sites-enabled/000-default.conf
        [ -d /etc/apache2/sites-enabled ] || {
          echo "no /etc/apache2/sites-enabled: is apache2 in the package list?" >&2
          exit 1; }
        ;;
      nginx-site)
        dest=/etc/nginx/sites-enabled/default
        [ -d /etc/nginx/sites-enabled ] || {
          echo "no /etc/nginx/sites-enabled: is nginx in the package list?" >&2
          exit 1; }
        ;;
      tomcat-webapp)
        # tomcat9 on jammy and focal, tomcat10 on noble: whichever is here.
        webapps=$(find /var/lib -maxdepth 2 -type d -name webapps 2>/dev/null \
          | sort | head -1 || true)
        [ -n "$webapps" ] || {
          echo "no tomcat webapps directory: is tomcat in the package list?" >&2
          exit 1; }
        dest="$webapps/ROOT.war"
        ;;
    esac
    install -D -m 644 "$ARTIFACT_DIR/$name" "$dest"
    printf 'placed %s as %s\n' "$name" "$dest"
  done

  if [ "$unpacked" -eq 1 ]; then
    # One top-level directory is the usual shape; report what arrived either
    # way, because a unit or a start command has to name a path inside it.
    printf 'unpacked into %s:\n' "$PREFIX"
    find "$PREFIX" -maxdepth 1 -mindepth 1 | sed 's/^/  /'
    # Unpacking is not installing. With no unit and no launcher nothing will
    # ever bind the port, and the only question is whether that is said now or
    # after the 300s wait below times out saying "nothing is listening".
    if [ -z "$units" ] && [ -z "$launch" ]; then
      echo "the artifact unpacked but nothing starts it: no units and no launch" >&2
      echo "name the launcher the product ships, one of:" >&2
      find "$PREFIX" -maxdepth 4 -type f -name '*.sh' | sed 's/^/  /' >&2
      exit 1
    fi
  fi
fi

for unit in $units; do
  systemctl enable --now "$unit"
  # A placed config reaches disk AFTER apt's postinst has already started the
  # service - Debian and Ubuntu both start a daemon on install, and nothing
  # here installs a policy-rc.d to stop them - and `enable --now` on a unit
  # that is already active does NOT reread its configuration. So the service
  # went on serving the packaged default.
  #
  # That is what CVE-2021-41773 died of, twice, after eighteen of nineteen
  # steps: apache2 2.4.49 was the right build and blasty's own
  # 000-default.conf was on disk at the right path, but the running process
  # still had Debian's stock config, whose `<Directory /> Require all denied`
  # answers the traversal with 403 Forbidden. The evidence said so in one
  # line, once the failure started carrying the transcript:
  #   <title>403 Forbidden</title>
  #   <address>Apache/2.4.49 (Debian) Server at 10.42.1.10 Port 80</address>
  #
  # try-restart, not restart: a unit that is not running stays not running,
  # which is the enable --now result above and not ours to override.
  if [ "${placed:-0}" -ge 1 ]; then
    systemctl try-restart "$unit"
    printf 'restarted %s so it reads the placed config\n' "$unit"
  fi
done

# The unpacked product, started. After the units, because a product may need a
# database the apt step installed, and before the port wait, which is what
# proves this worked.
if [ -n "$launch" ]; then
  mapfile -t entries < <(find "$PREFIX" -maxdepth 4 -type f -name "$launch" | sort)
  case "${#entries[@]}" in
    1) ;;
    0)
      echo "no file named $launch under $PREFIX" >&2
      echo "--- shell scripts that are there ---" >&2
      find "$PREFIX" -maxdepth 4 -type f -name '*.sh' | sed 's/^/  /' >&2
      exit 1
      ;;
    *)
      echo "$launch is ambiguous under $PREFIX:" >&2
      printf '  %s
' "${entries[@]}" >&2
      exit 1
      ;;
  esac
  entry="${entries[0]}"
  home="$(dirname "$entry")"
  product="$(dirname "$home")"
  # A bundled runtime if the product ships one - Confluence's tarball does -
  # otherwise whichever JDK the apt step installed. Set rather than left to
  # chance: these launchers exit on an unset JAVA_HOME long before they bind a
  # port, and that failure reads as "nothing is listening".
  if [ -x "$product/jre/bin/java" ]; then
    export JAVA_HOME="$product/jre"
  else
    for candidate in /usr/lib/jvm/*/bin/java; do
      if [ -x "$candidate" ]; then
        JAVA_HOME="$(dirname "$(dirname "$candidate")")"
        export JAVA_HOME
        break
      fi
    done
  fi
  chmod +x "$entry" || true
  LAUNCH_LOG=/var/lib/xentry/launch.log
  printf 'launching %s from %s (JAVA_HOME=%s)\n' \
    "$entry" "$home" "${JAVA_HOME:-unset}"
  # setsid so a launcher that runs in the foreground - WSO2's does - does not
  # hold this step open until its timeout, and one that daemonises itself -
  # Confluence's does - is unaffected.
  #
  # The redirection on the SUBSHELL is not decoration. The broker reads this
  # step's stdout to EOF over its SSH channel, so the step ends when the last
  # holder of that pipe closes it, not when this script exits. Detaching the
  # grandchild is not enough: something in the setsid chain keeps the inherited
  # pipe, and with only the inner redirection a foreground launcher held the
  # provision step open for its whole life - measured at exactly the launcher's
  # runtime, which is the 1800s timeout for a real product. Closing the
  # subshell's own stdout and stderr is what makes the detach real.
  ( cd "$home" && setsid nohup "$entry" >"$LAUNCH_LOG" 2>&1 </dev/null & ) \
    >/dev/null 2>&1
fi

# The port the job was planned around has to be served, and served on an
# address the attacker can use. Waiting here rather than at readiness turns a
# five-minute timeout into a named fault while the evidence is still at hand.
listeners() {
  # Linux only, and the image always has one of the two.
  if command -v ss >/dev/null; then ss -Hltn 2>/dev/null
  else netstat -ltn 2>/dev/null | tail -n +3
  fi
}
# Every local address bound to this port, one per line. A listening socket's
# address is whichever field ends in :<port>; the peer field of a listener is
# always *:* or 0.0.0.0:*, so it cannot collide with a numeric port. Any %iface
# scope is dropped, because 127.0.0.53%lo is still loopback.
bound_on() {
  listeners | awk -v port="$1" '{
    for (i = 1; i <= NF; i++)
      if ($i ~ (":" port "$")) {
        sub(":" port "$", "", $i); sub("%.*", "", $i); print $i; break
      }
  }'
}
for port in $ports; do
  # 300s, the same grace readiness-generic.sh gives. Shorter here would fail a
  # slow-starting service that used to pass, which is not what this is for.
  deadline=$((SECONDS + 300))
  while :; do
    addresses="$(bound_on "$port")"
    # A reachable bind is anything that is not loopback: 0.0.0.0, ::, * or the
    # guest's own address. Loopback alone is the case worth naming.
    if [ -n "$addresses" ] && [ "$(printf '%s\n' "$addresses" \
          | grep -cvE '^(127\.[0-9.]+|\[?::1\]?)$' || true)" -gt 0 ]; then
      printf 'port %s is served on %s\n' "$port" "$(printf '%s' "$addresses" | tr '\n' ' ')"
      break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      if [ -n "$addresses" ]; then
        # PUBLISH IT instead of failing. Debian and Ubuntu ship most daemons
        # bound to localhost - redis.conf has "bind 127.0.0.1 ::1",
        # postgresql.conf has listen_addresses='localhost', my.cnf has
        # bind-address=127.0.0.1 - so the service installs, starts, is
        # genuinely running, and the attacker VM cannot reach it. That is lab
        # plumbing, not a property of the software under test, and it would
        # otherwise stop every non-web daemon CVE in the sweep.
        #
        # A FORWARDER, not a config edit. Editing each service's own file
        # would mean the harness authoring config per service - three files,
        # three syntaxes, three paths and counting - and would run the service
        # under a configuration the CVE was never reported against. socat
        # moves the socket and leaves the packaged config alone. It also helps
        # rather than hinders: redis sees the connection arriving from
        # 127.0.0.1, so protected-mode does not refuse it.
        #
        # Bound to the guest's OWN address, not 0.0.0.0: binding 0.0.0.0:6379
        # while the service holds 127.0.0.1:6379 fails with "address already
        # in use", because the two overlap. The guest address and loopback are
        # distinct, so both sockets coexist.
        #
        # Nothing here comes from a model: the port list is validated above,
        # the address is the guest's own, and this script is pinned by digest.
        guest_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
        if [ -n "$guest_ip" ] && command -v socat >/dev/null 2>&1 \
            && [[ "$guest_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
          echo "port $port is loopback-only; publishing it on $guest_ip"
          setsid socat "TCP-LISTEN:${port},bind=${guest_ip},fork,reuseaddr" \
            "TCP:127.0.0.1:${port}" </dev/null >/dev/null 2>&1 &
          # Proven, not assumed: the point is that the port answers on the
          # guest's address, so wait for exactly that before going on.
          for _ in 1 2 3 4 5 6 7 8 9 10; do
            addresses="$(bound_on "$port")"
            [ "$(printf '%s\n' "$addresses" \
              | grep -cvE '^(127\.[0-9.]+|\[?::1\]?)$' || true)" -gt 0 ] && break
            sleep 1
          done
          if [ "$(printf '%s\n' "$addresses" \
            | grep -cvE '^(127\.[0-9.]+|\[?::1\]?)$' || true)" -gt 0 ]; then
            printf 'port %s is served on %s\n' "$port" \
              "$(printf '%s' "$addresses" | tr '\n' ' ')"
            break
          fi
          echo "the forwarder did not come up on $guest_ip:$port" >&2
        fi
        echo "port $port is bound to loopback only, so the attacker cannot reach it;" >&2
        echo "the service needs a listen address of 0.0.0.0 in its own config" >&2
      else
        echo "nothing is listening on port $port after installing ${packages:-no packages}" >&2
        echo "units started: ${units:-none}, launch: ${launch:-none}" >&2
        # Why a web application installs and then serves nothing. Debian
        # expresses "you need one of these servers" as a Recommends, and this
        # step installs with --no-install-recommends, so the server never
        # arrives. Measured: roundcube-core recommends
        # "apache2 | lighttpd | spawn-fcgi | php-fpm | httpd-cgi" and the
        # roundcube job provisioned with nothing on port 443, while cacti,
        # wordpress, hoteldruid and mediawiki DEPEND on apache2 and come up
        # fine. One level down counts - roundcube itself declares neither -
        # so each named package's own Depends are inspected too.
        for want in $packages; do
          for near in "$want" $(apt-cache depends --no-recommends --no-suggests \
              --no-conflicts --no-breaks --no-replaces --no-enhances "$want" \
              2>/dev/null | awk '/Depends:/ {print $2}' | tr -d '<>' | head -20); do
            apt-cache show "$near" 2>/dev/null \
              | awk -v p="$near" '/^Recommends:/ && /apache2|nginx|lighttpd|php-fpm|httpd/ {
                   print "  " p " recommends a web server but does not depend on one:"
                   print "    " $0
                   print "    this step installs with --no-install-recommends, so none"
                   print "    was installed - name one in setup_packages"
                 }' >&2
          done
        done
        if [ -n "${LAUNCH_LOG:-}" ] && [ -f "$LAUNCH_LOG" ]; then
          echo "--- last 40 lines of $LAUNCH_LOG ---" >&2
          tail -n 40 "$LAUNCH_LOG" >&2
        fi
      fi
      echo "--- listening sockets ---" >&2
      listeners >&2
      exit 1
    fi
    sleep 2
  done
done

# What went in, recorded in the step output: a provision nobody can pin down
# is not a provision anyone can repeat.
dpkg-query -W -f '${binary:Package}=${Version}\n' | sort > /var/lib/xentry/packages.txt
touch /var/lib/xentry/setup-generic.done
printf 'generic setup: %d packages installed, units: %s\n' \
  "$(wc -l < /var/lib/xentry/packages.txt)" "${units:-none}"
