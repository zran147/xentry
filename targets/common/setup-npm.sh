#!/usr/bin/env bash
# Provision an application-package target: install the lab's dependencies from
# the job's date-pinned registry mirror and run its app. Runs as root.
# Args: registry_url node_version node_sha256 app_archive app_dir build start
#       port fixed_subject fixed_version control_port
#
# No command comes from the model, the app, or the lab. `build` and `start` are
# step names from a closed set, not shell strings, and every other argument is
# a token checked here. The lab's package.json decides which dependencies get
# installed and at what ranges; which versions those ranges mean is decided by
# the mirror, which serves only what existed before the advisory.
#
# That is the whole reason this installs from a registry rather than from a
# pre-resolved closure. A closure resolved on the host takes today's answer to
# the lab's ranges, and for a recent CVE today's answer leans toward the fix.
# The mirror answers as the registry would have while the flaw was unpublished,
# which is what the apt side has always done with its snapshot serial.
#
# The runtime comes from the same mirror. Ubuntu's own nodejs is 18.19 on
# noble, 12.22 on jammy and 8.9 on bionic, and a current npm advisory needs 20
# or later - so there is no apt package that can serve, and baking node into a
# per-ecosystem image would mean one 2.3 GB image per ecosystem forever.
#
# fixed_subject/fixed_version install a second build of the same app with that
# one dependency overridden, served on control_port. The job's control run
# points the same PoC at it and requires it to fail.
set -euo pipefail

registry="${1:?registry_url}"
node_version="${2:?node_version}"
node_sha256="${3:?node_sha256}"
app_archive="${4:?app_archive}"
app_dir="${5-}"
build="${6:?build}"
start="${7:?start}"
port="${8:?port}"
fixed_subject="${9-}"
fixed_version="${10-}"
control_port="${11-0}"

ARTIFACTS=/var/lib/xentry/artifacts
APP=/srv/app
FIXED=/srv/app-fixed
SRC=/srv/app-src
RUN_USER=xentry-app
PREFIX=/usr/local/node

[[ "$registry" =~ ^http://[0-9.]+:[0-9]+/$ ]] || { echo "refused registry_url: $registry" >&2; exit 2; }
[[ "$node_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "refused node_version" >&2; exit 2; }
[[ "$node_sha256" =~ ^[0-9a-f]{64}$ ]] || { echo "refused node_sha256" >&2; exit 2; }
case "$app_archive" in
  "$ARTIFACTS"/*.tar.gz) ;;
  *) echo "refused archive path: $app_archive" >&2; exit 2 ;;
esac
[ -f "$app_archive" ] || { echo "missing archive: $app_archive" >&2; exit 2; }
if [ -n "$app_dir" ]; then
  case "$app_dir" in
    /*|*..*) echo "refused app_dir: $app_dir" >&2; exit 2 ;;
    *) [[ "$app_dir" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || {
         echo "refused app_dir: $app_dir" >&2; exit 2; } ;;
  esac
fi
case "$build" in next-build) ;; *) echo "refused build: $build" >&2; exit 2 ;; esac
case "$start" in next-start) ;; *) echo "refused start: $start" >&2; exit 2 ;; esac
[[ "$port" =~ ^[0-9]{2,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] \
  || { echo "refused port: $port" >&2; exit 2; }
if [ -n "$fixed_subject" ]; then
  [[ "$fixed_subject" =~ ^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$ ]] \
    || { echo "refused fixed_subject: $fixed_subject" >&2; exit 2; }
  [[ "$fixed_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
    || { echo "refused fixed_version: $fixed_version" >&2; exit 2; }
  [[ "$control_port" =~ ^[0-9]{2,5}$ ]] && [ "$control_port" -ne "$port" ] \
    || { echo "refused control_port: $control_port" >&2; exit 2; }
fi

mkdir -p /var/lib/xentry
rm -f /var/lib/xentry/setup-npm.done
rm -rf "$APP" "$FIXED" "$SRC" "$PREFIX"
mkdir -p "$SRC" "$PREFIX"

# 1. The runtime, from the mirror, checked against the digest the host pinned.
archive=/tmp/node.tar.xz
tarball="node-${node_version}-linux-x64.tar.xz"
curl -fsS --retry 3 -o "$archive" "${registry}nodejs/${node_version}/${tarball}"
echo "$node_sha256  $archive" | sha256sum -c -
tar -C "$PREFIX" --strip-components=1 -xf "$archive"
rm -f "$archive"
export PATH="$PREFIX/bin:$PATH"
# On every account's PATH, not just this script's. readiness-npm.sh runs as
# xentry-guest and reads the installed version with `node -e`; with the runtime
# only under $PREFIX/bin it failed with "node: command not found" after a
# provision that had otherwise worked all the way through two builds. The
# tree stays where it is so a reader can see exactly what was installed; only
# the entry points are linked.
install -d -m 0755 /usr/local/bin
for tool in "$PREFIX"/bin/*; do
  ln -sf "$tool" "/usr/local/bin/$(basename "$tool")"
done
command -v node >/dev/null && command -v npm >/dev/null || {
  echo "the node tarball did not provide node and npm" >&2; exit 2; }
PATH=/usr/local/bin:/usr/bin:/bin node --version >/dev/null || {
  echo "node is not on a default PATH, so readiness would fail" >&2; exit 2; }
echo "node $(node --version), npm $(npm --version) from the job mirror"

# 2. The lab's application source, unpacked once and installed twice. Once,
#    deliberately: the two builds have to differ in one dependency version and
#    in nothing else, or the control run compares two things instead of one.
tar -xzf "$app_archive" -C "$SRC"
src_root="$SRC"
if [ -n "$app_dir" ]; then
  if [ -d "$SRC/$app_dir" ]; then
    src_root="$SRC/$app_dir"
  else
    found=$(find "$SRC" -mindepth 2 -maxdepth 2 -type d -name "$(basename "$app_dir")" | head -1)
    [ -n "$found" ] || { echo "app_dir not in the archive: $app_dir" >&2; exit 2; }
    src_root="$found"
  fi
fi
[ -f "$src_root/package.json" ] || { echo "no package.json in $app_dir" >&2; exit 2; }

# 3. The account that owns and runs the app. Created before any install: the
#    build runs the lab author's JavaScript and has no business doing that as
#    root, and it is not the PoC's actor either, so the exploit cannot simply
#    write the app's files.
id -u "$RUN_USER" >/dev/null 2>&1 \
  || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin "$RUN_USER"

install_tree() {
  local dest="$1" unit="$2" listen="$3" subject="$4" version="$5"
  mkdir -p "$dest"
  # .npmrc is written by us, not copied: a lab could point the registry
  # elsewhere or relax integrity checking, and the dependency set this job
  # resolves has to be the one the mirror's date admits.
  # The lab's own lockfiles are left behind along with its .npmrc. A lockfile
  # pins versions, and which versions a range means is the one thing this job
  # decides: an author's lockfile written last week can name the patched
  # build, and the mirror would serve it because it is old enough. npm also
  # rewrites a lockfile's `resolved` onto the configured registry, so the
  # install would not even fail loudly - it would quietly be their resolution
  # instead of ours.
  tar -C "$src_root" --exclude=.npmrc --exclude=.yarnrc --exclude=.yarnrc.yml \
      --exclude=package-lock.json --exclude=npm-shrinkwrap.json \
      --exclude=yarn.lock --exclude=pnpm-lock.yaml \
      --exclude=node_modules --exclude=.git -cf - . | tar -C "$dest" -xf -
  cat > "$dest/.npmrc" <<NPMRC
registry=${registry}npm/
audit=false
fund=false
NPMRC
  # The control build overrides one dependency. Written into package.json
  # rather than passed on a command line, so the lockfile records it.
  if [ -n "$subject" ]; then
    node -e '
const fs = require("fs");
const [file, name, version] = process.argv.slice(1);
const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
  if (pkg[field] && pkg[field][name]) pkg[field][name] = version;
}
if (!(pkg.dependencies || {})[name]) {
  console.error(name + " is not a dependency of this lab");
  process.exit(1);
}
fs.writeFileSync(file, JSON.stringify(pkg, null, 2));
' "$dest/package.json" "$subject" "$version"
  fi
  chown -R "$RUN_USER":"$RUN_USER" "$dest"
  # npm verifies every tarball against the integrity the index carried, so a
  # corrupted or substituted tarball fails here rather than reaching runtime.
  ( cd "$dest"
    runuser -u "$RUN_USER" -- env PATH="$PATH" npm install --ignore-scripts --no-audit --no-fund
    case "$build" in
      next-build) runuser -u "$RUN_USER" -- env PATH="$PATH" npx --no-install next build ;;
    esac
  )
  chown -R "$RUN_USER":"$RUN_USER" "$dest"
  local exec_start
  case "$start" in
    next-start) exec_start="$PREFIX/bin/npx --no-install next start -p $listen" ;;
  esac
  cat > "/etc/systemd/system/$unit.service" <<UNIT
[Unit]
Description=xentry application target ($unit)
After=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$dest
Environment=NODE_ENV=production
Environment=HOSTNAME=0.0.0.0
Environment=PATH=$PREFIX/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$exec_start
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$unit.service"
}

install_tree "$APP" xentry-app "$port" "" ""
if [ -n "$fixed_subject" ]; then
  install_tree "$FIXED" xentry-app-fixed "$control_port" "$fixed_subject" "$fixed_version"
fi

# Both ports have to be served, and served where the attacker can reach them.
# A build that compiles and then exits, or a server that binds 127.0.0.1
# because HOSTNAME did not take, would otherwise leave readiness to time out
# five minutes later against localhost and the PoC to fail as if it were wrong.
reachable_on() {
  ss -Hltn 2>/dev/null | awk -v port="$1" '{
    for (i = 1; i <= NF; i++)
      if ($i ~ (":" port "$")) {
        sub(":" port "$", "", $i); sub("%.*", "", $i)
        if ($i !~ /^(127\.[0-9.]+|\[?::1\]?)$/) { print $i; found = 1; exit }
        break
      }
  } END { exit(found ? 0 : 1) }'
}
wait_for_port() {
  local want="$1" unit="$2" deadline=$((SECONDS + 300)) where
  while ! where="$(reachable_on "$want")"; do
    [ "$SECONDS" -lt "$deadline" ] || {
      echo "port $want is not reachably served by $unit" >&2
      ss -Hltn >&2 || true
      systemctl --no-pager --lines=40 status "$unit.service" >&2 || true
      exit 1; }
    sleep 2
  done
  printf 'port %s served by %s on %s\n' "$want" "$unit" "$where"
}

wait_for_port "$port" xentry-app
[ -z "$fixed_subject" ] || wait_for_port "$control_port" xentry-app-fixed

: > /var/lib/xentry/setup-npm.done
