#!/usr/bin/env bash
# Readiness for an application-package target: the ports must accept, and the
# version actually installed is read out of the tree and reported.
# Runs as xentry-guest. Args: ports package
#
# What this can and cannot establish is worth being exact about. The lab's
# package.json declares ranges; which versions those ranges resolved to was
# decided by the job's registry mirror, which served only what existed before
# the advisory. So the version here is a *measurement* of that resolution, not
# a check against something the harness pinned in advance - the mirror's date
# is the pin, and it is recorded with the job.
#
# The one thing this does assert is the control build: if /srv/app-fixed
# exists, the subject package must resolve differently there. Two trees at the
# same version would make a failed control run look like proof when it is two
# identical runs with different luck.
set -euo pipefail
ports="${1:?ports}"
package="${2-}"

APP=/srv/app
FIXED=/srv/app-fixed
# The runtime came from the job's mirror into /usr/local/node and setup-npm.sh
# links its entry points into /usr/local/bin. Naming the prefix here too means
# this step does not depend on that linking having worked.
PATH=/usr/local/node/bin:$PATH
export PATH

for port in $ports; do
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo "bad port: $port" >&2; exit 2; }
done
test -f /var/lib/xentry/setup-npm.done

installed_version() {
  local tree="$1" manifest="$1/node_modules/$package/package.json"
  [ -f "$manifest" ] || { echo "$package is not installed in $tree" >&2; exit 1; }
  node -e '
const fs = require("fs");
process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).version);
' "$manifest"
}

if [ -n "$package" ]; then
  [[ "$package" =~ ^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$ ]] \
    || { echo "bad package: $package" >&2; exit 2; }
  affected="$(installed_version "$APP")"
  printf '%s@%s resolved in the target build\n' "$package" "$affected"
  if [ -d "$FIXED" ]; then
    fixed="$(installed_version "$FIXED")"
    [ "$affected" != "$fixed" ] || {
      echo "the control build has $package@$fixed, the same as the target build;" >&2
      echo "the two runs would differ in nothing" >&2; exit 1; }
    printf 'control differs by %s: %s -> %s\n' "$package" "$affected" "$fixed"
  fi
fi

deadline=$((SECONDS + 600))
for port in $ports; do
  until timeout 2 bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || { echo "port $port never accepted" >&2; exit 1; }
    sleep 2
  done
  printf 'port %s accepting\n' "$port"
done
printf 'npm target ready\n'
