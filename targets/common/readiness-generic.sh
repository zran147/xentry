#!/usr/bin/env bash
# A pipeline ending in `grep -q` is a trap under `set -o pipefail`: grep exits
# at its first match and closes the pipe, the writer dies of SIGPIPE, and
# pipefail reports 141 for a pipeline that FOUND what it was looking for. It
# only bites once the writer exceeds the 64KB pipe buffer, so it is invisible
# on small inputs and intermittent on growing ones. `grep -c` reads to the end,
# so there is no early close and no signal.
# Readiness for a derived target: the declared ports must accept locally, and
# the installed package must be the version the advisory named.
# Runs as xentry-guest. Args: ports package expected_version
#
# The version check is what separates "something is listening" from "the
# affected build is listening". Without it a derived job proves only that a
# PoC printed a nonce against some version of something.
set -euo pipefail
ports="${1:?ports}"
package="${2-}"
expected="${3-}"
cve_id="${4-}"

# Does the installed build already carry the fix for THIS CVE? Debian and
# Ubuntu cite the CVE id in the changelog entry of the update that fixed it,
# so this is a direct test for the one hole three ADR entries could only warn
# about: a stable series keeps the upstream version and backports the patch,
# so 2.4.48-3.1+deb11u1 satisfies every version check and reproduces nothing.
# Without this the job runs, the exploit fails, and the report says "did not
# reproduce" - indistinguishable from a PoC that does not work.
if [ -n "$package" ] && [ -n "$cve_id" ]; then
  [[ "$cve_id" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || { echo "bad cve_id" >&2; exit 2; }
  changelog="/usr/share/doc/$package/changelog.Debian.gz"
  if [ -f "$changelog" ]; then
    if [ "$(zcat "$changelog" | grep -c -- "$cve_id" || true)" -gt 0 ]; then
      echo "the installed $package names $cve_id in its changelog, so this" >&2
      echo "build carries the fix and the exploit would fail for that reason" >&2
      exit 1
    fi
    printf '%s does not name %s in its changelog\n' "$package" "$cve_id"
  else
    printf 'no changelog for %s; cannot check whether the fix is backported\n' "$package"
  fi
fi

for port in $ports; do
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo "bad port: $port" >&2; exit 2; }
done
# EITHER marker, and a message when neither is there. setup-docker.sh writes
# setup-docker.done, so a docker-provisioned target failed this line every
# time - and because a bare `test` under `set -e` prints nothing, the job
# reported only the runner's fallback, "readiness failed". Two jobs on
# kozmer/log4j-shell-poc died exactly that way with no detail at all.
# `ls A B` is an AND - it fails when EITHER is missing - so this is two tests
# joined by ||, which is the OR that was meant.
[ -f /var/lib/xentry/setup-generic.done ] ||
  [ -f /var/lib/xentry/setup-docker.done ] || {
  echo "no provisioning marker in /var/lib/xentry: expected setup-generic.done" >&2
  echo "or setup-docker.done, so the provisioning step did not finish" >&2
  ls -la /var/lib/xentry/ >&2 || true
  exit 1; }

if [ -n "$package" ] && [ -n "$expected" ]; then
  [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || { echo "bad package" >&2; exit 2; }
  [[ "$expected" =~ ^[0-9][0-9.]*$ ]] || { echo "bad expected_version" >&2; exit 2; }
  installed="$(dpkg-query -W -f '${Version}' "$package")"
  # Compare against the upstream part: the advisory never carries a Debian
  # epoch or a packaging suffix.
  upstream="${installed#*:}"
  case "$upstream" in
    # "$expected"[a-z]* is the UPSTREAM PATCH LEVEL, and without it this
    # check rejected the build it was asked to confirm: sudo CVE-2023-22809
    # resolved sudo 1.9.12, the archive carried 1.9.12p1-1 - which IS 1.9.12
    # patch 1 - and readiness failed the job with "does not match". Debian
    # spells several upstreams this way: sudo 1.9.17p2, openssh 9.1p1, openssl
    # 1.1.1w. It stays tight because a letter must follow the prefix
    # immediately, so 1.9.12 does not match 1.9.120.
    "$expected"|"$expected".*|"$expected"-*|"$expected"[a-z]*) ;;
    *) echo "installed $package $installed does not match $expected" >&2; exit 1 ;;
  esac
  printf '%s=%s matches %s\n' "$package" "$installed" "$expected"
fi

deadline=$((SECONDS + 300))
for port in $ports; do
  until timeout 2 bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || { echo "port $port never accepted" >&2; exit 1; }
    sleep 2
  done
  printf 'port %s accepting\n' "$port"
done
printf 'generic target ready\n'
