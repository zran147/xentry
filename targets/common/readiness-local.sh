#!/usr/bin/env bash
# A pipeline ending in `grep -q` is a trap under `set -o pipefail`: grep exits
# at its first match and closes the pipe, the writer dies of SIGPIPE, and
# pipefail reports 141 for a pipeline that FOUND what it was looking for. It
# only bites once the writer exceeds the 64KB pipe buffer, so it is invisible
# on small inputs and intermittent on growing ones. `grep -c` reads to the end,
# so there is no early close and no signal.
# Readiness for a local privesc job. Runs as xentry-guest ON THE TARGET.
# Args: package expected_version
#
# No port: nothing listens for a local PoC. What is checked instead is that
# the evidence channel is CLOSED to this actor before anything runs - an open
# one would make the whole observation worthless - and that the installed
# package is the version the advisory named.
set -euo pipefail
package="${1-}"
expected="${2-}"
cve_id="${3-}"

test -f /var/lib/xentry/setup-generic.done
test "$(id -u)" -ne 0 || { echo "the actor is already root" >&2; exit 1; }
test -e /dev/ttyS0 || { echo "no serial console to carry evidence" >&2; exit 1; }
test ! -w /dev/ttyS0 || { echo "this actor can already write the console" >&2; exit 1; }
test ! -r /root || { echo "this actor can already read /root" >&2; exit 1; }
command -v gcc >/dev/null || echo "note: no gcc; a C PoC will fail to build" >&2

if [ -n "$package" ] && [ -n "$expected" ]; then
  [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || { echo "bad package" >&2; exit 2; }
  [[ "$expected" =~ ^[0-9][0-9.]*$ ]] || { echo "bad expected_version" >&2; exit 2; }
  installed="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)"
  [ -n "$installed" ] || { echo "$package is not installed" >&2; exit 1; }
  case "${installed#*:}" in
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

# If the setup step installed a kernel, the running one must BE it. GRUB picks
# the newest entry, which is not necessarily the one that was installed, so
# this is the assertion that a job reporting on kernel X ran on kernel X.
if [ -f /var/lib/xentry/kernel.want ]; then
  want="$(sed -n 's/^kernel=//p' /var/lib/xentry/kernel.want | tail -1)"
  running="$(uname -r)"
  [ -n "$want" ] || { echo "kernel.want is empty" >&2; exit 1; }
  test "$running" = "$want" || {
    echo "running kernel $running is not the installed $want" >&2; exit 1; }
  printf 'booted the installed kernel %s\n' "$running"
fi
printf 'local target ready: channel closed to %s\n' "$(id -un)"
