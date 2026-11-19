#!/usr/bin/env bash
# Unpack a derived target's PoC on the attacker and build it if it declares a
# build the image can do. Runs as xentry-guest.
# Args: poc_archive poc_sha256 poc_dir entrypoint
#
# There is no network here, so nothing is downloaded: a PoC whose dependencies
# are not in the attacker image fails, which is the honest outcome.
set -euo pipefail
archive="${1:?poc_archive}"
expected_sha="${2:?poc_sha256}"
poc_dir="${3:?poc_dir}"
entrypoint="${4:?entrypoint}"

case "$entrypoint" in
  /*|*..*) echo "refused entrypoint: $entrypoint" >&2; exit 2 ;;
esac
test -f "$archive"
echo "$expected_sha  $archive" | sha256sum -c -
rm -rf "$poc_dir"
mkdir -p "$poc_dir"
tar -xzf "$archive" -C "$poc_dir" --strip-components=1

# The entrypoint is required AFTER the build, not before it. A compiled PoC's
# entrypoint is the binary the build produces, which does not exist yet:
# blasty/CVE-2021-3156's Makefile is `gcc -std=c99 -o sudo-hax-me-a-sandwich
# hax.c`, so requiring the file here refused the correct answer and accepting
# hax.c instead left the run step doing `exec ./hax.c`.
cd "$poc_dir"
# Build only what the entrypoint needs building. A Makefile at the root of a
# PoC repository is usually the *lab's* - briskets/CVE-2026-126187-poc has one
# whose default target is a help text and whose real targets run `docker build`
# - so `make` there failed the job with "make: command not found" for a PoC
# that is a single dependency-free Python file. An interpreted entrypoint has
# nothing to compile, and not running a stranger's build recipe for no reason
# is the same instinct that keeps their Dockerfile unexecuted.
case "$entrypoint" in
  *.py|*.sh|*.rb|*.pl|*.js|*.php)
    test -f "$entrypoint" || { echo "no $entrypoint in this repository" >&2; exit 1; }
    printf 'no build: %s is interpreted\n' "$entrypoint" ;;
  *)
    if [ -f Makefile ] || [ -f makefile ]; then
      command -v make >/dev/null || {
        echo "this PoC needs make and the image has none" >&2; exit 1; }
      make
    elif [ -f go.mod ]; then
      # There is no network in the guest, so a module that is not vendored
      # cannot be fetched. Saying which of the three things is wrong beats
      # "go build failed": no toolchain, no vendor directory, or a build error.
      command -v go >/dev/null || {
        echo "this PoC is written in Go and the image carries no toolchain." >&2
        echo "Name golang-go in setup_packages, or approve a built binary." >&2
        exit 1; }
      if [ -d vendor ]; then
        GOFLAGS=-mod=vendor GOPROXY=off go build ./... || {
          echo "the vendored Go build failed; its output is above" >&2; exit 1; }
      else
        GOPROXY=off GOFLAGS=-mod=mod go build ./... || {
          echo "this PoC needs Go modules it does not vendor, and the guest has" >&2
          echo "no network to fetch them. Vendor them upstream, or approve a" >&2
          echo "built binary as an artifact." >&2
          exit 1; }
      fi
    elif [ -f pom.xml ] || [ -f build.gradle ] || [ -f build.gradle.kts ]; then
      # Deliberately not attempted. Maven and Gradle resolve from
      # repo.maven.apache.org at build time, and this harness has a dated
      # proxy for apt, npm, pypi and container images - not for Maven. Running
      # the build would either reach the live internet from a guest that must
      # not have it, or fail with a dependency error that reads like a broken
      # PoC. CVE-2023-46604's PoC is this shape: one Main.java in a Maven tree.
      echo "this PoC builds with Maven or Gradle, which resolve dependencies" >&2
      echo "from the live internet at build time. The guest has no network and" >&2
      echo "this harness has no dated Maven proxy, so approve the built .jar" >&2
      echo "as an artifact instead." >&2
      exit 1
    fi ;;
esac
# Now it has to exist and has to be runnable. Saying what the build DID
# produce is the difference between a diagnosis and "cannot execute binary
# file": the usual cause is an entrypoint naming the source rather than the
# binary the Makefile writes.
if [ ! -f "$entrypoint" ]; then
  echo "the build produced no $entrypoint. Executable files here:" >&2
  find . -maxdepth 2 -type f -perm -u+x -printf '  %p\n' 2>/dev/null >&2 || true
  # The commonest reason, named: a single C file and no Makefile. The flags
  # are in the README rather than in the repository - CVE-2016-5195's says
  # `gcc -pthread dirty.c -o dirty -lcrypt` - and this harness will not guess
  # them, because a wrong link line is a compile error attributed to the CVE.
  sources=$(find . -maxdepth 2 -name '*.c' | head -5)
  if [ -n "$sources" ] && [ ! -f Makefile ] && [ ! -f makefile ]; then
    echo "there is C source here and no Makefile:" >&2
    printf '  %s\n' $sources >&2
    echo "its compiler flags live in the README, which this harness does not" >&2
    echo "read as a build recipe. Approve a built binary as an artifact." >&2
  fi
  exit 1
fi
chmod 0755 "$entrypoint"
printf 'generic poc ready: %s\n' "$entrypoint"
