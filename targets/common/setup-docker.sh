#!/usr/bin/env bash
# Build and run the vulnerable environment from the PoC author's own Dockerfile.
# Runs as root in the target VM.
# Args: apt_proxy_url suite sources_format archive check_valid_until
#       oci_mirror_url app_archive dockerfile_dir ports
#
# This exists because a PoC's Dockerfile is often the only description of the
# vulnerable environment its author ever wrote - blasty's CVE-2021-41773 is a
# compose file, four vendored .debs and a config, and nothing else says how the
# pieces fit. What it costs is provenance: the base image is whatever its tag
# points at today, and anything the Dockerfile apt-installs comes from the live
# archive rather than the job's dated one. The rest of this harness pins both.
# So this path is the PoC author's reproducibility, not ours, and the record
# says which image digest was actually used so a reader can tell them apart.
#
# No command comes from the model here either. The Dockerfile is the author's,
# run by `docker build` with no arguments this script did not choose, and the
# only app-supplied values are a directory inside the staged archive and the
# ports to publish - both checked below.
set -euo pipefail

proxy_url="${1:?apt_proxy_url}"
suite="${2:?suite}"
sources_format="${3-deb822}"
archive="${4-ubuntu}"
check_valid_until="${5-1}"
oci_url="${6:?oci_mirror_url}"
app_archive="${7:?app_archive}"
dockerfile_dir="${8-}"
ports="${9-}"
# The address the job's apt proxy answers on, for a container's own apt. The
# image's sources.list names deb.debian.org (or archive.ubuntu.com) and
# `docker build` takes no volume flag, so the file cannot be rewritten - the
# only way in is to BE that host. The second listener runs on port 80, which is
# the port that file already asks for, and --add-host is the one docker build
# flag that can redirect a name.
container_apt_host="${10-}"

[[ "$proxy_url" =~ ^http://[0-9.]+:[0-9]+$ ]] || { echo "bad apt_proxy_url" >&2; exit 2; }
[[ "$oci_url" =~ ^http://[0-9.]+:[0-9]+$ ]] || { echo "bad oci_mirror_url" >&2; exit 2; }
[[ "$suite" =~ ^[a-z]+$ ]] || { echo "bad suite" >&2; exit 2; }
case "$app_archive" in
  /var/lib/xentry/artifacts/*) ;;
  *) echo "refused app archive: $app_archive" >&2; exit 2 ;;
esac
[ -f "$app_archive" ] || { echo "missing app archive: $app_archive" >&2; exit 2; }
# A directory inside the archive, never a path out of it.
if [ -n "$dockerfile_dir" ]; then
  case "$dockerfile_dir" in
    /*|*..*) echo "refused dockerfile dir: $dockerfile_dir" >&2; exit 2 ;;
  esac
  [[ "$dockerfile_dir" =~ ^[A-Za-z0-9._/-]+$ ]] || {
    echo "refused dockerfile dir: $dockerfile_dir" >&2; exit 2; }
fi
for port in $ports; do
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo "refused port: $port" >&2; exit 2; }
done
[ -n "$ports" ] || { echo "no port to publish" >&2; exit 2; }

mkdir -p /var/lib/xentry /etc/apt/sources.list.d /etc/apt/apt.conf.d
: > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/ubuntu.sources
case "$archive" in
  ubuntu) components="main restricted universe multiverse" ;;
  debian) components="main contrib non-free" ;;
  *) echo "bad archive: $archive" >&2; exit 2 ;;
esac
if [ "$sources_format" = deb822 ]; then
  cat > /etc/apt/sources.list.d/xentry.sources <<EOF
Types: deb
URIs: ${proxy_url}/${archive}
Suites: ${suite}
Components: ${components}
Trusted: yes
EOF
else
  echo "deb [trusted=yes] ${proxy_url}/${archive} ${suite} ${components}" \
    > /etc/apt/sources.list
fi
[ "$check_valid_until" = 1 ] || printf 'Acquire::Check-Valid-Until "false";\n' \
  > /etc/apt/apt.conf.d/99xentry-valid-until

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io

# The guest reaches Docker Hub only through the host's mirror. registry-mirrors
# applies to docker.io and nothing else, which is the whole reason this is
# serveable at all; insecure-registries because the mirror is plain HTTP on a
# network with no route off the bridge.
host=${oci_url#http://}
install -d -m 755 /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "registry-mirrors": ["${oci_url}"],
  "insecure-registries": ["${host}"],
  "iptables": false,
  "bridge": "none"
}
EOF
systemctl restart docker
systemctl is-active docker >/dev/null || { journalctl -u docker -n 40 --no-pager >&2; exit 1; }

BUILD=/opt/xentry-app
rm -rf "$BUILD"
mkdir -p "$BUILD"
tar -C "$BUILD" --strip-components=1 -xf "$app_archive"
context="$BUILD/${dockerfile_dir}"
[ -f "$context/Dockerfile" ] || {
  echo "no Dockerfile at ${dockerfile_dir:-the repository root}" >&2
  echo "--- Dockerfiles in the archive ---" >&2
  find "$BUILD" -maxdepth 4 -name Dockerfile | sed "s#^$BUILD/##" | sed 's/^/  /' >&2
  exit 1
}

# --network host so the build's own apt-get reaches the job's proxy rather than
# nothing: docker's default bridge is off above, because a second NAT inside a
# network with forward=none only breaks the route to the host's mirrors.
# The output is kept so a failure can be explained rather than quoted. The
# commonest one by far: the author's Dockerfile runs its own `apt-get update`,
# and --network host puts the build on the guest's network - where the only
# archive that answers is this job's proxy, reached through the guest's
# /etc/apt/sources.list. The CONTAINER has its own sources.list from the base
# image, pointing at deb.debian.org, which nothing here can route to. apt then
# exits 100 and the step used to surface `returned a non-zero code: 100`,
# which reads as a broken harness. CVE-2025-32433's job died exactly there.
build_log=/var/lib/xentry/docker-build.log
hosts=()
if [ -n "$container_apt_host" ]; then
  [[ "$container_apt_host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
    echo "refused container_apt_host: $container_apt_host" >&2; exit 2; }
  # Both Debian names and both Ubuntu ones: a released suite's dated Release
  # carries no Valid-Until, so it does not expire - measured on bookworm at
  # 20250415 (none) against sid at the same serial (Valid-Until 21 Apr 2025).
  # archive.ubuntu.com and security.ubuntu.com share the /ubuntu prefix;
  # Debian needs /debian and /debian-security, which the proxy now routes.
  for name in deb.debian.org security.debian.org archive.ubuntu.com \
              security.ubuntu.com ports.ubuntu.com; do
    hosts+=(--add-host "$name:$container_apt_host")
  done
  echo "pointing the container's apt at $container_apt_host:80"
fi
if ! docker build --network host "${hosts[@]+"${hosts[@]}"}" -t xentry-target "$context" \
    2>&1 | tee "$build_log"; then
  if grep -qiE "code: 100|Could not resolve|Temporary failure resolving|Failed to fetch" \
      "$build_log"; then
    echo >&2
    echo "the PoC's own Dockerfile installs packages from the internet, and" >&2
    echo "this guest has no route to one: the only archive it can reach is" >&2
    echo "this job's proxy, and the container's sources.list points elsewhere." >&2
    echo "A Dockerfile that apt-installs at build time cannot be built here -" >&2
    echo "approve a prebuilt artifact, or use a CVE whose package the dated" >&2
    echo "archive carries." >&2
    # The two halves that would have to agree if this were ever to work, so
    # the reader can see whether they do: what the container is built FROM,
    # and which archive this job's proxy serves.
    echo >&2
    base=$(grep -im1 '^[[:space:]]*FROM[[:space:]]' "$context/Dockerfile" 2>/dev/null || true)
    echo "  the Dockerfile's base: ${base:-unknown}" >&2
    echo "  this job's apt proxy:  $archive $suite at the advisory's serial" >&2
    echo "  the container's own sources.list is the one apt reads, and it" >&2
    echo "  points at the distro's public archive, not at that proxy." >&2
  fi
  exit 1
fi

publish=""
for port in $ports; do publish="$publish -p ${port}:${port}"; done
# shellcheck disable=SC2086 - the ports are validated above and must word-split
docker run -d --network host --name xentry-target $publish xentry-target

# Which image this actually ran, so a reader can tell the author's
# reproducibility from ours. The base tag is whatever it pointed at today.
docker image inspect xentry-target --format '{{.Id}}' > /var/lib/xentry/image-id.txt
docker image inspect xentry-target --format '{{range .RootFS.Layers}}{{.}}{{"\n"}}{{end}}' \
  >> /var/lib/xentry/image-id.txt
printf 'built and ran %s on ports %s\n' "$(cat /var/lib/xentry/image-id.txt | head -1)" "$ports"
touch /var/lib/xentry/setup-docker.done
