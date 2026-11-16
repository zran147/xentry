#!/usr/bin/env bash
# Point apt at this job's pinned snapshot mirror. Runs as root in the VM.
# Args: apt_proxy_url suite
#
# The guest has no route off its own bridge, so this host service is the only
# archive it can reach, and the service rewrites every path onto one snapshot
# serial - the guest cannot ask for a different one. Transport is plain HTTP on
# an isolated bridge; the archive signature is still checked against the
# shipped Ubuntu keyring, which is the part that matters.
set -euo pipefail

proxy_url="${1:?apt_proxy_url}"
suite="${2:?suite}"

install -d -m 755 /etc/apt/sources.list.d /etc/apt/apt.conf.d
: > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/ubuntu.sources
cat > /etc/apt/sources.list.d/xentry-snapshot.sources <<EOF
Types: deb
URIs: ${proxy_url}/ubuntu
Suites: ${suite} ${suite}-updates ${suite}-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF

cat > /etc/apt/apt.conf.d/99xentry <<'EOF'
Acquire::Retries "3";
Acquire::http::Timeout "60";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOF

export DEBIAN_FRONTEND=noninteractive
apt-get update
# Recorded in the step output, so the audit trail says which snapshot this
# machine was built from.
echo "xentry: apt pinned to ${proxy_url}/ubuntu suites ${suite},-updates,-security"
