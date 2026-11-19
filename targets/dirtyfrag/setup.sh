#!/usr/bin/env bash
# Dirty Frag target setup: install the pinned 6.17.0-23 kernel. Runs as root.
# Args: proxy_url image_artifact_id image_sha256 modules_artifact_id modules_sha256
set -euo pipefail
proxy_url="${1:?proxy_url}"
image_id="${2:?kernel_artifact_id}"
image_sha="${3:?kernel_sha256}"
modules_id="${4:?kernel_modules_artifact_id}"
modules_sha="${5:?kernel_modules_sha256}"
image_deb="/tmp/linux-image-6.17.0-23-generic.deb"
modules_deb="/tmp/linux-modules-6.17.0-23-generic.deb"

curl -fsS --retry 3 --connect-timeout 15 --max-time 300 \
  "$proxy_url/artifacts/$image_id" -o "$image_deb"
curl -fsS --retry 3 --connect-timeout 15 --max-time 300 \
  "$proxy_url/artifacts/$modules_id" -o "$modules_deb"
echo "$image_sha  $image_deb" | sha256sum -c -
echo "$modules_sha  $modules_deb" | sha256sum -c -

dpkg -i "$modules_deb" "$image_deb"
update-initramfs -u -k all
update-grub
printf 'kernel=6.17.0-23-generic\n' > /var/lib/xentry/setup-dirtyfrag.done
