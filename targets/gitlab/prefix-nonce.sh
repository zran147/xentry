#!/usr/bin/env bash
# Prefix the GitLab nonce with an invalid % sequence so the pinned PoC's
# pre-auth file-read error echoes the file content. Runs as root.
# Args: nonce_path
set -euo pipefail
nonce_path="${1:?nonce_path}"
case "$nonce_path" in
  /*) ;;
  *) echo "nonce_path must be absolute" >&2; exit 2 ;;
esac
case "$nonce_path" in
  *[[:space:]]*) echo "nonce_path must not contain whitespace" >&2; exit 2 ;;
esac
tmp="${nonce_path}.prefix"
printf '%%zz' > "$tmp"
cat "$nonce_path" >> "$tmp"
printf ' xentry-nonce-sha256:' >> "$tmp"
sha256sum "$nonce_path" | cut -d' ' -f1 >> "$tmp"
printf '\n' >> "$tmp"
chown git:git "$tmp"
chmod 0640 "$tmp"
mv "$tmp" "$nonce_path"
printf 'gitlab-nonce-prefixed\n'
