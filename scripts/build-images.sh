#!/usr/bin/env bash
# Validate image manifests or build the pinned Ubuntu image profiles.
# Usage: scripts/build-images.sh [--dry-run|--execute] [--only IMAGE]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFESTS="${XENTRY_IMAGE_MANIFESTS:-$ROOT/config/image-manifests.yaml}"
CATALOG="${XENTRY_ARTIFACT_CATALOG:-$ROOT/config/artifacts.yaml}"
IMAGE_DIR="${XENTRY_IMAGE_DIR:-$ROOT/var/images}"
MODE="${1:---dry-run}"
shift || true
UV_BIN="${UV_BIN:-$(command -v uv || echo "$HOME/.local/bin/uv")}"

case "$MODE" in
  --dry-run|--execute) ;;
  *) echo "usage: $0 [--dry-run|--execute] [--only IMAGE]" >&2; exit 2 ;;
esac

cd "$ROOT"
exec "$UV_BIN" run --extra app python "$ROOT/scripts/build-images.py" \
  --manifests "$MANIFESTS" \
  --catalog "$CATALOG" \
  --image-dir "$IMAGE_DIR" \
  --mode "${MODE#--}" \
  "$@"
