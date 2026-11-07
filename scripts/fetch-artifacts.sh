#!/usr/bin/env bash
# Validate or download the pinned artifact catalog (Gate G).
# Usage: scripts/fetch-artifacts.sh [--dry-run|--download]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${XENTRY_ARTIFACT_CATALOG:-$ROOT/config/artifacts.yaml}"
ARTIFACT_DIR="${XENTRY_ARTIFACT_DIR:-$ROOT/var/artifacts}"
MODE="${1:---dry-run}"
UV_BIN="${UV_BIN:-$(command -v uv || echo "$HOME/.local/bin/uv")}"

case "$MODE" in
  --dry-run|--download) ;;
  *) echo "usage: $0 [--dry-run|--download]" >&2; exit 2 ;;
esac

cd "$ROOT"
exec "$UV_BIN" run --extra app python "$ROOT/scripts/fetch-artifacts.py" \
  --catalog "$CATALOG" \
  --out "$ARTIFACT_DIR" \
  --mode "${MODE#--}"
