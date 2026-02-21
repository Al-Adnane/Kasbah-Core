#!/usr/bin/env sh
set -eu

DIR="/app/.kasbah"
MAX=$((10 * 1024 * 1024))  # 10MB
KEEP=5

rotate_one() {
  f="$1"
  [ -f "$f" ] || return 0
  sz="$(wc -c < "$f" | tr -d ' ')"
  [ "$sz" -lt "$MAX" ] && return 0

  ts="$(date +%Y%m%d_%H%M%S)"
  mv "$f" "${f}.${ts}"
  : > "$f"

  # Keep only newest $KEEP rotated files
  ls -1t "${f}."* 2>/dev/null | awk "NR>${KEEP}" | xargs -r rm -f
}

rotate_one "$DIR/rtp_audit.log"
rotate_one "$DIR/decisions.jsonl"
rotate_one "$DIR/rtp_used_jti.jsonl"
rotate_one "$DIR/rtp_signal_state.jsonl"
rotate_one "$DIR/ledger.json"

echo "rotated"
