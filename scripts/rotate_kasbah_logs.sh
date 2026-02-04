#!/bin/sh
set -eu

KASBAH_DIR="${KASBAH_DIR:-/app/.kasbah}"
MAX_MB="${KASBAH_LOG_MAX_MB:-10}"          # rotate threshold
KEEP="${KASBAH_LOG_KEEP:-10}"              # keep N rotated copies
DATE="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$KASBAH_DIR"

rotate_one () {
  f="$1"
  [ -f "$f" ] || return 0
  # size in MB (portable-ish)
  sz_bytes="$(wc -c < "$f" 2>/dev/null || echo 0)"
  sz_mb=$(( (sz_bytes + 1048575) / 1048576 ))
  if [ "$sz_mb" -lt "$MAX_MB" ]; then
    return 0
  fi

  mv "$f" "$f.$DATE"
  : > "$f"

  # keep newest KEEP files, delete older
  # shellcheck disable=SC2012
  ls -1t "$f".20* 2>/dev/null | awk "NR>$KEEP {print}" | xargs -r rm -f
}

rotate_one "$KASBAH_DIR/rtp_audit.log"
rotate_one "$KASBAH_DIR/rtp_used_jti.jsonl"
rotate_one "$KASBAH_DIR/decisions.jsonl"
rotate_one "$KASBAH_DIR/ledger.json"
rotate_one "$KASBAH_DIR/rtp_signal_state.jsonl"

echo "[OK] rotation complete @ $DATE"
