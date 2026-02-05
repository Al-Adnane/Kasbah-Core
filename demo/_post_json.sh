#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
PATH_SUFFIX="${1:?usage: _post_json.sh /path 'JSON_PAYLOAD'}"
PAYLOAD="${2:?usage: _post_json.sh /path 'JSON_PAYLOAD'}"

TRIES="${TRIES:-25}"
SLEEP="${SLEEP:-0.2}"
TIMEOUT="${TIMEOUT:-2}"

tmp="/tmp/kasbah_resp.json"

i=0
while true; do
  i=$((i+1))
  curl --max-time "$TIMEOUT" -sS -X POST "$BASE$PATH_SUFFIX" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" > "$tmp" 2>/dev/null || true

  if python3 -c 'import json; json.load(open("/tmp/kasbah_resp.json"))' >/dev/null 2>&1; then
    cat "$tmp"
    exit 0
  fi

  if [ "$i" -ge "$TRIES" ]; then
    echo "FAIL: non-JSON after $TRIES tries: POST $PATH_SUFFIX" >&2
    echo "---- raw ----" >&2
    sed -n '1,200p' "$tmp" >&2 || true
    exit 1
  fi
  sleep "$SLEEP"
done
