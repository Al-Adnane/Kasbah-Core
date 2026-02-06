#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"

if [ ! -f cat/.bootstrap_key ]; then
  echo "FAIL: cat/.bootstrap_key not found. Run ./cat/06_get_bootstrap_key.sh first."
  exit 1
fi

KEY="$(cat cat/.bootstrap_key)"

echo "== Audit verify =="
curl -sS "$BASE/api/rtp/audit/verify" -H "Authorization: Bearer $KEY"
echo
