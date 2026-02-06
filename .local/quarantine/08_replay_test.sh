#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"

if [ ! -f cat/.bootstrap_key ]; then
  echo "FAIL: cat/.bootstrap_key not found. Run ./cat/06_get_bootstrap_key.sh first."
  exit 1
fi

KEY="$(cat cat/.bootstrap_key)"

TMP="$(mktemp -t kasbah_decide.XXXXXX.json)"
trap 'rm -f "$TMP"' EXIT

echo "== Decide (authorized) =="
curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"replay-test","usage":{"tokens":0,"cost":0,"agent_id":"replay-test"},"signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99}}' \
  > "$TMP"

head -c 500 "$TMP"
echo
echo

T="$(python3 - <<PY
import json
p="$TMP"
d=json.load(open(p,"r",encoding="utf-8"))
t=d.get("ticket") or {}
# the API returns ticket object; we need the signed ticket payload for consume.
# If you later switch to a JWT string, adapt here.
print(json.dumps(t))
PY
)"

if [[ -z "$T" ]]; then
  echo "FAIL: could not extract ticket object"
  exit 1
fi

echo "OK: extracted ticket object bytes=${#T}"
echo

echo "== Consume #1 (expected valid=true) =="
curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":$T,\"tool\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"replay-test\"}}" ; echo

echo
echo "== Consume #2 (expected valid=false: replay) =="
curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":$T,\"tool\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"replay-test\"}}" ; echo
