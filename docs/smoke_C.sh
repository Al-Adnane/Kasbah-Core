#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

RESP="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"smoke-C","signals":{"consistency":0.99,"pred_accuracy":0.99,"normality":0.10,"latency_score":0.99}}')"

DEC="$(printf '%s' "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("decision"))')"
JTI="$(printf '%s' "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("ticket",{}).get("jti",""))')"

echo "decision=$DEC"
echo "jti=$JTI"
test "$DEC" = "ALLOW"
test -n "$JTI"

# consume once then replay
C1="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":$(printf '%s' "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); import json as j; print(j.dumps(d["ticket"]))'),\"tool_name\":\"read.me\"}")"
echo "$C1" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["valid"] is True'

C2="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":$(printf '%s' "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); import json as j; print(j.dumps(d["ticket"]))'),\"tool_name\":\"read.me\"}")"
echo "$C2" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["valid"] is False'

# explain must work
curl -sS "$BASE/api/rtp/explain/$JTI" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert "row_hash" in d and "prev_hash" in d; print("PASS: explain ok")'

echo "PASS: smoke_C ✅"
