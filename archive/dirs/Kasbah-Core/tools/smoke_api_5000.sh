#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:5000}"

echo "== 1) health =="
curl -sS "$BASE/api/health" | sed -n '1,120p'
echo

echo "== 2) decide (request ticket) =="
DEC="$(curl -sS -X POST "$BASE/api/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool":"db.query","agent_id":"test","signals":{"consistency":0.95}}')"
echo "$DEC" | sed -n '1,160p'
echo

TICKET="$(printf "%s" "$DEC" | python3 -c 'import sys,json; print(json.load(sys.stdin)["ticket"])')"
echo "ticket=$TICKET"
echo

echo "== 3) consume (first use) =="
curl -sS -X POST "$BASE/api/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool\":\"db.query\"}" | sed -n '1,120p'
echo

echo "== 4) replay (second use should fail) =="
curl -sS -X POST "$BASE/api/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool\":\"db.query\"}" | sed -n '1,120p'
echo
