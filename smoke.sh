#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8002}"

echo "== containers =="
docker ps --format 'table {{.Names}}\t{{.Status}}'

echo "== health =="
curl -sS --max-time 3 "$BASE/health" ; echo

echo "== mint =="
DECIDE="$(curl -sS --max-time 5 -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","usage":{"tokens":0,"cost":0,"agent_id":"smoke"}}')"
echo "$DECIDE"

T="$(printf '%s' "$DECIDE" | python3 -c 'import json,sys; x=json.load(sys.stdin); print(x.get("ticket","") if isinstance(x,dict) else "")')"
echo "ticket_len=${#T}"
test -n "$T"

echo "== consume =="
curl -sS --max-time 5 -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$T\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"}}"
echo

echo "== replay (should fail) =="
curl -sS --max-time 5 -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$T\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"}}"
echo

echo "== audit =="
curl -sS --max-time 5 "$BASE/api/rtp/audit?limit=5" ; echo
