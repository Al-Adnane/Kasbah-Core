#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
CONSUME_PATH="${CONSUME_PATH:-/api/rtp/consume}"

echo "[A] decide"
DECIDE=$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","usage":{"tokens":0,"cost":0,"agent_id":"smoke"},"signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')

echo "$DECIDE" | head -c 600; echo

echo "[B] detect ticket field"
echo "$DECIDE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("keys=",sorted(d.keys())); print("ticket_type=",type(d.get("ticket")).__name__); print("ticket=",d.get("ticket"))' || true

TICKET=$(echo "$DECIDE" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d.get("ticket"); 
import json as J
print(t if isinstance(t,str) else (J.dumps(t) if isinstance(t,dict) else ""))' 2>/dev/null || true)

echo "ticket_bytes=${#TICKET}"
if [ -z "$TICKET" ]; then
  echo "NO_TICKET_FROM_DECIDE"
  exit 2
fi

echo "[C] consume #1"
curl -sS -X POST "$BASE$CONSUME_PATH" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":$TICKET,\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"}}"
echo
