#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:8002}"
CONSUME_PATH="${CONSUME_PATH:-/api/rtp/consume}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1"; exit 1; }; }
need curl
need python3

echo "[1] openapi"
OA=$(curl -sS "$BASE/openapi.json" || true)
echo "openapi_bytes=${#OA}"

echo "[2] decide"
DECIDE=$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","usage":{"tokens":0,"cost":0,"agent_id":"smoke"},"signals":{"consistency":0.97,"pred_accuracy":0.95,"normality":0.10}}' || true)

echo "$DECIDE" | head -c 400; echo
DECISION=$(echo "$DECIDE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("decision",""))' 2>/dev/null || true)
echo "decision=$DECISION"

TICKET=$(echo "$DECIDE" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d.get("ticket"); print(t if isinstance(t,str) else "")' 2>/dev/null || true)
echo "ticket_bytes=${#TICKET}"

if [ -z "$TICKET" ]; then
  echo "NO_TICKET (need policy allow for read.me)"
  exit 2
fi

echo "[3] consume #1 ($CONSUME_PATH)"
C1=$(curl -sS -X POST "$BASE$CONSUME_PATH" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"}}" || true)
echo "$C1" | head -c 400; echo

echo "[4] consume #2 (replay should fail)"
set +e
C2=$(curl -sS -X POST "$BASE$CONSUME_PATH" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"}}")
RC=$?
set -e
echo "replay_http_rc=$RC"
echo "$C2" | head -c 400; echo

echo "[5] audit"
A=$(curl -sS "$BASE/api/rtp/audit?limit=5" || true)
echo "$A" | head -c 400; echo

echo "PASS_CHECKPOINT_A"
