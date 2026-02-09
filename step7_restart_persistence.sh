#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:8002"

# read dev key from .env
DEV_MASTER_KEY="$(python3 -c 'import re; s=open(".env","r",encoding="utf-8").read(); m=re.search(r"^DEV_MASTER_KEY=(.*)$", s, re.M); print((m.group(1).strip() if m else ""))')"
AUTH="Authorization: Bearer ${DEV_MASTER_KEY}"

echo "==============================="
echo "STEP 7 — RESTART + PERSISTENCE"
echo "==============================="

echo "[0] restart stack"
docker compose restart
sleep 2

echo "[1] health"
curl -sS "$BASE/health" ; echo

echo "[2] decide -> ticket"
DECIDE="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"tool_name":"read.me","agent_id":"step7-restart","signals":{"consistency":0.99}}')"

TICKET="$(printf '%s' "$DECIDE" | python3 -c 'import sys,json
d=json.loads(sys.stdin.read())
t=d.get("ticket")
print(t["jti"] if isinstance(t,dict) and "jti" in t else (t if isinstance(t,str) else ""))
')"
echo "ticket_len=${#TICKET}"
[[ -n "$TICKET" ]] || { echo "❌ no ticket"; echo "$DECIDE"; exit 1; }

echo "[3] consume once (ALLOW)"
OUT1="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"step7-restart\"}")"
echo "$OUT1" | grep -qi "ALLOWED" || { echo "❌ expected ALLOWED"; echo "$OUT1"; exit 1; }
echo "✅ allowed"

echo "[4] restart again"
docker compose restart
sleep 2

echo "[5] replay after restart (must still DENY)"
OUT2="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"step7-restart\"}")"
echo "$OUT2"
echo "$OUT2" | grep -qi "replay\|deny\|invalid\|used" || { echo "❌ replay was not denied after restart"; exit 1; }
echo "🎯 PERSISTENCE CONFIRMED (replay survives restart)"
