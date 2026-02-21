#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:8002"

# 1) Ensure local .env keys exist
if [[ ! -f .env ]]; then
  cat <<'EENV' > .env
DEV_MASTER_KEY=dev-master-key
API_KEY=ksb_live_local_change_me
EENV
  echo "✅ created .env"
else
  grep -q '^DEV_MASTER_KEY=' .env || echo 'DEV_MASTER_KEY=dev-master-key' >> .env
  grep -q '^API_KEY=' .env || echo 'API_KEY=ksb_live_local_change_me' >> .env
  echo "✅ ensured DEV_MASTER_KEY and API_KEY in .env"
fi

# 2) Restart so env is loaded
docker compose up -d --build
sleep 1

# 3) Read dev key from .env (no fancy tooling)
DEV_MASTER_KEY="$(python3 -c 'import re; s=open(".env","r",encoding="utf-8").read(); m=re.search(r"^DEV_MASTER_KEY=(.*)$", s, re.M); print((m.group(1).strip() if m else ""))')"
AUTH="Authorization: Bearer ${DEV_MASTER_KEY}"

echo "==============================="
echo "STEP 7 — FINAL KILLSHOT (AUTH v2)"
echo "==============================="

echo "[1] Health"
curl -sS "$BASE/health" ; echo

echo "[2] Decide (expect 200)"
DECIDE="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"tool_name":"read.me","agent_id":"step7","signals":{"consistency":0.99}}')"

echo "decide_len=${#DECIDE}"
echo "decide_head=$(echo "$DECIDE" | head -c 220)"

TICKET="$(printf '%s' "$DECIDE" | python3 -c 'import sys,json
raw=sys.stdin.read().strip()
d=json.loads(raw)
t=d.get("ticket")
if isinstance(t, dict) and "jti" in t:
    print(t["jti"])
elif isinstance(t, str):
    print(t)
else:
    print("")
')"

if [[ -z "${TICKET:-}" ]]; then
  echo "❌ No ticket extracted. Full decide below:"
  echo "$DECIDE"
  exit 1
fi
echo "✅ Ticket extracted (len=${#TICKET})"

echo "[3] First consume (should ALLOW)"
OUT1="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"step7\"}")"
echo "$OUT1"
echo "$OUT1" | grep -qi "ALLOWED" || { echo "❌ First consume failed"; exit 1; }
echo "✅ First consume allowed"

echo "[4] Replay (should DENY)"
OUT2="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"step7\"}")"
echo "$OUT2"
echo "$OUT2" | grep -qi "deny\|invalid\|used\|replay" || { echo "❌ Replay NOT denied"; exit 1; }
echo "✅ Replay denied"

echo "[5] Tool mismatch (should DENY)"
OUT3="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"shell.exec\",\"agent_id\":\"step7\"}")"
echo "$OUT3"
echo "$OUT3" | grep -qi "deny\|mismatch\|invalid" || { echo "❌ Tool mismatch NOT denied"; exit 1; }
echo "✅ Tool mismatch denied"

echo "[6] Tamper (should DENY)"
BAD="${TICKET%?}x"
OUT4="$(curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"step7\"}")"
echo "$OUT4"
echo "$OUT4" | grep -qi "deny\|invalid\|signature\|bad" || { echo "❌ Tamper NOT denied"; exit 1; }
echo "✅ Tamper denied"

echo "🎯 STEP 7 COMPLETE (auth + moats verified)"
