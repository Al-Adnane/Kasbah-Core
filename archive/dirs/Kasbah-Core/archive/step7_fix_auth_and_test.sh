#!/usr/bin/env bash
set -euo pipefail

# 1) Ensure a local .env exists with dev keys
#    (safe defaults for local; change later for prod)
if [[ ! -f .env ]]; then
  cat <<'EENV' > .env
# Local dev keys (change for prod)
DEV_MASTER_KEY=dev-master-key
API_KEY=ksb_live_local_change_me
EENV
  echo "✅ created .env"
else
  # ensure keys exist (append if missing)
  grep -q '^DEV_MASTER_KEY=' .env || echo 'DEV_MASTER_KEY=dev-master-key' >> .env
  grep -q '^API_KEY=' .env || echo 'API_KEY=ksb_live_local_change_me' >> .env
  echo "✅ ensured DEV_MASTER_KEY and API_KEY in .env"
fi

# 2) Restart containers so env is loaded
docker compose up -d --build
sleep 1

# 3) Run Step 7 tests WITH Authorization header
BASE="http://127.0.0.1:8002"
DEV_MASTER_KEY="$(python3 - <<'PY'
import os
k=""
# read from .env without loading anything fancy
for line in open(".env","r",encoding="utf-8"):
    line=line.strip()
    if not line or line.startswith("#"): 
        continue
    if line.startswith("DEV_MASTER_KEY="):
        k=line.split("=",1)[1].strip()
        break
print(k)
PY
)"

AUTH="Authorization: Bearer ${DEV_MASTER_KEY}"

echo "==============================="
echo "STEP 7 — FINAL KILLSHOT (AUTH)"
echo "==============================="

echo "[1] Health"
curl -sS "$BASE/health" ; echo

echo "[2] Decide (expect 200)"
DECIDE="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"tool_name":"read.me","agent_id":"step7","signals":{"consistency":0.99}}')"
echo "decide_raw=$(echo "$DECIDE" | head -c 220)"

TICKET="$(echo "$DECIDE" | python3 - <<'PY'
import sys,json
d=json.load(sys.stdin)
# accept either jti or ticket string shapes
t=d.get("ticket")
if isinstance(t, dict) and "jti" in t:
    print(t["jti"])
elif isinstance(t, str):
    print(t)
else:
    print("")
PY
)"

if [[ -z "${TICKET:-}" ]]; then
  echo "❌ No ticket returned. Full decide:"
  echo "$DECIDE"
  exit 1
fi
echo "✅ Ticket OK"

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
