#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8002}"

echo "=============================="
echo "🔍 KASBAH FULL SYSTEM CHECK"
echo "BASE=$BASE"
echo "=============================="
echo

echo "== 0) docker status =="
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' | sed -n '1,120p'
echo

echo "== 1) health =="
code="$(curl -s -o /tmp/health.json -w "%{http_code}" "$BASE/health" || true)"
echo "HTTP=$code /health"
cat /tmp/health.json 2>/dev/null || true
echo
echo

echo "== 2) openapi routes (rtp-related) =="
curl -sS "$BASE/openapi.json" > /tmp/kasbah_openapi.json
python3 - <<'PY'
import json
o=json.load(open("/tmp/kasbah_openapi.json","r"))
paths=o.get("paths",{})
rtp=sorted([p for p in paths if "rtp" in p or "ticket" in p])
print("RTP_PATHS=", rtp)
print("HAS_DECIDE=", "/api/rtp/decide" in paths)
print("HAS_CONSUME=", "/api/rtp/consume" in paths)
PY
echo

decide() {
  curl -sS -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer dev-master-key" \
    -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}'
}

consume() {
  local jwt="$1"
  curl -sS -X POST "$BASE/api/rtp/consume" \
    -H "Content-Type: application/json" \
    -d "{\"ticket\":\"$jwt\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}"
}

echo "== 3) RTP happy path (decide -> consume) =="
DEC="$(decide)"
echo "$DEC" | python3 -m json.tool | sed -n '1,80p'
JWT="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("ticket",""))' "$DEC")"
echo "JWT_LEN=${#JWT}"
CONSUME1="$(consume "$JWT" || true)"
echo "$CONSUME1" | python3 -m json.tool 2>/dev/null || { echo "CONSUME_NOT_JSON:"; echo "$CONSUME1"; }
echo

echo "== 4) Replay moat (consume same JWT twice; 2nd should DENY) =="
CONSUME2="$(consume "$JWT" || true)"
echo "$CONSUME2" | python3 -m json.tool 2>/dev/null || { echo "CONSUME_NOT_JSON:"; echo "$CONSUME2"; }
echo

echo "== 5) Tampered JWT should FAIL =="
BAD="${JWT%?}x"
TAMP="$(consume "$BAD" || true)"
echo "$TAMP" | python3 -m json.tool 2>/dev/null || { echo "TAMP_NOT_JSON:"; echo "$TAMP"; }
echo

echo "== 6) Audit tail =="
curl -sS "$BASE/api/rtp/audit?limit=10" | python3 -m json.tool || true
echo

echo "✅ DONE"
