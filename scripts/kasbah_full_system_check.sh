#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8002}"

req() {
  # req METHOD PATH [JSON]
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"
  local body; body="$(mktemp)"
  local code
  code="$(curl -sS --connect-timeout 3 --max-time 12 \
    -o "$body" -w '%{http_code}' \
    -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} )" || code="000"
  echo "HTTP=$code PATH=$path"
  cat "$body"
  echo
  rm -f "$body"
  echo "$code"
}

pp() { python3 - <<'PY' || cat
import sys,json
s=sys.stdin.read()
if not s.strip(): print("(empty)"); raise SystemExit(0)
try: print(json.dumps(json.loads(s), indent=2, sort_keys=True))
except Exception: print(s)
PY
}

echo "=============================="
echo "🔍 KASBAH FULL SYSTEM CHECK"
echo "BASE=$BASE"
echo "=============================="

echo
echo "== 0) docker status =="
docker compose ps || true

echo
echo "== 1) compose validity =="
docker compose config >/dev/null && echo "✅ compose ok" || { echo "❌ compose invalid"; exit 1; }

echo
echo "== 2) health (moats counters) =="
H_JSON="$(mktemp)"
H_CODE="$(curl -sS -o "$H_JSON" -w '%{http_code}' "$BASE/health" || true)"
echo "HTTP=$H_CODE /health"
cat "$H_JSON" | pp
rm -f "$H_JSON"
[ "$H_CODE" = "200" ] || { echo "❌ health not reachable"; exit 1; }

echo
echo "== 3) moat inventory (try likely endpoints) =="
for P in /api/system/moats /api/moats /system/moats /moats; do
  set +e
  OUT="$(mktemp)"
  CODE="$(curl -sS -o "$OUT" -w '%{http_code}' "$BASE$P" || true)"
  set -e
  if [ "$CODE" = "200" ]; then
    echo "FOUND $P"
    cat "$OUT" | pp
    rm -f "$OUT"
    break
  else
    rm -f "$OUT"
  fi
done
echo "(If nothing printed above, moat inventory endpoint is missing or moved.)"

echo
echo "== 4) RTP core tests =="
DEC="$(curl -sS -X POST "$BASE/api/rtp/decide" -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
echo "$DEC" | pp

python3 - <<'PY'
import json,sys
o=json.loads(sys.stdin.read())
assert o.get("decision")=="ALLOW", o
t=o.get("ticket","")
assert isinstance(t,str) and t, o
print("✅ DECIDE_ALLOW_OK")
print("TICKET_PREFIX=", t[:12])
PY <<<"$DEC"

TICKET="$(python3 - <<'PY'
import json,sys
o=json.loads(sys.stdin.read()); t=o.get("ticket",""); print(t if isinstance(t,str) else "")
PY <<<"$DEC")"

R1="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "CONSUME #1:"; echo "$R1" | pp

R2="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "CONSUME #2 (replay expected):"; echo "$R2" | pp

python3 - <<'PY'
import json,sys
o=json.loads(sys.stdin.read())
txt=str(o).lower()
assert ("replay" in txt) or (o.get("valid") is False) or (o.get("decision") in ("DENY","DENIED")) or (o.get("status") in ("DENY","DENIED")), o
print("✅ REPLAY_DENIED_OK")
PY <<<"$R2"

echo
echo "== 5) mismatch + tamper quick =="
DEC2="$(curl -sS -X POST "$BASE/api/rtp/decide" -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"evil","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
T2="$(python3 - <<'PY'
import json,sys
o=json.loads(sys.stdin.read()); t=o.get("ticket",""); print(t if isinstance(t,str) else "")
PY <<<"$DEC2")"

MM="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$T2\",\"tool_name\":\"shell.exec\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "MISMATCH:"; echo "$MM" | pp

BAD="${T2%?}x"
TP="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "TAMPER:"; echo "$TP" | pp

echo
echo "== 6) redis env sanity (what mode are we actually running?) =="
CN="$(docker compose ps -q api | head -n 1 || true)"
if [ -n "${CN:-}" ]; then
  docker exec -i "$CN" sh -lc 'env | egrep "REPLAY_LOCK_MODE|REDIS_URL|REDIS_HOST|REDIS_PORT|KASBAH_" | sort | sed -n "1,200p"' || true
else
  echo "api container not found"
fi

echo
echo "=============================="
echo "✅ DONE"
echo "If 3 moats are missing, the evidence will be in:"
echo "  - moat inventory endpoint output (if present)"
echo "  - env vars showing modes disabled"
echo "  - code counters in /health"
echo "=============================="
