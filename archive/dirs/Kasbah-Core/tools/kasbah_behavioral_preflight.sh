#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8002}"

fail(){ echo "❌ FAIL: $1"; exit 1; }
ok(){ echo "✅ $1"; }
step(){ echo; echo "=============================="; echo "== $1 =="; echo "=============================="; }

# request: METHOD PATH JSON(optional)
# prints body to stdout; sets HTTP_CODE
HTTP_CODE=""
request() {
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"
  local body; body="$(mktemp)"
  HTTP_CODE="$(curl -sS --connect-timeout 3 --max-time 12 \
    -o "$body" -w '%{http_code}' \
    -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} )" || HTTP_CODE="000"
  cat "$body"
  rm -f "$body"
}

pp(){
  python3 - <<'PY' || cat
import sys,json
s=sys.stdin.read()
if not s.strip():
  print("(empty)"); raise SystemExit(0)
try:
  print(json.dumps(json.loads(s), indent=2, sort_keys=True))
except Exception:
  print(s)
PY
}

extract_ticket(){
  python3 - <<'PY'
import json,sys
o=json.load(sys.stdin)
t=o.get("ticket","")
if isinstance(t,str): print(t); raise SystemExit(0)
if isinstance(t,dict): print(t.get("jti") or t.get("ticket") or ""); raise SystemExit(0)
print("")
PY
}

assert_json_field(){
  # env RAW, KEY, VAL
  python3 - <<'PY'
import os,json
raw=os.environ["RAW"]
key=os.environ["KEY"]
val=os.environ["VAL"]
o=json.loads(raw)
got=str(o.get(key,""))
assert got==val, (key, got, val, o)
print("OK", key, got)
PY
}

assert_denial(){
  python3 - <<'PY'
import os,json,sys
s=os.environ.get("RAW","")
if not s.strip(): raise SystemExit("EMPTY")
try: o=json.loads(s)
except Exception: o={"raw":s}
txt=str(o).lower()
ok=False
if isinstance(o,dict):
  if o.get("valid") is False: ok=True
  if str(o.get("decision","")).upper() in ("DENY","DENIED"): ok=True
  if str(o.get("status","")).upper() in ("DENY","DENIED"): ok=True
  if "detail" in o and any(x in str(o["detail"]).lower() for x in ("replay","mismatch","invalid","denied")): ok=True
if any(x in txt for x in ("deny","denied","replay","invalid","not found","mismatch")): ok=True
assert ok, o
print("OK_DENIAL")
PY
}

step "0) HEALTH"
H="$(request GET /health "")"
echo "HTTP=$HTTP_CODE"
[ "$HTTP_CODE" = "200" ] || fail "health not reachable"
echo "$H" | pp
ok "health ok"

step "1) DECIDE should ALLOW with strong signals"
DEC_ALLOW="$(request POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "decide allow http $HTTP_CODE"
echo "$DEC_ALLOW" | pp
RAW="$DEC_ALLOW" KEY="decision" VAL="ALLOW" assert_json_field >/dev/null || fail "decide did not ALLOW"
TICKET="$(echo "$DEC_ALLOW" | extract_ticket)"
[ -n "$TICKET" ] || fail "ticket missing"
ok "decide allow ok"

step "2) CONSUME must ALLOW once, then REPLAY must DENY"
C1="$(request POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "consume#1 http $HTTP_CODE"
echo "$C1" | pp

C2="$(request POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "consume#2 http $HTTP_CODE"
echo "$C2" | pp
RAW="$C2" assert_denial >/dev/null || fail "replay not denied"
ok "replay denied ok"

step "3) TOOL MISMATCH must DENY"
DEC2="$(request POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"evil","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "decide2 http $HTTP_CODE"
T2="$(echo "$DEC2" | extract_ticket)"
[ -n "$T2" ] || fail "ticket2 missing"

MM="$(request POST /api/rtp/consume "{\"ticket\":\"$T2\",\"tool_name\":\"shell.exec\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "mismatch consume http $HTTP_CODE"
echo "$MM" | pp
RAW="$MM" assert_denial >/dev/null || fail "tool mismatch not denied"
ok "tool mismatch denied ok"

step "4) TAMPER must DENY"
BAD="${T2%?}x"
TP="$(request POST /api/rtp/consume "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "tamper consume http $HTTP_CODE"
echo "$TP" | pp
RAW="$TP" assert_denial >/dev/null || fail "tamper not denied"
ok "tamper denied ok"

step "5) DECIDE should DENY with hostile/low signals (if moat exists)"
DEC_DENY="$(request POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"low","signals":{"consistency":0.01,"accuracy":0.01,"normality":0.01,"latency_score":0.01}}')"
echo "HTTP=$HTTP_CODE"; [ "$HTTP_CODE" = "200" ] || fail "decide deny http $HTTP_CODE"
echo "$DEC_DENY" | pp
# We don't hard-fail if it allows (because some configs might allow); we just report.
python3 - <<'PY'
import json,sys
o=json.loads(sys.stdin.read())
print("DECISION=", o.get("decision"))
PY <<<"$DEC_DENY"

step "6) Malformed input must not crash service"
curl -sS --max-time 5 -X POST "$BASE/api/rtp/decide" -d '{' >/dev/null 2>&1 || true
H2="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$H2" = "200" ] || fail "API crashed after malformed input"
ok "malformed survived"

step "7) Burst stability (80 decides) then health"
for i in {1..80}; do
  curl -s -o /dev/null -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -d '{"tool_name":"read.me","agent_id":"burst","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}' &
done
wait || true
H3="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$H3" = "200" ] || fail "API unhealthy after burst"
ok "burst survived"

echo
echo "=============================="
echo "🎯 BEHAVIORAL PRE-FLIGHT PASSED (core moats)"
echo "=============================="
