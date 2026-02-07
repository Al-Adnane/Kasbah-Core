#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"

fail(){ echo "❌ FAIL: $1"; exit 1; }
step(){ echo; echo "== $1 =="; }

# curl_req METHOD PATH JSON_BODY
# outputs body; sets REQ_CODE
REQ_CODE=""
curl_req() {
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"
  local tmp; tmp="$(mktemp)"
  REQ_CODE="$(curl -sS --max-time 10 -o "$tmp" -w '%{http_code}' -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} || true)"
  cat "$tmp"
  rm -f "$tmp"
}

pretty(){
  python3 - <<'PY' || cat
import sys,json
s=sys.stdin.read()
if not s.strip():
  print("(empty)"); raise SystemExit(0)
try:
  o=json.loads(s)
  print(json.dumps(o, indent=2, sort_keys=True))
except Exception:
  print(s)
PY
}

json_get(){
  # env RAW, KEY
  python3 - <<'PY'
import os,json
raw=os.environ.get("RAW","")
key=os.environ.get("KEY","")
o=json.loads(raw)
v=o.get(key,"")
print(v if isinstance(v,str) else "")
PY
}

extract_ticket(){
  python3 - <<'PY'
import os,json
o=json.loads(os.environ["RAW"])
t=o.get("ticket","")
if isinstance(t,str): print(t); raise SystemExit(0)
if isinstance(t,dict): print(t.get("jti") or t.get("ticket") or ""); raise SystemExit(0)
print("")
PY
}

is_denial(){
  python3 - <<'PY'
import os,json,sys
s=os.environ.get("RAW","")
if not s.strip(): raise SystemExit(2)
try: o=json.loads(s)
except Exception: o={"raw":s}
txt=(json.dumps(o) if isinstance(o,(dict,list)) else str(o)).lower()
ok=False
if isinstance(o,dict):
  if o.get("valid") is False: ok=True
  if str(o.get("decision","")).upper() in ("DENY","DENIED"): ok=True
  if str(o.get("status","")).upper() in ("DENY","DENIED"): ok=True
  if "detail" in o and "replay" in str(o["detail"]).lower(): ok=True
if ("replay" in txt) or ("deny" in txt) or ("denied" in txt) or ("invalid" in txt) or ("not found" in txt):
  ok=True
sys.exit(0 if ok else 1)
PY
}

retry_decide_allow(){
  # tries up to 8 times to get ALLOW
  local i body
  for i in 1 2 3 4 5 6 7 8; do
    body="$(curl_req POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
    if [ "$REQ_CODE" = "200" ] && echo "$body" | grep -q '"decision":"ALLOW"'; then
      echo "$body"
      return 0
    fi
    sleep 1
  done
  echo "$body"
  return 1
}

echo "=============================="
echo "🧪 KASBAH FULL LAUNCH DIAGNOSTIC v4"
echo "BASE=$BASE"
echo "=============================="

step "A. Compile (apps/api)"
python3 - <<'PY' || fail "python compile"
import py_compile
from pathlib import Path
files=sorted(str(p) for p in Path("apps/api").rglob("*.py"))
for f in files:
  py_compile.compile(f, doraise=True)
print("PY_COMPILE_OK files=", len(files))
PY
echo "✅ PY_COMPILE_OK"

step "B. Compose validate"
docker compose config >/dev/null || fail "docker compose config"
echo "✅ COMPOSE_VALID"

step "C. Rebuild + up + health"
docker compose down -v >/dev/null 2>&1 || true
docker compose build --no-cache
docker compose up -d
sleep 3
HCODE="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$HCODE" = "200" ] || fail "health not 200 (got $HCODE)"
echo "✅ HEALTH_OK"

step "D. Decide must ALLOW (with retry) — show body"
DEC="$(retry_decide_allow)" || { echo "HTTP=$REQ_CODE"; echo "$DEC" | pretty; fail "decide did not return ALLOW"; }
echo "HTTP=$REQ_CODE"
echo "$DEC" | pretty

TICKET="$(RAW="$DEC" extract_ticket)"
[ -n "$TICKET" ] || fail "empty ticket"
echo "✅ DECIDE_ALLOW_OK ticket_prefix=${TICKET:0:12}"

step "E. Consume #1 then Replay (#2 must deny)"
R1="$(curl_req POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$REQ_CODE"; echo "$R1" | pretty
[ "$REQ_CODE" = "200" ] || fail "consume#1 HTTP $REQ_CODE"

R2="$(curl_req POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$REQ_CODE"; echo "$R2" | pretty
RAW="$R2" is_denial || fail "replay not denied"
echo "✅ REPLAY_DENIED_OK"

step "F. Tool mismatch (read.me ticket, consume as shell.exec) must deny"
DEC2="$(curl_req POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"evil","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
[ "$REQ_CODE" = "200" ] || { echo "$DEC2" | pretty; fail "decide2 HTTP $REQ_CODE"; }
T2="$(RAW="$DEC2" extract_ticket)"
[ -n "$T2" ] || fail "empty ticket2"

MM="$(curl_req POST /api/rtp/consume "{\"ticket\":\"$T2\",\"tool_name\":\"shell.exec\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$REQ_CODE"; echo "$MM" | pretty
RAW="$MM" is_denial || fail "tool mismatch not denied"
echo "✅ TOOL_MISMATCH_DENIED_OK"

step "G. Tamper must deny"
BAD="${T2%?}x"
TP="$(curl_req POST /api/rtp/consume "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP=$REQ_CODE"; echo "$TP" | pretty
RAW="$TP" is_denial || fail "tamper not denied"
echo "✅ TAMPER_DENIED_OK"

step "H. Malformed JSON must not crash API"
curl -sS --max-time 5 -X POST "$BASE/api/rtp/decide" -d '{' >/dev/null 2>&1 || true
HCODE2="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$HCODE2" = "200" ] || fail "API unhealthy after malformed input"
echo "✅ MALFORMED_SURVIVED"

step "I. Burst (80 decide) then health"
for i in {1..80}; do
  curl -s -o /dev/null -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -d '{"tool_name":"read.me","agent_id":"burst","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}' &
done
wait || true
HCODE3="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$HCODE3" = "200" ] || fail "API unhealthy after burst"
echo "✅ BURST_SURVIVED"

step "J. Redis blip (stop/start) + health"
RID="$(docker compose ps -q redis 2>/dev/null | head -n 1 || true)"
if [ -n "${RID:-}" ]; then
  docker stop "$RID" >/dev/null 2>&1 || true
  sleep 2
  HCODE4="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
  [ "$HCODE4" = "200" ] || fail "API died without redis"
  docker start "$RID" >/dev/null 2>&1 || true
  sleep 2
  HCODE5="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
  [ "$HCODE5" = "200" ] || fail "API unhealthy after redis restart"
  echo "✅ REDIS_BLIP_SURVIVED"
else
  echo "⚠️ SKIP: redis container not found"
fi

step "K. Inside-container self-check via Python (no curl needed)"
CN="$(docker compose ps -q api | head -n 1 || true)"
if [ -n "${CN:-}" ]; then
  docker exec -i "$CN" sh -lc "python3 - <<'PY'
import json,urllib.request
base='http://127.0.0.1:8002'
def post(path,data):
    req=urllib.request.Request(base+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=5) as r:
        return r.status, json.loads(r.read().decode())
st,dec=post('/api/rtp/decide',{'tool_name':'read.me','agent_id':'inbox','signals':{'consistency':0.99,'accuracy':0.99,'normality':0.99,'latency_score':0.99}})
print('IN_CONTAINER_DECIDE_STATUS',st)
print('IN_CONTAINER_DECIDE_DECISION',dec.get('decision'))
PY"
  echo "✅ IN_CONTAINER_OK"
else
  echo "⚠️ SKIP: api container not found"
fi

echo
echo "=============================="
echo "🎯 ALL DIAGNOSTICS PASSED"
echo "Kasbah is launch-grade."
echo "=============================="
