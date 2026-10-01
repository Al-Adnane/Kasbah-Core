#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8002}"

fail(){ echo "❌ FAIL: $1"; exit 1; }
step(){ echo; echo "== $1 =="; }

# request: METHOD PATH JSON(optional)
# echoes body, sets HTTP_CODE and CURL_EC and CURL_ERR
HTTP_CODE=""
CURL_EC=0
CURL_ERR=""
request() {
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"

  local bodyfile errfile
  bodyfile="$(mktemp)"
  errfile="$(mktemp)"

  set +e
  HTTP_CODE="$(curl -sS --connect-timeout 3 --max-time 10 \
    -o "$bodyfile" \
    -w '%{http_code}' \
    -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} \
    2>"$errfile")"
  CURL_EC=$?
  set -e

  CURL_ERR="$(cat "$errfile" || true)"
  cat "$bodyfile"

  rm -f "$bodyfile" "$errfile"
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

echo "=============================="
echo "🧪 KASBAH DIAGNOSTIC (FINAL)"
echo "BASE=$BASE"
echo "=============================="

step "1) Compile (apps/api)"
python3 - <<'PY' || fail "python compile"
import py_compile
from pathlib import Path
files=sorted(str(p) for p in Path("apps/api").rglob("*.py"))
for f in files:
  py_compile.compile(f, doraise=True)
print("PY_COMPILE_OK files=", len(files))
PY
echo "✅ PY_COMPILE_OK"

step "2) Compose validate"
docker compose config >/dev/null || fail "docker compose config"
echo "✅ COMPOSE_VALID"

step "3) Rebuild + up"
docker compose down -v >/dev/null 2>&1 || true
docker compose build --no-cache
docker compose up -d
sleep 3

step "4) Health"
H="$(request GET /health "")"
echo "CURL_EC=$CURL_EC HTTP=$HTTP_CODE"
[ "$CURL_EC" -eq 0 ] || { echo "curl_err: $CURL_ERR"; fail "health curl failed"; }
echo "$H" | pretty
[ "$HTTP_CODE" = "200" ] || fail "health not 200 (got $HTTP_CODE)"
echo "✅ HEALTH_OK"

step "5) Decide must ALLOW (retry 10)"
DEC=""
for i in {1..10}; do
  DEC="$(request POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
  echo "try=$i CURL_EC=$CURL_EC HTTP=$HTTP_CODE"
  [ "$CURL_EC" -eq 0 ] || { echo "curl_err: $CURL_ERR"; sleep 1; continue; }
  if [ "$HTTP_CODE" = "200" ]; then
    echo "$DEC" | pretty
    if echo "$DEC" | grep -q '"decision":"ALLOW"'; then
      break
    fi
  fi
  sleep 1
done
echo "$DEC" | grep -q '"decision":"ALLOW"' || fail "decide never returned ALLOW"

TICKET="$(RAW="$DEC" extract_ticket)"
[ -n "$TICKET" ] || fail "empty ticket"
echo "✅ DECIDE_ALLOW_OK ticket_prefix=${TICKET:0:12}"

step "6) Consume then replay"
R1="$(request POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "consume#1 CURL_EC=$CURL_EC HTTP=$HTTP_CODE"
[ "$CURL_EC" -eq 0 ] || { echo "curl_err: $CURL_ERR"; fail "consume#1 curl failed"; }
echo "$R1" | pretty
[ "$HTTP_CODE" = "200" ] || fail "consume#1 not 200"

R2="$(request POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "consume#2 CURL_EC=$CURL_EC HTTP=$HTTP_CODE"
[ "$CURL_EC" -eq 0 ] || { echo "curl_err: $CURL_ERR"; fail "consume#2 curl failed"; }
echo "$R2" | pretty
RAW="$R2" is_denial || fail "replay not denied"
echo "✅ REPLAY_DENIED_OK"

echo
echo "=============================="
echo "🎯 PASSED: health + decide + replay"
echo "=============================="
