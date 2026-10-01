#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"

fail(){ echo "❌ FAIL: $1"; exit 1; }
step(){ echo; echo "== $1 =="; }

REQ_HTTP=""
REQ_CURL_EC=0
REQ_ERR=""

# req METHOD PATH JSON
# sets: REQ_HTTP, REQ_CURL_EC, REQ_ERR ; echoes body
req() {
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"

  local tmp_out tmp_err
  tmp_out="$(mktemp)"
  tmp_err="$(mktemp)"

  # -i includes headers so we can parse status reliably
  # keep timeouts tight so failures are visible quickly
  set +e
  curl -sS -i \
    --connect-timeout 3 --max-time 10 \
    -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" \
    ${data:+-d "$data"} \
    >"$tmp_out" 2>"$tmp_err"
  REQ_CURL_EC=$?
  set -e

  REQ_ERR="$(cat "$tmp_err" || true)"

  # parse HTTP status from first HTTP line if present
  REQ_HTTP="$(awk 'NR==1 && $1 ~ /^HTTP\// {print $2; exit}' "$tmp_out" || true)"

  # output body (strip headers up to first empty line)
  awk 'BEGIN{p=0} {if(p){print} if($0==""){p=1}}' "$tmp_out"

  rm -f "$tmp_out" "$tmp_err"
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
raw=os.environ["RAW"]
o=json.loads(raw)
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
echo "🧪 KASBAH FULL LAUNCH DIAGNOSTIC v5"
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

H="$(req GET /health "")"
echo "CURL_EC=$REQ_CURL_EC HTTP=${REQ_HTTP:-} ERR=${REQ_ERR:-}"
echo "$H" | sed -n '1,20p'
[ "$REQ_CURL_EC" -eq 0 ] || fail "health curl failed"
[ "${REQ_HTTP:-}" = "200" ] || fail "health not 200 (got ${REQ_HTTP:-empty})"
echo "✅ HEALTH_OK"

step "D. Decide (retry up to 10) — and DO NOT LIE about failures"
DEC=""
for i in {1..10}; do
  DEC="$(req POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
  echo "try=$i  CURL_EC=$REQ_CURL_EC  HTTP=${REQ_HTTP:-}  ERR=${REQ_ERR:-}"
  if [ "$REQ_CURL_EC" -eq 0 ] && [ "${REQ_HTTP:-}" = "200" ]; then
    echo "$DEC" | pretty
    if echo "$DEC" | grep -q '"decision":"ALLOW"'; then
      echo "✅ DECIDE_ALLOW_OK"
      break
    fi
  else
    # print error only when it fails, so it's visible
    [ -n "${REQ_ERR:-}" ] && echo "curl_err: $REQ_ERR"
  fi
  sleep 1
done

# hard fail if never reached ALLOW, but show last body
echo "$DEC" | pretty
echo "$DEC" | grep -q '"decision":"ALLOW"' || fail "decide never returned ALLOW (see tries above: curl exit / http / errors)"

TICKET="$(RAW="$DEC" extract_ticket)"
[ -n "$TICKET" ] || fail "empty ticket"
echo "ticket_prefix=${TICKET:0:12}"

step "E. Consume #1 then Replay (#2 must deny)"
R1="$(req POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "CURL_EC=$REQ_CURL_EC HTTP=${REQ_HTTP:-} ERR=${REQ_ERR:-}"
echo "$R1" | pretty
[ "$REQ_CURL_EC" -eq 0 ] || fail "consume#1 curl failed"
[ "${REQ_HTTP:-}" = "200" ] || fail "consume#1 not 200"

R2="$(req POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "CURL_EC=$REQ_CURL_EC HTTP=${REQ_HTTP:-} ERR=${REQ_ERR:-}"
echo "$R2" | pretty

RAW="$R2" is_denial || fail "replay not denied"
echo "✅ REPLAY_DENIED_OK"

echo
echo "=============================="
echo "🎯 DIAGNOSTIC OK THROUGH REPLAY"
echo "=============================="
