#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"
HTTP_STATUS=""

fail() { echo "❌ FAIL: $1"; exit 1; }
step() { echo; echo "== $1 =="; }

curl_json() {
  local method="$1"; shift
  local path="$1"; shift
  local body="${1:-}"

  local resp status payload
  resp="$(curl -sS -w $'\n__HTTP_STATUS__:%{http_code}\n' -X "$method" "$BASE$path" \
    -H "Content-Type: application/json" \
    ${body:+-d "$body"} || true)"

  status="$(printf '%s' "$resp" | awk -F: '/^__HTTP_STATUS__:/ {print $2}' | tail -n 1)"
  payload="$(printf '%s' "$resp" | sed '/^__HTTP_STATUS__:/d')"

  HTTP_STATUS="${status:-}"
  export HTTP_STATUS
  printf '%s' "$payload"
}

pretty() {
  python3 - <<'PY' || cat
import sys,json
s=sys.stdin.read()
if not s.strip():
  print("(empty)")
  raise SystemExit(0)
try:
  o=json.loads(s)
  print(json.dumps(o, indent=2, sort_keys=True))
except Exception:
  print(s)
PY
}

is_denial_payload() {
  python3 - <<'PY'
import os, json, sys
s=os.environ.get("PAYLOAD","")
if not s.strip():
  raise SystemExit(2)
try:
  o=json.loads(s)
except Exception:
  o={"raw":s}
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
echo "🧪 KASBAH FULL LAUNCH DIAGNOSTIC v3"
echo "BASE=$BASE"
echo "=============================="

step "A. Python compile (apps/api only)"
python3 - <<'PY' || fail "python compile"
import py_compile
from pathlib import Path
files=sorted(str(p) for p in Path("apps/api").rglob("*.py"))
if not files:
  raise SystemExit("No python files found under apps/api")
for f in files:
  py_compile.compile(f, doraise=True)
print("PY_COMPILE_OK files=", len(files))
PY
echo "✅ PY_COMPILE_OK"

step "B. docker-compose.yml validate"
docker compose config >/dev/null || fail "docker compose config (invalid YAML)"
echo "✅ COMPOSE_VALID"

step "C. Clean rebuild + health"
docker compose down -v >/dev/null 2>&1 || true
docker compose build --no-cache
docker compose up -d
sleep 4
H="$(curl -sS -w '%{http_code}' -o /dev/null "$BASE/health" || true)"
[ "$H" = "200" ] || fail "health not 200 (got $H)"
echo "✅ HEALTH_OK"

step "D. Decide (must ALLOW) — show HTTP + body"
DEC_BODY="$(curl_json POST /api/rtp/decide '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
echo "HTTP_STATUS=${HTTP_STATUS:-}"
echo "$DEC_BODY" | pretty

[ "${HTTP_STATUS:-}" = "200" ] || fail "decide HTTP ${HTTP_STATUS:-?} (body printed above)"

DECISION="$(python3 - <<'PY'
import os, json
raw=os.environ.get("RAW","")
if not raw.strip(): raise SystemExit("EMPTY_BODY")
o=json.loads(raw); print(o.get("decision",""))
PY
RAW="$DEC_BODY")" || fail "decide response not valid JSON"

[ "$DECISION" = "ALLOW" ] || fail "decide returned $DECISION (body printed above)"

TICKET="$(python3 - <<'PY'
import os, json
raw=os.environ.get("RAW","")
o=json.loads(raw)
t=o.get("ticket","")
if isinstance(t,str): print(t)
elif isinstance(t,dict): print(t.get("jti") or t.get("ticket") or "")
else: print("")
PY
RAW="$DEC_BODY")"
[ -n "$TICKET" ] || fail "empty ticket"
echo "✅ DECIDE_ALLOW_OK  ticket_prefix=${TICKET:0:12}"

step "E. Consume #1 then replay (#2 must deny)"
R1="$(curl_json POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP_STATUS=${HTTP_STATUS:-}"
echo "R1_RAW=$R1"
echo "$R1" | pretty
[ "${HTTP_STATUS:-}" = "200" ] || fail "consume#1 HTTP ${HTTP_STATUS:-?}"

R2="$(curl_json POST /api/rtp/consume "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "HTTP_STATUS=${HTTP_STATUS:-}"
echo "R2_RAW=$R2"
echo "$R2" | pretty

PAYLOAD="$R2" is_denial_payload || fail "replay not denied (body printed above)"
echo "✅ REPLAY_DENIED_OK"

echo
echo "=============================="
echo "🎯 DIAGNOSTIC OK THROUGH REPLAY"
echo "=============================="
