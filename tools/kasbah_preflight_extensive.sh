#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"

ok(){ echo "✅ $1"; }
warn(){ echo "⚠️  $1"; }
fail(){ echo "❌ $1"; exit 1; }
step(){ echo; echo "=============================="; echo "== $1 =="; echo "=============================="; }

need_cmd(){
  command -v "$1" >/dev/null 2>&1
}

pp_json(){
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

http(){
  # http METHOD PATH [JSON]
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
  echo "$code"
  cat "$body"
  rm -f "$body"
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

step "0) Repo sanity"
need_cmd git || fail "git not found"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not in a git repo"
git status --porcelain | sed -n '1,120p' || true
ok "git status displayed"

echo
echo "Top risk files (must NOT contain real secrets):"
for f in .env .env.local .env.production docker-compose.yml Caddyfile; do
  [ -f "$f" ] && echo " - $f"
done

step "1) Python compile integrity (apps/api)"
python3 - <<'PY' || fail "python compile failed"
import py_compile
from pathlib import Path
files=sorted(str(p) for p in Path("apps/api").rglob("*.py"))
if not files: raise SystemExit("No python files under apps/api")
for f in files:
    py_compile.compile(f, doraise=True)
print("PY_COMPILE_OK files=", len(files))
PY
ok "python compile ok"

step "2) Docker compose validity"
docker compose config >/dev/null || fail "docker-compose.yml invalid"
ok "compose config ok"

step "3) Build + boot + health"
docker compose up -d --build
sleep 3

CODE="$(http GET /health "")"
BODY="$(http GET /health "")"  # re-fetch body cleanly
# We intentionally call twice: one for code, one for body, because our helper prints both.
# But we only need a hard pass condition:
HC="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$HC" = "200" ] || fail "health not 200 (got $HC)"
ok "health 200"

echo "HEALTH BODY:"
curl -sS "$BASE/health" | pp_json

step "4) Moat inventory must be non-empty"
MC="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/api/system/moats" || true)"
[ "$MC" = "200" ] || fail "/api/system/moats not 200 (got $MC)"
MOATS_RAW="$(curl -sS "$BASE/api/system/moats" || true)"
echo "$MOATS_RAW" | pp_json

python3 - <<'PY' || fail "moat inventory empty"
import json,sys
s=sys.stdin.read().strip()
if not s: raise SystemExit(1)
o=json.loads(s)
# allow dict or list, but must contain at least 1 moat entry
if isinstance(o, list) and len(o) >= 1: pass
elif isinstance(o, dict) and len(o.keys()) >= 1: pass
else: raise SystemExit(1)
print("MOATS_NONEMPTY_OK")
PY <<<"$MOATS_RAW"
ok "moat inventory non-empty"

step "5) RTP core: decide ALLOW + consume + replay"
DEC="$(curl -sS -X POST "$BASE/api/rtp/decide" -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
echo "$DEC" | pp_json

python3 - <<'PY' || fail "decide did not ALLOW"
import json,sys
o=json.loads(sys.stdin.read())
assert o.get("decision")=="ALLOW", o
PY <<<"$DEC"
ok "decide ALLOW"

TICKET="$(echo "$DEC" | extract_ticket)"
[ -n "$TICKET" ] || fail "ticket missing"
echo "ticket_prefix=${TICKET:0:12}"

R1="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "CONSUME #1:"; echo "$R1" | pp_json

R2="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "CONSUME #2 (replay expected):"; echo "$R2" | pp_json

RAW="$R2" is_denial || fail "replay not denied"
ok "replay denied"

step "6) Hostile misuse: tool mismatch + tamper"
DEC2="$(curl -sS -X POST "$BASE/api/rtp/decide" -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"evil","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"
T2="$(echo "$DEC2" | extract_ticket)"
[ -n "$T2" ] || fail "ticket2 missing"

MM="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$T2\",\"tool_name\":\"shell.exec\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "MISMATCH:"; echo "$MM" | pp_json
RAW="$MM" is_denial || fail "tool mismatch not denied"
ok "tool mismatch denied"

BAD="${T2%?}x"
TP="$(curl -sS -X POST "$BASE/api/rtp/consume" -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"evil\",\"usage\":{\"tokens\":0,\"cost\":0}}")"
echo "TAMPER:"; echo "$TP" | pp_json
RAW="$TP" is_denial || fail "tamper not denied"
ok "tamper denied"

step "7) Malformed input must not crash"
curl -sS --max-time 5 -X POST "$BASE/api/rtp/decide" -d '{' >/dev/null 2>&1 || true
HC2="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$HC2" = "200" ] || fail "API unhealthy after malformed input"
ok "malformed survived"

step "8) Burst stability (80 decide calls) + health"
for i in {1..80}; do
  curl -s -o /dev/null -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -d '{"tool_name":"read.me","agent_id":"burst","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}' &
done
wait || true
HC3="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/health" || true)"
[ "$HC3" = "200" ] || fail "API unhealthy after burst"
ok "burst survived"

step "9) Static linters/tests (optional, auto-skip)"
if need_cmd pytest; then
  pytest -q || fail "pytest failed"
  ok "pytest ok"
else
  warn "pytest not installed (skipped)"
fi

if python3 -c 'import ruff' >/dev/null 2>&1; then
  python3 -m ruff check apps/api || fail "ruff check failed"
  ok "ruff ok"
else
  warn "ruff not installed (skipped)"
fi

if python3 -c 'import mypy' >/dev/null 2>&1; then
  python3 -m mypy apps/api || warn "mypy reported issues"
  ok "mypy ran"
else
  warn "mypy not installed (skipped)"
fi

step "10) Env + moats mode dump (inside api container)"
CN="$(docker compose ps -q api | head -n 1 || true)"
if [ -n "${CN:-}" ]; then
  docker exec -i "$CN" sh -lc 'env | egrep "ENV=|REPLAY_LOCK_MODE|REDIS_URL|KASBAH_" | sort | sed -n "1,220p"' || true
  ok "env dumped"
else
  warn "api container not found (skipped env dump)"
fi

echo
echo "=============================="
echo "🎯 PRE-FLIGHT EXTENSIVE CHECK PASSED"
echo "=============================="
