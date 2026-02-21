#!/usr/bin/env bash
set -euo pipefail

BASE=http://127.0.0.1:8002
echo "=============================="
echo "🚀 KASBAH ONE-SHOT LAUNCH TEST v2"
echo "=============================="

fail() { echo "❌ FAIL: $1"; exit 1; }

echo "== A. Python compile (all files via find) =="

PYFILES=$(find apps/api -name "*.py")

python3 - <<PY || fail "python compile"
# [AUTO-COMMENTED: invalid in bash] import py_compile,sys
files = """$PYFILES""".split()
for f in files:
    try:
        py_compile.compile(f, doraise=True)
    except Exception as e:
        print("SYNTAX ERROR IN:", f)
        raise
print("PY_COMPILE_OK")
PY

echo "✅ PY_COMPILE_OK"

echo "== B. Clean docker rebuild =="
docker compose down -v >/dev/null 2>&1 || true
docker compose build --no-cache
docker compose up -d
sleep 4
curl -fsS $BASE/health >/dev/null || fail "health"
echo "✅ HEALTH_OK"

echo "== C. Ticket mint / replay =="
DEC=$(curl -sS -X POST $BASE/api/rtp/decide -H "Content-Type: application/json" -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')
DECISION=$(echo "$DEC" | python3 -c 'import sys,json; o=json.load(sys.stdin); print(o.get("decision",""))')
if [ "$DECISION" != "ALLOW" ]; then
  echo "❌ FAIL: decide returned $DECISION"
  echo "$DEC"
  exit 1
fi
JTI=$(echo "$DEC" | python3 -c 'import sys,json; o=json.load(sys.stdin); t=o.get("ticket"); print(t if isinstance(t,str) else (t.get("jti") if isinstance(t,dict) else ""))')

R1=$(curl -sS -X POST $BASE/api/rtp/consume -H "Content-Type: application/json" -d "{\"ticket\":\"$JTI\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")
R2=$(curl -sS -X POST $BASE/api/rtp/consume -H "Content-Type: application/json" -d "{\"ticket\":\"$JTI\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}")

export R1="$R1"
export R2="$R2"

echo "R1_RAW=$R1"
echo "R2_RAW=$R2"

python3 - <<'PY_REPLAY' || fail "replay not denied"
# [AUTO-COMMENTED: invalid in bash] import os, json, sys, re
r1 = os.environ.get("R1","")
r2 = os.environ.get("R2","")
if not r2.strip():
    raise SystemExit("R2_EMPTY")

def parse(x):
    try: return json.loads(x)
    except Exception: return {"raw": x}

o2 = parse(r2)
txt = (json.dumps(o2) if isinstance(o2,(dict,list)) else str(o2)).lower()

ok = False
if isinstance(o2, dict):
    if o2.get("valid") is False: ok = True
    if str(o2.get("decision","")).upper() in ("DENY","DENIED"): ok = True
    if "detail" in o2 and "replay" in str(o2["detail"]).lower(): ok = True
if ("replay" in txt) or ("deny" in txt) or ("denied" in txt):
    ok = True

if not ok:
    raise SystemExit("R2_NOT_DENIAL: " + txt[:200])

print("✅ REPLAY_DENIED_OK")
PY_REPLAY

echo "$R1" | grep -qi allow || fail "first consume"
# [AUTO-COMMENTED: invalid in bash] import json,sys
r2 = sys.stdin.read().strip()
try:
    o=json.loads(r2)
except Exception:
    o={"raw": r2}
txt=str(o).lower()
ok = (
    (isinstance(o,dict) and (o.get("valid") is False))
    or (isinstance(o,dict) and str(o.get("decision","")).upper() in ("DENY","DENIED"))
    or ("replay" in txt)
    or ("denied" in txt)
    or ("deny" in txt)
)
if not ok:
    raise SystemExit("R2 did not look like denial: "+str(o))
print("REPLAY_DENIED_OK")
PY2
<<<"$R2"
echo "✅ REPLAY_OK"

echo "== D. Tool mismatch =="
T=$(curl -sS -X POST $BASE/api/rtp/decide -H "Content-Type: application/json" -d '{"tool_name":"read.me","agent_id":"evil"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["ticket"] if isinstance(o.get("ticket"), str) else o["ticket"].get("jti"))')
MM=$(curl -sS -X POST $BASE/api/rtp/consume -H "Content-Type: application/json" -d "{\"ticket\":\"$T\",\"tool_name\":\"shell.exec\",\"agent_id\":\"evil\"}")
echo "$MM" | grep -qi deny || fail "tool mismatch"
echo "✅ TOOL_MISMATCH_OK"

echo "== E. Tamper =="
BAD="${T%?}x"
TP=$(curl -sS -X POST $BASE/api/rtp/consume -H "Content-Type: application/json" -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"evil\"}")
echo "$TP" | grep -qi deny || fail "tamper"
echo "✅ TAMPER_OK"

echo "== F. Redis kill =="
docker stop kasbah-core-redis-1 >/dev/null 2>&1 || true
sleep 3
curl -fsS $BASE/health >/dev/null || fail "api died without redis"
docker start kasbah-core-redis-1 >/dev/null 2>&1 || true
echo "✅ REDIS_FALLBACK_OK"

echo "== G. Malformed JSON =="
curl -sS -X POST $BASE/api/rtp/decide -d '{' >/dev/null 2>&1 || true
curl -fsS $BASE/health >/dev/null || fail "crash on malformed json"
echo "✅ MALFORMED_OK"

echo "== H. Burst =="
for i in {1..80}; do curl -s -o /dev/null $BASE/api/rtp/decide & done
wait || true
curl -fsS $BASE/health >/dev/null || fail "burst crash"
echo "✅ BURST_OK"

echo "=============================="
echo "🎯 ALL CORE MOATS PASSED"
echo "=============================="
