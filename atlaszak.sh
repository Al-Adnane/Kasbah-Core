#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE="http://127.0.0.1:8002"
AUTH="Bearer dev-master-key"

say() { printf "\n== %s ==\n" "$1"; }

say "Kasbah-Core — AtlasZak runtime test"

say "Booting system"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build --force-recreate

say "Waiting for health"
for i in {1..20}; do
  if curl -sS "$BASE/health" >/dev/null 2>&1; then
    echo "OK"
    break
  fi
  sleep 1
done

say "Health"
curl -sS "$BASE/health" ; echo

say "Decide (read.me)"
DEC="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"

echo "$DEC" | python3 -m json.tool | sed -n '1,40p'

JWT="$(printf '%s' "$DEC" | python3 - <<'PY'
import sys,json
d=json.load(sys.stdin)
t=d.get("ticket","")
print(t if isinstance(t,str) else (t.get("ticket","") if isinstance(t,dict) else ""))
PY
)"

echo "jwt_len=${#JWT}"

say "Tamper (1 char) must fail"
BAD="${JWT%?}x"
CODE="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "tamper_http=$CODE"

say "Consume (happy path)"
curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}" \
| python3 -m json.tool

say "Replay (re-consume legit token) must fail"
CODE2="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT\",\"tool_name\":\"read.me\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "replay_http=$CODE2"

say "Tool mismatch must fail"
DEC2="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99}}')"

JWT2="$(printf '%s' "$DEC2" | python3 - <<'PY'
import sys,json
d=json.load(sys.stdin)
t=d.get("ticket","")
print(t if isinstance(t,str) else (t.get("ticket","") if isinstance(t,dict) else ""))
PY
)"

CODE3="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT2\",\"tool_name\":\"shell.exec\",\"agent_id\":\"smoke\",\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "mismatch_http=$CODE3"

say "Audit (last 10)"
curl -sS "$BASE/api/rtp/audit?limit=10" | python3 -m json.tool

say "AtlasZak test complete"
