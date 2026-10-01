#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"
AUTH="${AUTH:-Bearer dev-master-key}"

say(){ printf "\n== %s ==\n" "$1"; }

say "Boot"
docker compose up -d --build

say "Health"
curl -sS "$BASE/health" ; echo

say "Moat Map (live)"
curl -sS "$BASE/api/system/moats" | python3 -m json.tool | sed -n '1,240p'

say "Decide (read.me)"
DEC="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d '{"tool_name":"read.me","agent_id":"atlaszak","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.99,"latency_score":0.99},"usage":{"args":{"doc":"hello","page":1}}}')"
echo "$DEC" | python3 -m json.tool | sed -n '1,80p'

JWT="$(printf '%s' "$DEC" | python3 -c 'import sys,json
d=json.load(sys.stdin); t=d.get("ticket","")
print(t if isinstance(t,str) else (t.get("ticket","") if isinstance(t,dict) else ""))
')"
[ -n "$JWT" ] || { echo "NO_JWT"; exit 2; }
echo "jwt_len=${#JWT}"

say "Verify (shows TTL + bindings)"
curl -sS -X POST "$BASE/api/rtp/verify" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT\"}" \
| python3 -m json.tool | sed -n '1,200p'

say "Consume (happy path)"
curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT\",\"tool_name\":\"read.me\",\"agent_id\":\"atlaszak\",\"args\":{\"doc\":\"hello\",\"page\":1},\"usage\":{\"tokens\":0,\"cost\":0}}" \
| python3 -m json.tool

say "Tamper (1 char) must fail"
BAD="${JWT%?}x"
CODE="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$BAD\",\"tool_name\":\"read.me\",\"agent_id\":\"atlaszak\",\"args\":{\"doc\":\"hello\",\"page\":1},\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "tamper_http=$CODE (expect 401)"

say "Replay (re-consume legit token) must fail"
CODE2="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT\",\"tool_name\":\"read.me\",\"agent_id\":\"atlaszak\",\"args\":{\"doc\":\"hello\",\"page\":1},\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "replay_http=$CODE2 (expect 409)"

say "Tool mismatch must fail"
DEC2="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d '{"tool_name":"read.me","agent_id":"atlaszak","signals":{"consistency":0.99},"usage":{"args":{"doc":"hello","page":1}}}')"
JWT2="$(printf '%s' "$DEC2" | python3 -c 'import sys,json
d=json.load(sys.stdin); t=d.get("ticket",""); print(t if isinstance(t,str) else (t.get("ticket","") if isinstance(t,dict) else ""))
')"
CODE3="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT2\",\"tool_name\":\"shell.exec\",\"agent_id\":\"atlaszak\",\"args\":{\"doc\":\"hello\",\"page\":1},\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "mismatch_http=$CODE3 (expect 400)"

say "Args mismatch must fail"
DEC3="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d '{"tool_name":"read.me","agent_id":"atlaszak","signals":{"consistency":0.99},"usage":{"args":{"doc":"hello","page":1}}}')"
JWT3="$(printf '%s' "$DEC3" | python3 -c 'import sys,json
d=json.load(sys.stdin); t=d.get("ticket",""); print(t if isinstance(t,str) else (t.get("ticket","") if isinstance(t,dict) else ""))
')"
CODE4="$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -H "Authorization: $AUTH" \
  -d "{\"ticket\":\"$JWT3\",\"tool_name\":\"read.me\",\"agent_id\":\"atlaszak\",\"args\":{\"doc\":\"hello\",\"page\":2},\"usage\":{\"tokens\":0,\"cost\":0}}" || true)"
echo "args_mismatch_http=$CODE4 (expect 400)"

say "Audit-chain verify"
curl -sS "$BASE/api/rtp/audit_chain/verify" | python3 -m json.tool | sed -n '1,120p'

say "Audit (last 10)"
curl -sS "$BASE/api/rtp/audit?limit=10" | python3 -m json.tool | sed -n '1,220p'

say "DONE"
echo
echo "Now open the Control Room:"
echo "  $BASE/atlaszak"
