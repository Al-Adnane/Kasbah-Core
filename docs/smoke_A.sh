#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "missing $1"; exit 1; }; }
need curl; need python3

OA="$(curl -sS "$BASE/openapi.json")"

# Find POST endpoint under /api/rtp/ whose requestBody schema includes "ticket"
CONSUME_PATH="$(echo "$OA" | python3 -c '
import sys,json
o=json.load(sys.stdin)
paths=o.get("paths",{})
best=""
for p, spec in paths.items():
    if not p.startswith("/api/rtp/"): 
        continue
    post = None
    for k,v in spec.items():
        if k.lower()=="post":
            post=v
    if not post: 
        continue
    if p.endswith("/decide") or p.endswith("/audit"): 
        continue
    rb = post.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
    # brute scan schema json for "ticket"
    txt = json.dumps(rb)
    if "ticket" in txt:
        best=p
        break
print(best)
')"

echo "consume_path=$CONSUME_PATH"
if [ -z "$CONSUME_PATH" ]; then
  echo "NO_CONSUME_ENDPOINT_WITH_TICKET_IN_SCHEMA"
  echo "Known RTP paths:"
  BASE="$BASE" ./demo/rtp_paths.sh || true
  exit 9
fi

DECIDE="$(curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","usage":{"tokens":0,"cost":0,"agent_id":"smoke"},"signals":{"consistency":0.98,"pred_accuracy":0.96,"normality":0.10}}')"

DECISION="$(echo "$DECIDE" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("decision",""))')"
echo "decision=$DECISION"

TICKET="$(echo "$DECIDE" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d.get("ticket"); print(t if isinstance(t,str) else "")')"
echo "ticket_bytes=${#TICKET}"

if [ -z "$TICKET" ]; then
  echo "NO_TICKET_RETURNED (policy likely DENY)"
  exit 2
fi

C1="$(curl -sS -X POST "$BASE$CONSUME_PATH" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"},\"signals\":{\"consistency\":0.98,\"pred_accuracy\":0.96,\"normality\":0.10}}")"
echo "$C1" | head -c 220; echo
echo "$C1" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("status") in ("ALLOWED","OK","allowed"); print("consume1_ok")'

set +e
C2="$(curl -sS -X POST "$BASE$CONSUME_PATH" \
  -H "Content-Type: application/json" \
  -d "{\"ticket\":\"$TICKET\",\"tool_name\":\"read.me\",\"usage\":{\"tokens\":0,\"cost\":0,\"agent_id\":\"smoke\"},\"signals\":{\"consistency\":0.98,\"pred_accuracy\":0.96,\"normality\":0.10}}")"
RC=$?
set -e
echo "replay_http_rc=$RC"
echo "$C2" | head -c 220; echo
if [ "$RC" -eq 0 ]; then
  echo "REPLAY_DID_NOT_FAIL"
  exit 3
fi

A="$(curl -sS "$BASE/api/rtp/audit?limit=5")"
echo "$A" | head -c 220; echo
echo "$A" | python3 -c 'import sys,json; a=json.load(sys.stdin); assert isinstance(a,list); print("audit_items", len(a))'

echo "PASS_LOCK_A"
