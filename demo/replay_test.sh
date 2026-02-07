#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:8002}"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Decide
curl -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"replay-test","signals":{"consistency":0.99,"pred_accuracy":0.99,"normality":0.99,"latency_score":0.99}}' \
  > "$TMP"

# Inspect + extract ticket
python3 - "$TMP" <<'PY'
import json,sys
path=sys.argv[1]
with open(path,"r") as f:
    d=json.load(f)

print("decision", d.get("decision"))
if d.get("decision")!="ALLOW":
    print("deny_reason", d.get("reason"))
    raise SystemExit(12)

print("jti", d["ticket"]["jti"])

with open("/tmp/payload.json","w") as f:
    json.dump({"ticket": d["ticket"], "tool_name":"read.me"}, f)
PY

echo "== consume #1 =="
curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d @/tmp/payload.json ; echo

echo "== consume #2 (replay) =="
curl -sS -X POST "$BASE/api/rtp/consume" \
  -H "Content-Type: application/json" \
  -d @/tmp/payload.json ; echo
