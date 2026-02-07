#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

echo "[0] health"
curl -sS "$BASE/health" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["status"]=="operational"; print("OK health")'

echo "[1] decide -> E should move"
out="$(curl -sS -X POST "$BASE/api/rtp/decide" -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"accuracy":0.99,"normality":0.01,"latency_score":0.99}}')"

python3 - <<PY
import json
d=json.loads("""$out""")
assert d.get("detail") is None
assert d.get("agent_state_error") is None
st=d.get("agent_state") or {}
assert st.get("b_last") is not None and st["b_last"] > 0.90
assert st.get("ema") is not None and st["ema"] > 0.0
assert d.get("geometry_penalty") == 0.0
print("PASS_LOCK_EF", "ema", st["ema"], "b_last", st["b_last"], "geom_thr", d.get("geometry_threshold"))
PY
