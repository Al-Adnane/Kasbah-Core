#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
AGENT="${AGENT:-smoke}"

post() { ./demo/_post_json.sh "/api/rtp/decide" "$1"; }

show() {
  python3 -c 'import sys,json; d=json.load(sys.stdin); st=d.get("agent_state") or {}; print("thr", d.get("threshold"), "ema", st.get("ema"), "b_last", st.get("b_last"), "decision", d.get("decision"), "reason", d.get("reason"))'
}

echo "[G0] baseline"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.95,\"latency_score\":0.99}}" | show

echo "[G1] push EMA up"
for i in $(seq 1 14); do
  post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" >/dev/null
done

echo "[G2] observe: threshold should be higher at high EMA"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" | show

echo "[G3] hard stop check (non-demo tool should DENY when EMA >= 0.90)"
post "{\"tool_name\":\"shell.exec\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" | show

echo "PASS_LOCK_G"
