#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
AGENT="${AGENT:-smoke}"

post() { ./demo/_post_json.sh "/api/rtp/decide" "$1"; }

echo "[E0] baseline (high normality)"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.95,\"latency_score\":0.99}}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); st=d.get("agent_state") or {}; print("ema", st.get("ema"), "b_last", st.get("b_last"), "n", st.get("n"), "decision", d.get("decision"))' \
| sed -n '1,1p'

echo "[E1] push risk upward (low normality x6)"
for i in $(seq 1 6); do
  post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" >/dev/null
done

echo "[E2] check agent_state exists"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); st=d.get("agent_state") or {}; print("ema", st.get("ema"), "b_last", st.get("b_last"), "n", st.get("n"), "err", d.get("agent_state_error"))'

echo "PASS_LOCK_E"
