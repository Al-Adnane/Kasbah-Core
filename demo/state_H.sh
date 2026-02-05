#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
AGENT="${AGENT:-ttl-ticket}"

post() { ./demo/_post_json.sh "/api/rtp/decide" "$1"; }

echo "[H0] low EMA -> ttl ~60 and exp-iat ~60"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.95,\"latency_score\":0.99}}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); t=d.get("ticket") or {}; print("ema", (d.get("agent_state") or {}).get("ema"), "ttl", d.get("ttl_seconds"), "exp-iat", (t.get("exp",0)-t.get("iat",0)))'

echo "[H1] push EMA high"
for i in $(seq 1 18); do
  post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" >/dev/null
done

echo "[H2] high EMA -> ttl ~6 and exp-iat ~6"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.01,\"latency_score\":0.99}}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); t=d.get("ticket") or {}; print("ema", (d.get("agent_state") or {}).get("ema"), "ttl", d.get("ttl_seconds"), "exp-iat", (t.get("exp",0)-t.get("iat",0)))'

echo "PASS_LOCK_H"
