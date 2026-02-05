#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

for i in $(seq 1 50); do
  curl -fsS "$BASE/health" >/dev/null || { echo "health_fail_$i"; exit 1; }
done

for i in $(seq 1 50); do
  curl -fsS -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -d '{"tool_name":"read.me","agent_id":"smoke","signals":{"consistency":0.99,"pred_accuracy":0.99,"normality":0.99,"latency_score":0.99}}' \
    >/dev/null || { echo "decide_fail_$i"; exit 2; }
done

echo "HAMMER_PASS"
