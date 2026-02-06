#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:8003"

echo "=== Kasbah Test Suite ==="
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

echo "1. Health check"
curl -s "$BASE/health" | jq . || curl -s "$BASE/health"

echo ""
echo "2. Benchmark (real latency after 200 requests)"
curl -s "$BASE/api/system/benchmark" | jq . || curl -s "$BASE/api/system/benchmark"

echo ""
echo "3. Normal decide (should get ALLOW + ticket)"
curl -s -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "read.me",
    "signals": {
      "consistency": 0.95,
      "accuracy": 0.92,
      "normality": 0.90,
      "latency_score": 0.88
    },
    "agent_id": "test-agent-001"
  }' | jq . || echo "Failed"

echo ""
echo "4. Malformed JSON (should get 422 — not 500 crash)"
curl -s -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{invalid json here' | jq . || echo "Expected 422"

echo ""
echo "5. Forbidden tool (should get DENY via allowlist)"
curl -s -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "rm -rf /",
    "signals": {"consistency": 0.99}
  }' | jq . || echo "Failed"

echo ""
echo "All tests done. Check server logs in Terminal 1 for details."
