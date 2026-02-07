#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

call() {
  local agent="$1"
  curl -sS -X POST "$BASE/api/rtp/decide" \
    -H "Content-Type: application/json" \
    -d "{\"tool_name\":\"read.me\",\"agent_id\":\"$agent\",\"signals\":{\"consistency\":0.80,\"pred_accuracy\":0.80,\"normality\":0.80,\"latency_score\":0.80}}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(\"$agent\", d.get('decision'), 'thr=',d.get('threshold'),'int=',d.get('integrity_score'))"
}

call "trusted"
call "untrusted"
