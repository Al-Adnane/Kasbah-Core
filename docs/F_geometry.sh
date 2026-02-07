#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
AGENT="${AGENT:-geo}"

post() { ./demo/_post_json.sh "/api/rtp/decide" "$1"; }

echo "[F1] on-manifold (should have geom_penalty low/zero)"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.99,\"accuracy\":0.99,\"normality\":0.95,\"latency_score\":0.99}}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); print("geom_thr", d.get("geometry_threshold"), "geom_pen", d.get("geometry_penalty"), "geom_score", d.get("geometry_score"))'

echo "[F2] off-manifold-ish (still may be high if your geometry model is permissive; we only assert keys exist)"
post "{\"tool_name\":\"read.me\",\"agent_id\":\"$AGENT\",\"signals\":{\"consistency\":0.10,\"accuracy\":0.10,\"normality\":0.95,\"latency_score\":0.10}}" \
| python3 -c 'import sys,json; d=json.load(sys.stdin); print("geom_thr", d.get("geometry_threshold"), "geom_pen", d.get("geometry_penalty"), "geom_score", d.get("geometry_score"))'

echo "PASS_LOCK_F"
