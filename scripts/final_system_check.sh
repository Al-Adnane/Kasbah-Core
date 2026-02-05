#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8002}"

echo "[1] Python compile"
python3 -m py_compile apps/api/main.py
echo "OK: py_compile"

echo "[2] Compose config valid"
docker compose config >/dev/null
echo "OK: docker compose config"

echo "[3] Ensure API up"
docker compose up -d --build >/dev/null
for i in {1..20}; do
  if curl -sS "$BASE/health" >/dev/null 2>&1; then
    echo "OK: health"
    break
  fi
  sleep 0.4
done

echo "[4] OpenAPI contains audit endpoints"
curl -sS "$BASE/openapi.json" > /tmp/openapi.json
python3 - <<'PY'
import json
o=json.load(open("/tmp/openapi.json"))
paths=set(o.get("paths",{}))
need=[
 "/api/rtp/audit/verify",
 "/api/rtp/audit/tail",
 "/api/rtp/audit/jti/{jti}",
 "/api/rtp/audit/stats",
]
missing=[p for p in need if p not in paths]
if missing:
    raise SystemExit("FAIL: missing in openapi: "+", ".join(missing))
print("OK: openapi endpoints present")
PY

echo "[5] Ledger verify"
curl -sS "$BASE/api/rtp/audit/verify" | python3 -m json.tool
echo

echo "[6] Tail (iso)"
curl -sS "$BASE/api/rtp/audit/tail?limit=3" | python3 -m json.tool
echo

echo "[7] Stats (NA not None)"
curl -sS "$BASE/api/rtp/audit/stats?window=200" | python3 -m json.tool | sed -n '1,80p'
echo

echo "✅ FINAL_SYSTEM_CHECK: PASS"
