#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== PROD requires Redis test =="

echo
echo "1) Stop redis"
docker compose stop redis

echo
echo "2) Restart api in PRODUCTION=1 (should fail-closed if Redis mandatory)"
# We inject env at compose runtime for this test only
PRODUCTION=1 docker compose up -d --force-recreate api

echo
echo "3) Show api status"
docker compose ps api

echo
echo "4) Show last 80 api logs (look for Redis requirement / connection failure)"
docker logs --tail 80 kasbah-core-api-1 || true

echo
echo "5) Health probe (should FAIL if api refused to start)"
BASE="${BASE:-http://127.0.0.1:8002}"
curl -sS "$BASE/health" || echo "Health failed (expected if api is down)"

echo
echo "6) Restore: start redis + restart api normally"
docker compose up -d redis
docker compose restart api

echo
echo "7) Final status"
docker compose ps api redis
