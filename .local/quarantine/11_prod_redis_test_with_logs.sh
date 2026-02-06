#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${BASE:-http://127.0.0.1:8002}"

echo "== PROD requires Redis test (with logs) =="

echo
echo "A) Stop redis"
docker compose stop redis

echo
echo "B) Recreate api with PRODUCTION=1"
PRODUCTION=1 docker compose up -d --force-recreate api

echo
echo "C) Wait briefly then show api logs"
sleep 1
docker logs --tail 200 kasbah-core-api-1 || true

echo
echo "D) Try health (expect fail)"
curl -v --max-time 2 "$BASE/health" || true
echo

echo
echo "E) Show api logs again (after health probe)"
docker logs --tail 200 kasbah-core-api-1 || true

echo
echo "F) Restore redis and restart api normally"
docker compose up -d redis
docker compose restart api

echo
echo "G) Final health (expect OK)"
sleep 1
curl -sS "$BASE/health" || true
echo
