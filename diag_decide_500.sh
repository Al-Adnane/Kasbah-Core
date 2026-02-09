#!/usr/bin/env bash
set -u

BASE="http://127.0.0.1:8002"

echo "=== 0) basic endpoints ==="
echo "--- health ---"
curl -sS "$BASE/health" ; echo
echo

echo "--- openapi (first 30 lines) ---"
curl -sS "$BASE/openapi.json" | head -n 30 || true
echo

echo "=== 1) call decide with -v (shows status + headers) ==="
echo "--- decide (no auth) ---"
curl -v -sS -X POST "$BASE/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"read.me","agent_id":"step7","signals":{"consistency":0.99}}' \
  2>&1 | sed -n '1,120p'
echo

echo "=== 2) docker compose status ==="
docker compose ps
echo

echo "=== 3) last 200 lines of API logs (this should show the Python traceback) ==="
docker compose logs --no-color --tail=200 api || true
echo

echo "=== 4) print key env vars inside api container (redact secrets by showing only prefix/len) ==="
CN="$(docker compose ps -q api | head -n 1)"
if [[ -z "${CN:-}" ]]; then
  echo "NO_API_CONTAINER_ID"
  exit 1
fi

docker exec -i "$CN" sh -lc '
set -e
echo "REDIS_URL=${REDIS_URL:-<unset>}"
echo "KASBAH_RL_DECIDE_LIMIT=${KASBAH_RL_DECIDE_LIMIT:-<unset>}"
echo "KASBAH_GEOMETRY_THRESHOLD=${KASBAH_GEOMETRY_THRESHOLD:-<unset>}"
echo "DATA_DIR=${DATA_DIR:-<unset>}"
echo "FALLBACK_PATH=${FALLBACK_PATH:-<unset>}"

if [ -n "${API_KEY:-}" ]; then
  echo "API_KEY_LEN=${#API_KEY} API_KEY_PREFIX=${API_KEY%%????????????????????????????????????????????????????????????????????????????????????????}"
else
  echo "API_KEY=<unset>"
fi

if [ -n "${DEV_MASTER_KEY:-}" ]; then
  echo "DEV_MASTER_KEY_LEN=${#DEV_MASTER_KEY}"
else
  echo "DEV_MASTER_KEY=<unset>"
fi
'
echo

echo "=== 5) quick filesystem sanity (state dir / permissions) ==="
docker exec -i "$CN" sh -lc '
set -e
ls -la /app | sed -n "1,120p" || true
echo
find /app -maxdepth 3 -type d -name ".kasbah" -o -name "data" 2>/dev/null | head -n 50 || true
'
