#!/usr/bin/env sh
set -e

chmod +x /app/scripts/*.sh 2>/dev/null || true

# Background maintenance loop (every 5 minutes)
(
  while true; do
    /app/scripts/rotate_kasbah_logs.sh >/tmp/rotate.log 2>&1 || true
    BASE=http://127.0.0.1:8002 /app/scripts/slo_probe.sh >/tmp/slo.log 2>&1 || true
    sleep 300
  done
) &

cd /app
export PYTHONPATH="/app:${PYTHONPATH}"
# Start API (hardcoded so it never exits due to empty CMD)
exec uvicorn apps.api.main:app --host 0.0.0.0 --port 8002
