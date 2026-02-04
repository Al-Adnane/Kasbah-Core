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

# Start the original command
exec "$@"
