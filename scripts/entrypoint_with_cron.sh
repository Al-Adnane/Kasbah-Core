#!/usr/bin/env sh
set -e

# Ensure scripts are executable
chmod +x /app/scripts/*.sh || true

# Install cron job (every 5 minutes: rotate logs + SLO probe)
CRON_FILE="/etc/crontabs/root"
echo "*/5 * * * * /app/scripts/rotate_kasbah_logs.sh >/tmp/rotate.log 2>&1" > "$CRON_FILE"
echo "*/5 * * * * BASE=http://127.0.0.1:8002 /app/scripts/slo_probe.sh >/tmp/slo.log 2>&1" >> "$CRON_FILE"

# Start cron (busybox crond)
crond

# Exec original CMD
exec "$@"
