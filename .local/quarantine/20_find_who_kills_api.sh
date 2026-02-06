#!/usr/bin/env bash
set -euo pipefail

echo "== Compose status (api) =="
docker compose ps

echo
echo "== Events (last 2 minutes) =="
# Shows if Docker is restarting/stopping containers
docker events --since 2m --until 0s \
  --filter 'type=container' \
  --filter 'container=kasbah-core-api-1' \
  --filter 'event=stop' \
  --filter 'event=die' \
  --filter 'event=restart' \
  --filter 'event=kill' || true

echo
echo "== Inspect restart policy + healthcheck =="
docker inspect kasbah-core-api-1 --format \
'RestartPolicy={{json .HostConfig.RestartPolicy}} Healthcheck={{json .Config.Healthcheck}}'

echo
echo "== Exit code + OOMKilled + FinishedAt =="
docker inspect kasbah-core-api-1 --format \
'State={{json .State}}'

echo
echo "== Inside container: last 200 lines of /tmp/slo.log and /tmp/rotate.log =="
docker exec -it kasbah-core-api-1 sh -lc 'tail -n 200 /tmp/slo.log 2>/dev/null || true; echo "---"; tail -n 200 /tmp/rotate.log 2>/dev/null || true'

echo
echo "== Inside container: check if any supervisor/cron is running =="
docker exec -it kasbah-core-api-1 sh -lc 'ps aux | sed -n "1,200p"'
