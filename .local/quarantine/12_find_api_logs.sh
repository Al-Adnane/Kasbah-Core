#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

CN="kasbah-core-api-1"

echo "== Docker state (api) =="
docker inspect "$CN" --format 'Name={{.Name}} Status={{.State.Status}} Running={{.State.Running}} Restarting={{.State.Restarting}} ExitCode={{.State.ExitCode}} StartedAt={{.State.StartedAt}} FinishedAt={{.State.FinishedAt}} OOMKilled={{.State.OOMKilled}}'
echo

echo "== Restart count =="
docker inspect "$CN" --format 'RestartCount={{.RestartCount}}'
echo

echo "== Logging driver =="
docker inspect "$CN" --format 'LogType={{.HostConfig.LogConfig.Type}}'
echo

echo "== docker logs (tail 120) =="
docker logs --tail 120 "$CN" || true
echo

echo "== Look for app logs INSIDE container =="
docker exec -it "$CN" sh -lc '
set -e
echo "--- pwd:"; pwd
echo "--- find likely logs (top 40) ---"
find /app /var/log /tmp -maxdepth 3 -type f \( -name "*.log" -o -name "server.log" -o -name "api.log" -o -name "*uvicorn*" \) 2>/dev/null | head -n 40
echo
echo "--- list /app (top) ---"
ls -la /app 2>/dev/null | sed -n "1,120p" || true
echo
echo "--- tail common log names if present ---"
for f in /app/api.log /app/server.log /app/kasbah.log /var/log/* /tmp/*.log; do
  if [ -f "$f" ]; then
    echo "----- $f (tail 80) -----"
    tail -n 80 "$f" || true
    echo
  fi
done
'
