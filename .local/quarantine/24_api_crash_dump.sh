#!/usr/bin/env sh
set -e

CN="kasbah-core-api-1"

echo "== compose ps =="
docker compose ps

echo
echo "== api container state (restart count / exit / oom) =="
docker inspect "$CN" --format \
'Name={{.Name}}
State={{json .State}}
RestartCount={{.RestartCount}}
HostConfig.RestartPolicy={{json .HostConfig.RestartPolicy}}' || true

echo
echo "== last 220 api logs =="
docker logs --tail 220 "$CN" || true

echo
echo "== wait up to 15s for /health (prints first success) =="
i=0
while [ "$i" -lt 15 ]; do
  if curl -fsS http://127.0.0.1:8002/health >/tmp/health.json 2>/tmp/health.err; then
    echo "OK /health:"
    cat /tmp/health.json
    echo
    exit 0
  fi
  i=$((i+1))
  sleep 1
done

echo "FAIL: /health never became ready (15s). curl error:"
cat /tmp/health.err || true
echo
echo "== last 120 api logs (again) =="
docker logs --tail 120 "$CN" || true
exit 1
