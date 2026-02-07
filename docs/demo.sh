#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

echo "== up check: docker ps =="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | sed -n '1,20p'

echo "== waiting for API on $BASE/health =="
ok=0
for i in $(seq 1 50); do
  if curl -fsS "$BASE/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.2
done

if [ "$ok" -ne 1 ]; then
  echo "FAILED: API not reachable"
  echo "== docker ps =="
  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  echo "== api logs (tail 200) =="
  docker logs --tail 200 kasbah-core-api-1 || true
  exit 7
fi

echo "== health =="
curl -sS "$BASE/health" ; echo

echo "== replay test =="
BASE="$BASE" ./demo/replay_test.sh

echo "== ledger rows =="
docker exec -it kasbah-core-api-1 sh -lc 'python -c "import sqlite3; con=sqlite3.connect(\"/app/data/rtp_audit.sqlite\"); print(con.execute(\"select count(*) from audit_ledger\").fetchone()[0]); con.close()"'
