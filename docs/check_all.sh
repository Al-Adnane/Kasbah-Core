#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

echo "== 0) compile check (host) =="
python3 -m py_compile apps/api/main.py
python3 -m py_compile apps/api/rtp/kernel_gate.py
python3 -m py_compile apps/api/rtp/agent_state.py
python3 -m py_compile apps/api/rtp/geometry.py
echo "OK py_compile"

echo "== 1) docker compose config sanity =="
docker compose config >/dev/null
echo "OK compose config"

echo "== 2) rebuild + start =="
docker compose up -d --build
docker compose ps

echo "== 3) health stable (needs 5 consecutive OK within 10s) =="
ok=0
start=$(date +%s)
while true; do
  if curl -sS "$BASE/health" >/dev/null 2>&1; then
    ok=$((ok+1))
  else
    ok=0
  fi
  if [ "$ok" -ge 5 ]; then
    echo "OK health stable"
    break
  fi
  now=$(date +%s)
  if [ $((now-start)) -ge 10 ]; then
    echo "FAIL health never stabilized"
    exit 1
  fi
  sleep 0.3
done

echo "== 4) openapi sanity (rtp endpoints exist) =="

# retry openapi fetch for up to 10 seconds (handles occasional resets)
ok=0
start=$(date +%s)
while true; do
  if curl -sS "$BASE/openapi.json" > /tmp/openapi.json 2>/dev/null; then
    if python3 -c 'import json,sys; json.load(open("/tmp/openapi.json")); print("OK json")' >/dev/null 2>&1; then
      ok=1
      break
    fi
  fi
  now=$(date +%s)
  if [ $((now-start)) -ge 10 ]; then
    echo "FAIL openapi fetch/json"
    echo "---- first 40 lines of response ----"
    sed -n '1,40p' /tmp/openapi.json 2>/dev/null || true
    exit 1
  fi
  sleep 0.3
done

python3 - <<'PY'
import json
o=json.load(open("/tmp/openapi.json"))
paths=o.get("paths",{})
need = ["/health", "/api/rtp/decide", "/api/rtp/agent/{agent_id}/state"]
missing=[p for p in need if p not in paths]
if missing:
    raise SystemExit("MISSING_PATHS " + str(missing))
print("OK openapi paths")
PY

echo "== 5) E+F smoke =="
BASE="$BASE" ./demo/smoke_EF.sh

echo "PASS_LOCK_ALL"
