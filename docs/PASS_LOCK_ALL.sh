#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"

echo "== 1) health stable (needs 5 consecutive OK within 10s) =="
ok=0
for i in $(seq 1 50); do
  if ./demo/_get_json.sh "/health" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("status")=="operational"; print("OK")' >/dev/null 2>&1; then
    ok=$((ok+1))
    [ "$ok" -ge 5 ] && break
  else
    ok=0
  fi
  sleep 0.2
done
[ "$ok" -ge 5 ] && echo "OK health stable" || (echo "FAIL health stable" && exit 1)

echo "== 2) openapi sanity (consume exists) =="
./demo/_get_json.sh "/openapi.json" | python3 -c 'import sys,json; o=json.load(sys.stdin); assert "/api/rtp/decide" in o.get("paths", {}); assert "/api/rtp/consume" in o.get("paths", {}); print("OK openapi paths")'

echo "== 3) E =="
BASE="$BASE" ./demo/state_E.sh

echo "== 4) F =="
BASE="$BASE" ./demo/F_geometry.sh

echo "== 5) G =="
BASE="$BASE" ./demo/state_G.sh

echo "== 6) H =="
BASE="$BASE" ./demo/state_H.sh

echo "== 7) I+J =="
BASE="$BASE" ./demo/state_IJ.sh

echo "PASS_LOCK_ALL"
