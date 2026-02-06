#!/usr/bin/env bash
set -euo pipefail

export KASBAH_BASE_URL="${KASBAH_BASE_URL:-http://127.0.0.1:8002}"

echo "== docker up (clean) =="
docker compose down --remove-orphans || true
docker network prune -f >/dev/null 2>&1 || true
docker compose up --build -d

echo "== wait for API readiness =="
python3 - <<'PY'
import time, sys, os, requests
base = os.environ.get("KASBAH_BASE_URL","http://127.0.0.1:8002")
url = base + "/health"
for i in range(80):  # 40 seconds
    try:
        r = requests.get(url, timeout=1.5)
        if r.status_code == 200:
            print("READY:", r.text)
            sys.exit(0)
    except Exception:
        pass
    time.sleep(0.5)
print("NOT READY after 40s")
sys.exit(2)
PY

echo "== run suite =="
python test_kasbah_integrated.py
