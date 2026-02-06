#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== docker-compose.yml (caddy section) =="
python3 - <<'PY'
import re
from pathlib import Path
txt = Path("docker-compose.yml").read_text()
# print ~120 lines around the caddy service
m = re.search(r"(?ms)^\\s*caddy:\\s*\\n(.*?)(^\\S|\\Z)", txt)
if not m:
    print("FAIL: caddy service not found in docker-compose.yml")
else:
    block = m.group(0).splitlines()
    for i,line in enumerate(block[:140], start=1):
        print(f"{i:4d} {line}")
PY

echo
echo "== Caddyfile in repo root SHA =="
python3 - <<'PY'
import hashlib
from pathlib import Path
p=Path("Caddyfile")
print(hashlib.sha256(p.read_bytes()).hexdigest(), p)
PY

echo
echo "== docker compose config (resolved) - caddy volumes =="
docker compose config | sed -n '/^[[:space:]]*caddy:/,/^[^[:space:]]/p' | sed -n '1,200p'
