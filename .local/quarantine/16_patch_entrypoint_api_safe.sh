#!/usr/bin/env bash
set -euo pipefail

CN="kasbah-core-api-1"

echo "== Safe patch entrypoint_api.sh (no python) =="

docker exec -it "$CN" sh -lc '
set -e
cp -v /app/scripts/entrypoint_api.sh /app/scripts/entrypoint_api.sh.bak.$(date +%Y%m%d_%H%M%S)

# 1) Guard missing slo_probe.sh (replace the exact line)
perl -0777 -i -pe '"'"'s@^\s*BASE=http://127\.0\.0\.1:8002\s+/app/scripts/slo_probe\.sh\s+>/tmp/slo\.log 2>&1 \|\| true\s*$@    if [ -f /app/scripts/slo_probe.sh ]; then\n      BASE=http://127.0.0.1:8002 /app/scripts/slo_probe.sh >/tmp/slo.log 2>&1 || true\n    else\n      echo "WARN: /app/scripts/slo_probe.sh missing (skipping)" >/tmp/slo.log 2>&1 || true\n    fi@mg'"'"' /app/scripts/entrypoint_api.sh

# 2) Insert PRODUCTION Redis fail-closed block before "cd /app" (only if not already present)
if ! grep -q "PRODUCTION fail-closed: Redis must be reachable" /app/scripts/entrypoint_api.sh; then
  perl -0777 -i -pe '"'"'s@\ncd /app\n@\n\n# --- PRODUCTION fail-closed: Redis must be reachable ---\nREDIS_HOST=\"${REDIS_HOST:-redis}\"\nREDIS_PORT=\"${REDIS_PORT:-6379}\"\nif [ \"${PRODUCTION:-0}\" = \"1\" ]; then\n  echo \"INFO: PRODUCTION=1 -> requiring Redis at ${REDIS_HOST}:${REDIS_PORT}\"\n  python3 -c \"import os,socket,sys; h=os.environ.get(\\\"REDIS_HOST\\\",\\\"redis\\\"); p=int(os.environ.get(\\\"REDIS_PORT\\\",\\\"6379\\\")); s=socket.socket(); s.settimeout(1.0);\\\n  \\\n  (lambda: None)();\\\n  \\\n  \\\n  \\\n  \\\n  \\\n  \" 2>/dev/null || true\n  python3 - <<\"PY\"\nimport os, socket, sys\nhost=os.environ.get(\"REDIS_HOST\",\"redis\")\nport=int(os.environ.get(\"REDIS_PORT\",\"6379\"))\ns=socket.socket()\ns.settimeout(1.0)\ntry:\n    s.connect((host,port))\nexcept Exception as e:\n    print(\"FATAL: PRODUCTION=1 requires Redis but connection failed:\", e)\n    sys.exit(1)\nfinally:\n    try: s.close()\n    except: pass\nprint(\"OK: Redis reachable\")\nPY\nfi\n\ncd /app\n@'"'"' /app/scripts/entrypoint_api.sh
fi

echo
echo "== Show patched entrypoint_api.sh (1..120) =="
nl -ba /app/scripts/entrypoint_api.sh | sed -n "1,120p"
'
