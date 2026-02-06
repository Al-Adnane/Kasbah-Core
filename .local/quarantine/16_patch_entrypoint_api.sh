#!/usr/bin/env bash
set -euo pipefail

CN="kasbah-core-api-1"

echo "== Patch entrypoint_api.sh (slo guard + production redis fail-closed) =="

docker exec -it "$CN" sh -lc '
set -e
cp -v /app/scripts/entrypoint_api.sh /app/scripts/entrypoint_api.sh.bak.$(date +%Y%m%d_%H%M%S)

python3 - <<'"'"'PY'"'"'
from pathlib import Path
p=Path("/app/scripts/entrypoint_api.sh")
s=p.read_text().splitlines()

out=[]
inserted=False
for line in s:
    # Guard slo_probe
    if "slo_probe.sh" in line and "BASE=http" in line:
        out.append('    if [ -f /app/scripts/slo_probe.sh ]; then')
        out.append('      BASE=http://127.0.0.1:8002 /app/scripts/slo_probe.sh >/tmp/slo.log 2>&1 || true')
        out.append('    else')
        out.append('      echo "WARN: /app/scripts/slo_probe.sh missing (skipping)" >/tmp/slo.log 2>&1 || true')
        out.append('    fi')
        continue
    out.append(line)

# Inject Redis preflight right before "cd /app"
new=[]
for i,line in enumerate(out):
    if (not inserted) and line.strip() == "cd /app":
        new += [
            "",
            "# --- PRODUCTION fail-closed: Redis must be reachable ---",
            'REDIS_HOST="${REDIS_HOST:-redis}"',
            'REDIS_PORT="${REDIS_PORT:-6379}"',
            'if [ "${PRODUCTION:-0}" = "1" ]; then',
            '  echo "INFO: PRODUCTION=1 -> requiring Redis at ${REDIS_HOST}:${REDIS_PORT}"',
            "  python3 - <<'PY'",
            "import os, socket, sys",
            "host=os.environ.get('REDIS_HOST','redis')",
            "port=int(os.environ.get('REDIS_PORT','6379'))",
            "s=socket.socket()",
            "s.settimeout(1.0)",
            "try:",
            "    s.connect((host,port))",
            "except Exception as e:",
            "    print('FATAL: PRODUCTION=1 requires Redis but connection failed:', e)",
            "    sys.exit(1)",
            "finally:",
            "    try: s.close()",
            "    except: pass",
            "print('OK: Redis reachable')",
            "PY",
            "fi",
            "",
        ]
        inserted=True
    new.append(line)

p.write_text("\n".join(new) + "\n")
print("OK: patched entrypoint_api.sh")
PY

echo
echo "== Show patched entrypoint_api.sh =="
nl -ba /app/scripts/entrypoint_api.sh | sed -n "1,140p"
'
