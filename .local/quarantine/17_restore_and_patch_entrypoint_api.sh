#!/usr/bin/env bash
set -euo pipefail

CN="kasbah-core-api-1"
BAK="/app/scripts/entrypoint_api.sh.bak.20260206_020953"

echo "== Restore entrypoint_api.sh from backup and apply clean patch =="

docker exec -it "$CN" sh -lc "
set -e

if [ ! -f '$BAK' ]; then
  echo 'FAIL: backup not found: $BAK'
  ls -la /app/scripts/entrypoint_api.sh.bak.* || true
  exit 1
fi

cp -v '$BAK' /app/scripts/entrypoint_api.sh

# 1) Guard slo_probe.sh line safely (no expansions)
# Replace the exact line that calls slo_probe.sh with a guarded block.
awk '
  {
    if (\$0 ~ /BASE=http:\\/\\/127\\.0\\.0\\.1:8002 \\/app\\/scripts\\/slo_probe\\.sh/){
      print \"    if [ -f /app/scripts/slo_probe.sh ]; then\"
      print \"      BASE=http://127.0.0.1:8002 /app/scripts/slo_probe.sh >/tmp/slo.log 2>&1 || true\"
      print \"    else\"
      print \"      echo \\\"WARN: /app/scripts/slo_probe.sh missing (skipping)\\\" >/tmp/slo.log 2>&1 || true\"
      print \"    fi\"
      next
    }
    print
  }
' /app/scripts/entrypoint_api.sh > /tmp/entrypoint_api.sh.new
mv /tmp/entrypoint_api.sh.new /app/scripts/entrypoint_api.sh

# 2) Insert Redis preflight block BEFORE cd /app (only if not already there)
if ! grep -q 'KASBAH_REDIS_PREFLIGHT' /app/scripts/entrypoint_api.sh; then
  awk '
    BEGIN{inserted=0}
    {
      if (!inserted && \$0 ~ /^cd \\/app/){
        print \"# --- KASBAH_REDIS_PREFLIGHT ---\"
        print \"REDIS_HOST=\\\"\\${REDIS_HOST:-redis}\\\"\"
        print \"REDIS_PORT=\\\"\\${REDIS_PORT:-6379}\\\"\"
        print \"if [ \\\"\\${PRODUCTION:-0}\\\" = \\\"1\\\" ]; then\"
        print \"  echo \\\"INFO: PRODUCTION=1 -> requiring Redis at \\${REDIS_HOST}:\\${REDIS_PORT}\\\"\"
        print \"  python3 - <<\\x27PY\\x27\"
        print \"import os, socket, sys\"
        print \"host=os.environ.get(\\x27REDIS_HOST\\x27,\\x27redis\\x27)\"
        print \"port=int(os.environ.get(\\x27REDIS_PORT\\x27,\\x276379\\x27))\"
        print \"s=socket.socket(); s.settimeout(1.0)\"
        print \"try:\"
        print \"    s.connect((host,port))\"
        print \"except Exception as e:\"
        print \"    print(\\x27FATAL: PRODUCTION=1 requires Redis but connection failed:\\x27, e)\"
        print \"    sys.exit(1)\"
        print \"finally:\"
        print \"    try: s.close()\"
        print \"    except: pass\"
        print \"print(\\x27OK: Redis reachable\\x27)\"
        print \"PY\"
        print \"fi\"
        print \"\"
        inserted=1
      }
      print
    }
  ' /app/scripts/entrypoint_api.sh > /tmp/entrypoint_api.sh.new
  mv /tmp/entrypoint_api.sh.new /app/scripts/entrypoint_api.sh
fi

chmod +x /app/scripts/entrypoint_api.sh

echo
echo '== Final entrypoint_api.sh (1..120) =='
nl -ba /app/scripts/entrypoint_api.sh | sed -n '1,120p'
"
