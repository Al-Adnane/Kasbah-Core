#!/usr/bin/env bash
set -euo pipefail

CN="kasbah-core-api-1"
BAK="/app/scripts/entrypoint_api.sh.bak.20260206_020953"

echo "== Restore + patch entrypoint_api.sh via STDIN (no host expansion possible) =="

# Write the patch script into the container via STDIN (no $ expansion on host)
cat <<'SH' | docker exec -i "$CN" sh -lc 'cat > /tmp/patch_entrypoint.sh && chmod +x /tmp/patch_entrypoint.sh'
set -e

if [ ! -f "/app/scripts/entrypoint_api.sh.bak.20260206_020953" ]; then
  echo "FAIL: backup not found: /app/scripts/entrypoint_api.sh.bak.20260206_020953"
  ls -la /app/scripts/entrypoint_api.sh.bak.* || true
  exit 1
fi

echo "1) Restore from backup"
cp -v "/app/scripts/entrypoint_api.sh.bak.20260206_020953" /app/scripts/entrypoint_api.sh

echo "2) Guard slo_probe.sh call"
awk '
  {
    if ($0 ~ /BASE=http:\/\/127\.0\.0\.1:8002 \/app\/scripts\/slo_probe\.sh/){
      print "    if [ -f /app/scripts/slo_probe.sh ]; then"
      print "      BASE=http://127.0.0.1:8002 /app/scripts/slo_probe.sh >/tmp/slo.log 2>&1 || true"
      print "    else"
      print "      echo \"WARN: /app/scripts/slo_probe.sh missing (skipping)\" >/tmp/slo.log 2>&1 || true"
      print "    fi"
      next
    }
    print
  }
' /app/scripts/entrypoint_api.sh > /tmp/entrypoint_api.sh.new
mv /tmp/entrypoint_api.sh.new /app/scripts/entrypoint_api.sh

echo "3) Insert Redis fail-closed preflight before cd /app (idempotent)"
if ! grep -q "KASBAH_REDIS_PREFLIGHT" /app/scripts/entrypoint_api.sh; then
  awk '
    BEGIN{inserted=0}
    {
      if (!inserted && $0 ~ /^cd \/app/){
        print "# --- KASBAH_REDIS_PREFLIGHT ---"
        print "REDIS_HOST=\"${REDIS_HOST:-redis}\""
        print "REDIS_PORT=\"${REDIS_PORT:-6379}\""
        print "if [ \"${PRODUCTION:-0}\" = \"1\" ]; then"
        print "  echo \"INFO: PRODUCTION=1 -> requiring Redis at ${REDIS_HOST}:${REDIS_PORT}\""
        print "  python3 - <<'\''PY'\''"
        print "import os, socket, sys"
        print "host=os.environ.get('\''REDIS_HOST'\'','\''redis'\'')"
        print "port=int(os.environ.get('\''REDIS_PORT'\'','\''6379'\''))"
        print "s=socket.socket(); s.settimeout(1.0)"
        print "try:"
        print "    s.connect((host,port))"
        print "except Exception as e:"
        print "    print('\''FATAL: PRODUCTION=1 requires Redis but connection failed:'\'', e)"
        print "    sys.exit(1)"
        print "finally:"
        print "    try: s.close()"
        print "    except: pass"
        print "print('\''OK: Redis reachable'\'')"
        print "PY"
        print "fi"
        print ""
        inserted=1
      }
      print
    }
  ' /app/scripts/entrypoint_api.sh > /tmp/entrypoint_api.sh.new
  mv /tmp/entrypoint_api.sh.new /app/scripts/entrypoint_api.sh
fi

chmod +x /app/scripts/entrypoint_api.sh

echo
echo "== Final entrypoint_api.sh (1..95) =="
nl -ba /app/scripts/entrypoint_api.sh | sed -n "1,95p"
SH

# Execute it inside container
docker exec -it "$CN" sh -lc '/tmp/patch_entrypoint.sh'
