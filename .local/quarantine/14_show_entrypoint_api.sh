#!/usr/bin/env bash
set -euo pipefail
CN="kasbah-core-api-1"

echo "== Show entrypoint_api.sh =="
docker exec -it "$CN" sh -lc 'ls -la /app/scripts && echo && nl -ba /app/scripts/entrypoint_api.sh | sed -n "1,220p"'
