#!/usr/bin/env bash
set -euo pipefail
docker exec -it kasbah-core-api-1 sh -lc 'cd /app && python -c "from apps.api.rtp.audit_ledger import verify; print(verify())"'
