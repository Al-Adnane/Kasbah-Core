#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://localhost:8002}"
curl -sS "$BASE/openapi.json" | python3 -c '
import sys,json
o=json.load(sys.stdin)
paths=o.get("paths",{})
print("\n".join(sorted([p for p in paths if p.startswith("/api/rtp/")])))
'
