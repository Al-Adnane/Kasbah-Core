#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "== AtlasZak boot =="
docker compose up -d --build

echo "== waiting for http://127.0.0.1:8002/health =="
for i in $(seq 1 80); do
  if curl -sS http://127.0.0.1:8002/health >/dev/null 2>&1; then
    echo "✅ API ready"
    break
  fi
  sleep 0.25
done

echo
echo "Open this in a browser:"
echo "  http://127.0.0.1:8002/atlaszak"
echo
echo "If you want CLI mode too:"
echo "  ./atlaszak.sh"
