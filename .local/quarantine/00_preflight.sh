#!/usr/bin/env bash
set -euo pipefail

echo "== Preflight (Kasbah) =="
cd "$(dirname "$0")/.."

echo "PWD: $(pwd)"
echo

# must-have repo markers
test -f docker-compose.yml || { echo "FAIL: docker-compose.yml not found"; exit 1; }
test -d apps || { echo "FAIL: apps/ not found"; exit 1; }

echo "== Docker / Compose =="
docker --version
docker compose version
echo

echo "== Bring stack up =="
docker compose up -d
echo

echo "== Containers =="
docker compose ps
echo

BASE="${BASE:-http://127.0.0.1:8002}"

echo "== Health probe =="
curl -sS "$BASE/health" || true
echo
