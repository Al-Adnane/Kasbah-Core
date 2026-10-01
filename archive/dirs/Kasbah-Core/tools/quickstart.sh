#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f ".env" ]; then
  echo "ERROR: .env not found"
  echo "Create it first (cp .env.example .env)"
  exit 1
fi

echo "[1/3] Starting services (docker compose)…"
docker compose up -d --build

echo
echo "[2/3] Running proof script…"
bash ./atlaszak.sh

echo
echo "[3/3] Done. Gate is reachable."
