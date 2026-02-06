#!/usr/bin/env bash
set -euo pipefail

echo "Activating venv..."
source venv/bin/activate || { echo "ERROR: venv not found or activation failed"; exit 1; }

echo "Checking/starting Redis (optional for replay protection)..."
docker ps -q -f name=kasbah-redis > /dev/null || {
  echo "Starting Redis container..."
  docker run -d -p 6379:6379 --name kasbah-redis redis:7-alpine || echo "Redis already running or failed to start"
}

echo "Starting Kasbah server on port ${PORT:-8003}..."
exec python3 kasbah_hardened_final.py
