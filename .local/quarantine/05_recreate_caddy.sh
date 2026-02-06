#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Confirm host Caddyfile has no 'security' directive =="
grep -n "^\s*security\s*{" -n Caddyfile || echo "OK: no security block in host Caddyfile"
echo

echo "== Stop + remove caddy container (force recreate) =="
docker compose stop caddy || true
docker rm -f kasbah-core-caddy-1 || true
echo

echo "== Bring caddy up fresh =="
docker compose up -d caddy
echo

echo "== Status =="
docker compose ps caddy
echo

echo "== Logs (last 60s) =="
docker logs --since 60s kasbah-core-caddy-1 || true
