#!/usr/bin/env bash
set -euo pipefail

echo "== Find host processes that might restart docker/compose =="

echo
echo "-- 1) Look for scripts in repo that restart api/caddy/compose"
rg -n --hidden --no-ignore-vcs \
  "docker compose (restart|up|down)|docker-compose (restart|up|down)|restart api|compose restart api|kill .*kasbah-core-api-1|docker restart kasbah-core-api-1" \
  . || true

echo
echo "-- 2) List running host processes that mention docker/compose/kasbah"
ps aux | rg -n "(docker compose|docker-compose|kasbah-core|kasbah|compose restart|compose up|compose down)" || true

echo
echo "-- 3) Check for any scheduled jobs (macOS launch agents) mentioning kasbah/docker"
launchctl list | rg -n "(kasbah|docker|compose)" || true

echo
echo "-- 4) Recent shell history lines (best-effort) mentioning docker/compose/kasbah"
# zsh history location varies; try common
for f in "$HOME/.zsh_history" "$HOME/.bash_history"; do
  if [ -f "$f" ]; then
    echo "--- tail $f (filtered) ---"
    tail -n 2000 "$f" | rg -n "(docker compose|docker-compose|kasbah-core|kasbah)" || true
  fi
done
