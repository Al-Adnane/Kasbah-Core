#!/usr/bin/env bash
set -euo pipefail

echo "== Find host processes that might restart docker/compose (NO rg) =="

echo
echo "-- 1) Grep repo for restart/kill commands"
# fast-ish: only search common script/config file types + compose files
grep -RIn --exclude-dir=venv --exclude-dir=.git --exclude-dir=__pycache__ \
  -E "docker compose (restart|up|down)|docker-compose (restart|up|down)|restart api|compose restart api|docker restart kasbah-core-api-1|kill .*kasbah-core-api-1|signal=15" \
  . || true

echo
echo "-- 2) Running host processes mentioning docker/compose/kasbah"
ps aux | grep -E "docker compose|docker-compose|kasbah-core|kasbah|compose restart|compose up|compose down" | grep -v grep || true

echo
echo "-- 3) launchd jobs (launchctl list) mentioning kasbah/docker/compose"
launchctl list | grep -E "kasbah|docker|compose" || true

echo
echo "-- 4) Tail shell history (best-effort) mentioning docker/compose/kasbah"
for f in "$HOME/.zsh_history" "$HOME/.bash_history"; do
  if [ -f "$f" ]; then
    echo "--- tail $f (filtered) ---"
    tail -n 2000 "$f" | grep -E "docker compose|docker-compose|kasbah-core|kasbah" || true
  fi
done
