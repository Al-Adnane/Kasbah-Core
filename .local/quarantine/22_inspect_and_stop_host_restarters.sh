#!/usr/bin/env bash
set -euo pipefail

echo "== Find + inspect kasbah_hardened_final.py host process =="

echo
echo "-- A) Find PID + full command line"
ps aux | grep -F "kasbah_hardened_final.py" | grep -v grep || true

PID="$(ps aux | grep -F "kasbah_hardened_final.py" | grep -v grep | awk '{print $2}' | head -n 1 || true)"
if [ -z "${PID}" ]; then
  echo "OK: no kasbah_hardened_final.py process running"
  exit 0
fi

echo
echo "-- B) Show open files / cwd (best-effort)"
lsof -p "$PID" 2>/dev/null | head -n 40 || true

echo
echo "-- C) Show file path + first 220 lines of kasbah_hardened_final.py"
# Try to locate the file from the current repo first
if [ -f "./kasbah_hardened_final.py" ]; then
  echo "FILE=./kasbah_hardened_final.py"
  nl -ba ./kasbah_hardened_final.py | sed -n '1,220p'
else
  # Fallback: try to locate via lsof (if available)
  FP="$(lsof -p "$PID" 2>/dev/null | awk '/kasbah_hardened_final\.py/ {print $NF; exit}' || true)"
  if [ -n "$FP" ] && [ -f "$FP" ]; then
    echo "FILE=$FP"
    nl -ba "$FP" | sed -n '1,220p'
  else
    echo "WARN: could not locate file path via repo or lsof"
  fi
fi

echo
echo "-- D) Stop it (SIGTERM), then SIGKILL if needed"
kill "$PID" 2>/dev/null || true
sleep 1
if ps -p "$PID" >/dev/null 2>&1; then
  echo "WARN: still running -> SIGKILL"
  kill -9 "$PID" 2>/dev/null || true
fi

echo
echo "-- E) Confirm it is gone"
ps aux | grep -F "kasbah_hardened_final.py" | grep -v grep || echo "OK: stopped"
