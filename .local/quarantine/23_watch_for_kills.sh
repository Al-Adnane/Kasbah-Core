#!/usr/bin/env bash
set -euo pipefail

echo "== Watching docker events for kasbah-core-api kills/stops (Ctrl+C to stop) =="
echo "Timestamp (local) | action | signal | exitCode | container"
echo

docker events \
  --filter 'container=kasbah-core-api-1' \
  --filter 'event=kill' \
  --filter 'event=stop' \
  --filter 'event=die' \
  --format '{{.Time}} | {{.Action}} | {{.Actor.Attributes.signal}} | {{.Actor.Attributes.exitCode}} | {{.Actor.Attributes.name}}'
