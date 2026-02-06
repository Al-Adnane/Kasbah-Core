#!/usr/bin/env bash
set -euo pipefail

CN="kasbah-core-api-1"

KEY="$(docker exec -it "$CN" sh -lc 'echo -n "${KASBAH_BOOTSTRAP_API_KEY:-}"' | tr -d "\r")"

if [[ -z "$KEY" ]]; then
  echo "FAIL: KASBAH_BOOTSTRAP_API_KEY is empty in container $CN"
  exit 1
fi

echo "$KEY" > cat/.bootstrap_key
chmod 600 cat/.bootstrap_key
echo "OK: saved bootstrap key to cat/.bootstrap_key"
