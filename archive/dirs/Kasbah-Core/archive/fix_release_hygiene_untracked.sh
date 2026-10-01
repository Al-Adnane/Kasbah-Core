#!/usr/bin/env bash
set -euo pipefail

echo "=== status (before) ==="
git status --porcelain=v1

echo
echo "=== add + commit release scripts ==="
git add master_1_3.sh master_2_release_hygiene.sh docs/STEP8_BACKLOG.md docs/THREAT_MODEL_STEP7.md scripts/step8_env_check.sh || true
git commit -m "chore: add master scripts (1-3 + release hygiene) and Step 8/threat-model docs" || true

echo
echo "=== status (after) ==="
git status --porcelain=v1

echo
echo "=== rerun release hygiene ==="
./master_2_release_hygiene.sh
