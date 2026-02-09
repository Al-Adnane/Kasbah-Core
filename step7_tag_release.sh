#!/usr/bin/env bash
set -euo pipefail

echo "=== git status ==="
git status --porcelain=v1

echo
echo "=== commit Step 7 closure ==="
git add -A
git commit -m "Step 7: RTP moats closed (auth, replay, mismatch, tamper) + restart persistence" || true

echo
echo "=== tag ==="
TAG="step7-closed-$(date +%Y%m%d-%H%M)"
git tag -a "$TAG" -m "Step 7 closed: auth + RTP moats + restart persistence"
echo "✅ created tag: $TAG"

echo
echo "=== recent log ==="
git --no-pager log -5 --oneline
