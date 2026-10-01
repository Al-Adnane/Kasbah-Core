#!/usr/bin/env bash
set -euo pipefail

echo "==============================="
echo "RELEASE HYGIENE (2)"
echo "==============================="

# Ensure clean tree
if [[ -n "$(git status --porcelain=v1)" ]]; then
  echo "❌ Working tree not clean. Commit/stash first."
  git status --porcelain=v1
  exit 1
fi

# Show head + tags at head
echo "[A] HEAD"
git --no-pager log -1 --oneline
echo "[B] Tags at HEAD"
git tag --points-at HEAD || true
echo

# Ensure remote exists
REMOTE="${1:-origin}"
git remote get-url "$REMOTE" >/dev/null 2>&1 || { echo "❌ Remote '$REMOTE' not found"; git remote -v; exit 1; }

echo "[C] Push main + tags"
git push "$REMOTE" main
git push "$REMOTE" --tags
echo "✅ Pushed main + tags to $REMOTE"

# Optional: create GitHub release if gh is installed + authenticated
TAG="$(git tag --points-at HEAD | tail -n 1 || true)"
if command -v gh >/dev/null 2>&1 && [[ -n "${TAG:-}" ]]; then
  echo
  echo "[D] GitHub release (optional via gh)"
  gh release create "$TAG" \
    --title "$TAG" \
    --notes "Step 7 closed: auth + replay + mismatch + tamper, restart persistence verified." \
    || echo "⚠️ gh release create failed (maybe not logged in). You can do it manually in GitHub."
else
  echo
  echo "ℹ️ Skipping GitHub release (need 'gh' and a tag at HEAD)."
fi

echo "✅ Release hygiene complete"
