#!/usr/bin/env bash
#
# keep-downloaded.sh — force every file in this repo to be materialized on disk.
#
# WHY THIS EXISTS
# This repo lives under ~/Desktop, which macOS "Desktop & Documents" iCloud sync
# manages. With "Optimize Mac Storage" on, iCloud evicts file contents and leaves
# dataless placeholders (visible as the `dataless` flag in `ls -lO`). Node then
# fails to require evicted modules with confusing errors:
#   - "X is not a constructor"        (an evicted src file loaded as empty)
#   - "Cannot find module .../test.js" (evicted test file)
#   - "qs.parse is not a function"    (evicted file *inside* node_modules)
#   - `next build` hangs forever      (thousands of evicted deps)
# None of these are code bugs — the fix is to pull the bytes back down.
#
# PERMANENT FIX (do this once, then you rarely need this script):
#   System Settings → [your name] → iCloud → "Optimize Mac Storage" → OFF
#   (or move this repo out of ~/Desktop and ~/Documents entirely, e.g. ~/dev).
#
# USAGE
#   scripts/keep-downloaded.sh          # materialize the whole repo
#   scripts/keep-downloaded.sh --check  # only report how many files are evicted
#
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd -P)"

count_evicted() {
  # Count dataless placeholders, skipping .git (never evicted in practice).
  find "$ROOT" -type f -not -path '*/.git/*' -print0 2>/dev/null \
    | xargs -0 -P 8 -I {} sh -c 'ls -lO "{}" 2>/dev/null | grep -q dataless && echo x' 2>/dev/null \
    | wc -l | tr -d ' '
}

if [ "${1:-}" = "--check" ]; then
  echo "Evicted (dataless) files in repo: $(count_evicted)"
  exit 0
fi

echo "Materializing every file in $ROOT (this pulls bytes back from iCloud)…"
# brctl asks CloudDocs to download; the parallel cat forces synchronous fetch
# for anything brctl is slow to reach. Both are safe to run together.
brctl download "$ROOT" 2>/dev/null || true
find "$ROOT" -type f -not -path '*/.git/*' -print0 2>/dev/null \
  | xargs -0 -P 16 -I {} cat "{}" > /dev/null 2>&1 || true

remaining="$(count_evicted)"
echo "Done. Remaining evicted files: $remaining"
if [ "$remaining" != "0" ]; then
  echo "Some files are still evicted (iCloud may still be fetching). Re-run if a"
  echo "build or test fails, and consider turning off 'Optimize Mac Storage'."
fi
