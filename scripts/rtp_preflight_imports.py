#!/usr/bin/env python3
"""
Preflight import check for RTP/Kasbah.

Run this BEFORE docker build/up.
It fails fast and prints missing symbols/modules.

Fixes local dev: ensures repo root is on sys.path so `apps.*` imports work.
"""
from __future__ import annotations

import importlib
import os
import sys
import traceback
from pathlib import Path

# Ensure repo root is importable (so `import apps...` works on macOS)
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
# Optional: if your code expects /app like Docker does
os.environ.setdefault("PYTHONPATH", str(REPO_ROOT))

TARGETS = [
    "apps.api.rtp.kernel_gate",
    "apps.api.main",
]

def main() -> int:
    ok = True
    print(f"Using REPO_ROOT on sys.path: {REPO_ROOT}")
    for t in TARGETS:
        try:
            importlib.import_module(t)
            print(f"OK import: {t}")
        except Exception as e:
            ok = False
            print(f"\nFAIL import: {t}\n{e.__class__.__name__}: {e}")
            traceback.print_exc()
    return 0 if ok else 2

if __name__ == "__main__":
    raise SystemExit(main())
