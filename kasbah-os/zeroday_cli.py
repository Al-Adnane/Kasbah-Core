#!/usr/bin/env python3
"""
CLI wrapper for ZeroDayDiscoveryEngine's static CWE pattern scan.

Usage: python3 zeroday_cli.py <file>
Prints a single JSON object to stdout: { ok, findings: [...], report: {...} }.

Only the static analyzer is exercised (mode="static", the engine's default —
see zeroday_engine.py's own header: dynamic/symbolic modes were simulated and
have been removed from the engine entirely). No network access, no execution
of the scanned file's contents.
"""
import json
import sys

from zeroday_engine import ZeroDayDiscoveryEngine
from kasbah_types import SecurityClearance


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "usage: zeroday_cli.py <file>"}))
        return 1

    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1

    engine = ZeroDayDiscoveryEngine(clearance=SecurityClearance.ANALYST)
    findings = engine.analyze(data, mode="static")
    print(json.dumps({
        "ok": True,
        "findings": [f.to_dict() for f in findings],
        "report": engine.generate_report(),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
