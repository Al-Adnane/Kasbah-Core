from typing import Any, Dict, List
import os
import json
import time
from collections import deque

# In-memory audit buffer (best-effort, not authoritative under reload)
_AUDIT: List[Dict[str, Any]] = []

# Disk log path (authoritative, survives restarts)
_AUDIT_PATH = os.path.join(".kasbah", "rtp_audit.log")


def append_audit(event: Dict[str, Any]) -> None:
    """
    Append a single audit event.
    - Ensures a timestamp exists
    - Stores in memory for convenience
    - Writes JSONL to .kasbah/rtp_audit.log (authoritative)
    """
    if "ts" not in event:
        event["ts"] = time.time()
    if "ts_iso" not in event:
        event["ts_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event["ts"]))

    # 1) In-memory buffer (best effort)
    _AUDIT.append(event)

    # 2) Disk JSONL (authoritative)
    os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
    with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_audit(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Return the last N events, reading from disk so it survives restarts/reloads.
    Falls back gracefully if the file doesn't exist yet.
    """
    if limit <= 0:
        return []

    if not os.path.exists(_AUDIT_PATH):
        return []

    # Read the last `limit` lines efficiently
    last_lines = deque(maxlen=limit)
    with open(_AUDIT_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                last_lines.append(line)

    out: List[Dict[str, Any]] = []
    for line in last_lines:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except Exception:
            # Skip any malformed line
            continue

    return out


def reset_audit() -> None:
    """
    Clear in-memory audit buffer only (does not touch disk file).
    """
    _AUDIT.clear()

