from typing import Any, Dict, List
import os
import json
import time

# In-memory audit buffer (used by /api/rtp/audit)
_AUDIT: List[Dict[str, Any]] = []

# Disk log path (used for persistence/debugging)
_AUDIT_PATH = os.path.join(".kasbah", "rtp_audit.log")


def append_audit(event: Dict[str, Any]) -> None:
    """
    Append a single audit event.
    - Ensures a timestamp exists
    - Stores in memory for the API endpoint
    - Writes JSONL to .kasbah/rtp_audit.log
    """
    if "ts" not in event:
        event["ts"] = time.time()

    # 1) In-memory buffer
    _AUDIT.append(event)

    # 2) Disk JSONL
    os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
    with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_audit(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Read the last N events from the in-memory buffer.
    """
    if limit <= 0:
        return []
    return _AUDIT[-limit:]


def reset_audit() -> None:
    """
    Clear in-memory audit buffer (does not touch disk file).
    """
    _AUDIT.clear()

