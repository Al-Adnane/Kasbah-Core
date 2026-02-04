import json
import time
import os
from pathlib import Path

_AUDIT_PATH = os.path.join(".kasbah", "rtp_audit.log")

def append_audit(record: dict):
    """
    Appends a JSON record to the audit log.
    Creates the directory if it doesn't exist.
    """
    # Ensure directory exists
    Path(".kasbah").mkdir(exist_ok=True)
    
    # Add timestamp if not present
    record["ts"] = record.get("ts", time.time())
    
    # Append to log
    with open(_AUDIT_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")

def read_audit(limit: int = 50):
    """
    Reads the last N lines from the audit log.
    """
    if not Path(_AUDIT_PATH).exists():
        return []
    
    with open(_AUDIT_PATH, "r") as f:
        lines = f.readlines()
    
    # Parse JSON and return last 'limit' items
    logs = []
    for line in lines[-limit:]:
        try:
            logs.append(json.loads(line))
        except:
            pass
    return logs
