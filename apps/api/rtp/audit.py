import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Prefer container-mounted path (docker-compose mounts ./.kasbah -> /app/.kasbah)
AUDIT_DIR = Path(os.getenv("KASBAH_AUDIT_DIR", "/app/.kasbah"))
AUDIT_LOG = Path(os.getenv("KASBAH_AUDIT_LOG", str(AUDIT_DIR / "rtp_audit.log")))

def append_audit(event: str, agent_id: Optional[str] = None, jti: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> None:
    """
    Append a single JSONL audit record to AUDIT_LOG.
    Record schema is stable and append-only.
    """
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)

    rec: Dict[str, Any] = {
        "ts": time.time(),
        "event": str(event),
        "agent_id": agent_id,
        "jti": jti,
    }
    if extra and isinstance(extra, dict):
        # Keep it flat + JSON-safe as much as possible
        rec["extra"] = extra

    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")

def read_audit(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Read last N JSONL records. Best-effort parsing (skips bad lines).
    """
    if limit <= 0:
        return []
    if not AUDIT_LOG.exists():
        return []

    # Small file: read all is fine. If it grows, we can optimize later.
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except Exception:
            continue
    return out
