import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

# Always write inside the container-mapped directory.
# In Docker, /app is WORKDIR; ".kasbah" resolves to /app/.kasbah
AUDIT_DIR = Path(".kasbah")
AUDIT_PATH = AUDIT_DIR / "rtp_audit.log"


def _normalize_record(
    record_or_event: Union[Dict[str, Any], str],
    agent_id: Optional[str] = None,
    jti: Optional[str] = None,
) -> Dict[str, Any]:
    # Backward compatible:
    # - append_audit({"event": "...", ...})
    # - append_audit("DECIDE", agent_id="x", jti="y")
    if isinstance(record_or_event, dict):
        rec = dict(record_or_event)
        # allow "event" or legacy "type"
        if "event" not in rec and "type" in rec:
            rec["event"] = rec.pop("type")
        if agent_id is not None and "agent_id" not in rec:
            rec["agent_id"] = agent_id
        if jti is not None and "jti" not in rec:
            rec["jti"] = jti
    else:
        rec = {"event": str(record_or_event), "agent_id": agent_id, "jti": jti}

    rec["ts"] = float(rec.get("ts", time.time()))
    return rec


def append_audit(record_or_event: Union[Dict[str, Any], str], agent_id: Optional[str] = None, jti: Optional[str] = None) -> None:
    AUDIT_DIR.mkdir(exist_ok=True)
    rec = _normalize_record(record_or_event, agent_id=agent_id, jti=jti)
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")


def read_audit(limit: int = 50):
    if not AUDIT_PATH.exists():
        return []
    # tail-ish read without loading huge files: still OK for demo sizes
    lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-max(0, int(limit)):]:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out
