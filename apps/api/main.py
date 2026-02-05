from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict
import uvicorn

# Import the Kernel Gate
from apps.api.rtp.kernel_gate import KernelGate

app = FastAPI(title="Kasbah Core API", version="1.0.0")

# Initialize System
kernel_gate = KernelGate()

class DecisionRequest(BaseModel):
    tool_name: str
    agent_id: Optional[str] = "anonymous"
    usage: Optional[Dict] = {}
    signals: Dict

@app.get("/health")
def health_check():
    return {
        "status": "operational",
        "system": "Kasbah Core",
        "moats_active": 13
    }

@app.post("/api/rtp/decide")
def decide(request: DecisionRequest):
    try:
        result = kernel_gate.decide(request.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rtp/audit")
def get_audit(limit: int = 10):
    return kernel_gate.audit.get_recent_logs(limit)


@app.get("/api/rtp/audit/verify")
def audit_verify():
    """Verify the SQLite chained audit ledger."""
    import os, sqlite3, hashlib

    db = os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")
    con = sqlite3.connect(db)
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) FROM audit_ledger")
    total = cur.fetchone()[0]

    cur.execute("""
    SELECT COUNT(*) AS bad
    FROM audit_ledger a
    JOIN audit_ledger b ON b.id = a.id - 1
    WHERE a.prev_hash != b.row_hash
    """)
    bad_links = cur.fetchone()[0]

    cur.execute("SELECT payload_json, prev_hash, row_hash FROM audit_ledger ORDER BY id ASC")
    bad_hash = 0
    for payload_json, prev_hash, row_hash in cur.fetchall():
        expect = hashlib.sha256((prev_hash + "|" + payload_json).encode("utf-8")).hexdigest()
        if expect != row_hash:
            bad_hash += 1

    con.close()

    ok = (total >= 2 and bad_links == 0 and bad_hash == 0)
    return {
        "ok": bool(ok),
        "db": db,
        "total_rows": int(total),
        "bad_links": int(bad_links),
        "bad_hash": int(bad_hash),
    }


@app.get("/api/rtp/audit/tail")
def audit_tail(limit: int = 20, kind: str = None, tool: str = None, decision: str = None):
    """Lightweight audit tail from SQLite: no payloads, short hashes."""
    import sqlite3, os, datetime

    db = os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")
    con = sqlite3.connect(db)
    cur = con.cursor()

    cur.execute(
        "SELECT id, ts, kind, jti, tool, decision, prev_hash, row_hash "
        "FROM audit_ledger ORDER BY id DESC LIMIT ?",
        (int(limit) if limit is not None else 20,)
    )
    rows = cur.fetchall()
    con.close()

    out = []
    for _id, ts, k, jti, t, d, prev_hash, row_hash in rows:
        if kind is not None and str(k) != str(kind):
            continue
        if tool is not None and str(t) != str(tool):
            continue
        if decision is not None and str(d) != str(decision):
            continue

        tsf = float(ts or 0.0)
        out.append({
            "id": _id,
            "ts": tsf,
            "ts_iso": datetime.datetime.utcfromtimestamp(tsf).isoformat() + "Z",
            "kind": k,
            "jti": jti,
            "tool": t,
            "decision": d,
            "prev": (prev_hash or "")[:12],
            "row": (row_hash or "")[:12],
        })

    # keep descending order (newest first), already is
    return out


@app.get("/api/rtp/audit/jti/{jti}")
def audit_by_jti(jti: str):
    """Fetch the most recent audit row for a given ticket JTI."""
    import sqlite3, os, json, datetime

    db = os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")
    con = sqlite3.connect(db)
    cur = con.cursor()

    cur.execute(
        "SELECT id, ts, kind, jti, tool, decision, payload_json, prev_hash, row_hash "
        "FROM audit_ledger WHERE jti=? ORDER BY id DESC LIMIT 1",
        (jti,)
    )
    row = cur.fetchone()
    con.close()

    if not row:
        return {"found": False, "jti": jti}

    _id, ts, kind, jti2, tool, decision, payload_json, prev_hash, row_hash = row
    try:
        payload = json.loads(payload_json)
    except Exception:
        payload = {"_raw": payload_json}

    return {
        "found": True,
        "id": _id,
        "ts": ts,
        "ts_iso": datetime.datetime.utcfromtimestamp(float(ts or 0)).isoformat() + "Z",
        "kind": kind,
        "jti": jti2,
        "tool": tool,
        "decision": decision,
        "payload": payload,
        "prev_hash": prev_hash,
        "row_hash": row_hash,
    }


@app.get("/api/rtp/audit/stats")
def audit_stats(window: int = 200):
    """Quick counters over last N audit rows."""
    import sqlite3, os
    from collections import Counter

    db = os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")
    con = sqlite3.connect(db)
    cur = con.cursor()

    cur.execute(
        "SELECT id, ts, kind, tool, decision FROM audit_ledger ORDER BY id DESC LIMIT ?",
        (int(window),)
    )
    rows = cur.fetchall()
    con.close()

    kinds = Counter()
    kind_families = Counter()
    tools = Counter()
    decisions = Counter()

    for _id, ts, kind, tool, decision in rows:
        k = "NA" if kind is None else str(kind)
        fam = k.split("_", 1)[0] if "_" in k else k
        kind_families[fam] += 1
        kinds[k] += 1

        if tool is not None:
            tools[str(tool)] += 1

        d = "NA" if decision is None else str(decision)
        decisions[d] += 1

    # normalize decision key for None (avoid "None" in JSON)
    if "None" in decisions and "NA" not in decisions:
        decisions["NA"] = decisions.get("None", 0)
        decisions.pop("None", None)

    return {
        "db": db,
        "window": int(window),
        "rows": len(rows),
        "decisions": dict(decisions.most_common()),
        "top_kinds": dict(kinds.most_common(20)),
        "top_kind_families": dict(kind_families.most_common()),
        "top_tools": dict(tools.most_common(20)),
        "replays": int(kinds.get("REPLAY", 0)),
    }

@app.get("/api/rtp/status")
def system_status():
    return {
        "feedback_threat_level": kernel_gate.feedback_loop.threat_level,
        "thermo_state": kernel_gate.thermo.get_defense_state(),
        "topology_agents": len(kernel_gate.topology.graph)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
