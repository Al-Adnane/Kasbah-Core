from __future__ import annotations
import os, json, time, sqlite3, hashlib
from typing import Any, Dict, Optional

DB_PATH = os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  jti TEXT,
  tool TEXT,
  decision TEXT,
  payload_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_ts ON audit_ledger(ts);
CREATE INDEX IF NOT EXISTS idx_ledger_jti ON audit_ledger(jti);
"""

def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    return con

def init_ledger() -> None:
    con = _connect()
    try:
        for stmt in SCHEMA.strip().split(";"):
            s = stmt.strip()
            if s:
                con.execute(s + ";")
    finally:
        con.close()

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _last_hash(con: sqlite3.Connection) -> str:
    r = con.execute("SELECT row_hash FROM audit_ledger ORDER BY id DESC LIMIT 1").fetchone()
    return r[0] if r else "GENESIS"

def append_event(kind: str, payload: Dict[str, Any]) -> str:
    con = _connect()
    try:
        init_ledger()
        prev = _last_hash(con)
        payload_json = _canonical(payload)
        row_hash = _sha256(prev + "|" + payload_json)

        jti = payload.get("jti")
        if not jti and isinstance(payload.get("ticket"), dict):
            jti = payload["ticket"].get("jti")

        tool = payload.get("tool") or payload.get("tool_name")
        decision = payload.get("decision") or payload.get("status") or payload.get("allowed")

        con.execute(
            "INSERT INTO audit_ledger (ts,kind,jti,tool,decision,payload_json,prev_hash,row_hash) VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), kind, jti, tool, str(decision), payload_json, prev, row_hash),
        )
        return row_hash
    finally:
        con.close()

def verify() -> bool:
    con = _connect()
    try:
        init_ledger()
        rows = con.execute("SELECT payload_json,prev_hash,row_hash FROM audit_ledger ORDER BY id ASC").fetchall()
        prev = "GENESIS"
        for payload_json, prev_hash, row_hash in rows:
            if prev_hash != prev:
                return False
            if row_hash != _sha256(prev_hash + "|" + payload_json):
                return False
            prev = row_hash
        return True
    finally:
        con.close()

def latest_by_jti(jti: str) -> Optional[Dict[str, Any]]:
    con = _connect()
    try:
        init_ledger()
        r = con.execute(
            "SELECT kind,payload_json,row_hash,prev_hash,ts FROM audit_ledger WHERE jti=? ORDER BY id DESC LIMIT 1",
            (jti,),
        ).fetchone()
        if not r:
            return None
        kind,payload_json,row_hash,prev_hash,ts = r
        return {"kind": kind, "payload": json.loads(payload_json), "row_hash": row_hash, "prev_hash": prev_hash, "ts": ts}
    finally:
        con.close()


def recent(limit: int = 10):
    con = _connect()
    try:
        init_ledger()
        rows = con.execute(
            "SELECT id,ts,kind,jti,tool,decision,payload_json,prev_hash,row_hash "
            "FROM audit_ledger ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        out = []
        for (id_,ts,kind,jti,tool,decision,payload_json,prev_hash,row_hash) in rows[::-1]:
            try:
                payload = json.loads(payload_json)
            except Exception:
                payload = {"_raw": payload_json}
            out.append({
                "id": id_,
                "ts": ts,
                "kind": kind,
                "jti": jti,
                "tool": tool,
                "decision": decision,
                "payload": payload,
                "prev_hash": prev_hash,
                "row_hash": row_hash,
            })
        return out
    finally:
        con.close()

