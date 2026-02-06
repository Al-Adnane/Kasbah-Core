import os, json, time, sqlite3
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/agents", tags=["agents"])

def _db_path() -> str:
    return os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")

def _con():
    try:
        db_path = _db_path()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        con = sqlite3.connect(db_path)
        
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            persona TEXT NOT NULL,
            geometry_bias REAL NOT NULL DEFAULT 1.0,
            integrity_bias REAL NOT NULL DEFAULT 1.0,
            allowed_tools_json TEXT NOT NULL DEFAULT '[]',
            created_at REAL NOT NULL
        )
        """)
        con.commit()
        return con
    except Exception:
        return None

class AgentRegister(BaseModel):
    agent_id: str = Field(..., min_length=1)
    persona: str = Field("balanced")
    geometry_bias: float = 1.0
    integrity_bias: float = 1.0
    allowed_tools: List[str] = Field(default_factory=list)

@router.post("/register")
def register_agent(req: AgentRegister, request: Request):
    op = getattr(request.state, "operator", None)
    if not op:
        raise HTTPException(status_code=401, detail="Unauthorized")

    allowed_tools_json = json.dumps(req.allowed_tools, ensure_ascii=False)

    con = _con()
    if not con:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO agents (agent_id, persona, geometry_bias, integrity_bias, allowed_tools_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
              persona=excluded.persona,
              geometry_bias=excluded.geometry_bias,
              integrity_bias=excluded.integrity_bias,
              allowed_tools_json=excluded.allowed_tools_json
            """,
            (req.agent_id, req.persona, float(req.geometry_bias), float(req.integrity_bias), allowed_tools_json, int(time.time()))
        )
        con.commit()
        return {"ok": True, "agent_id": req.agent_id, "updated": True, "by_operator": op.get("id")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        con.close()

@router.get("/list")
def list_agents(limit: int = 100):
    con = _con()
    if not con:
        return []
    
    cur = con.cursor()
    cur.execute(
        "SELECT agent_id, persona, geometry_bias, integrity_bias, allowed_tools_json, created_at FROM agents ORDER BY created_at DESC LIMIT ?",
        (int(limit),)
    )
    rows = cur.fetchall()
    con.close()
    out = []
    for r in rows:
        out.append({
            "agent_id": r[0],
            "persona": r[1],
            "geometry_bias": r[2],
            "integrity_bias": r[3],
            "allowed_tools": json.loads(r[4] or "[]"),
            "created_at": r[5],
        })
    return out

@router.get("/{agent_id}")
def get_agent(agent_id: str):
    con = _con()
    if not con:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    cur = con.cursor()
    cur.execute(
        "SELECT agent_id, persona, geometry_bias, integrity_bias, allowed_tools_json, created_at FROM agents WHERE agent_id=? LIMIT 1",
        (agent_id,)
    )
    row = cur.fetchone()
    con.close()
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent_id": row[0],
        "persona": row[1],
        "geometry_bias": row[2],
        "integrity_bias": row[3],
        "allowed_tools": json.loads(row[4] or "[]"),
        "created_at": row[5],
    }

def load_agent(agent_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not agent_id:
        return None
    
    con = _con()
    if not con:
        return None
    
    cur = con.cursor()
    cur.execute(
        "SELECT agent_id, persona, geometry_bias, integrity_bias, allowed_tools_json FROM agents WHERE agent_id=? LIMIT 1",
        (agent_id,)
    )
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return {
        "agent_id": row[0],
        "persona": row[1],
        "geometry_bias": float(row[2] or 1.0),
        "integrity_bias": float(row[3] or 1.0),
        "allowed_tools": json.loads(row[4] or "[]"),
    }
