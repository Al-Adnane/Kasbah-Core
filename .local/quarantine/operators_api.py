import os, time, sqlite3, secrets, hashlib
from typing import Optional, List, Dict
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/operators", tags=["operators"])

_ROLE_RANK = {"observer": 1, "operator": 2, "admin": 3}

def _db_path() -> str:
    return os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")

def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

def _ensure_schema(con: sqlite3.Connection):
    # Base table (initial)
    con.execute("""
    CREATE TABLE IF NOT EXISTS operators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        api_key_hash TEXT UNIQUE NOT NULL,
        created_at REAL NOT NULL
    )
    """)

    # Migrations (add columns if missing)
    cols = [r[1] for r in con.execute("PRAGMA table_info(operators)").fetchall()]
    if "revoked" not in cols:
        con.execute("ALTER TABLE operators ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0")
    if "updated_at" not in cols:
        con.execute("ALTER TABLE operators ADD COLUMN updated_at REAL NOT NULL DEFAULT 0")

    # Indexes (safe after columns exist)
    con.execute("CREATE INDEX IF NOT EXISTS idx_ops_role ON operators(role)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ops_revoked ON operators(revoked)")
def _require_admin(request: Request):
    op = getattr(request.state, "operator", None)
    if not isinstance(op, dict):
        raise HTTPException(status_code=401, detail="Unauthorized")
    if _ROLE_RANK.get(op.get("role",""), 0) < _ROLE_RANK["admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return op

class OperatorCreate(BaseModel):
    name: str = Field(..., min_length=1)
    role: str = Field(..., pattern="^(observer|operator|admin)$")

class OperatorRotate(BaseModel):
    id: int

class OperatorRevoke(BaseModel):
    id: int

@router.get("/list")
def list_operators(limit: int = 100, request: Request = None):
    _require_admin(request)
    con = sqlite3.connect(_db_path())
    try:
        _ensure_schema(con)
        rows = con.execute(
            "SELECT id,name,role,revoked,created_at,updated_at FROM operators ORDER BY id DESC LIMIT ?",
            (int(limit),)
        ).fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r[0],
                "name": r[1],
                "role": r[2],
                "revoked": bool(r[3]),
                "created_at": r[4],
                "updated_at": r[5],
            })
        return out
    finally:
        con.close()

@router.post("/create")
def create_operator(req: OperatorCreate, request: Request):
    _require_admin(request)

    api_key = secrets.token_urlsafe(32)
    h = _hash_key(api_key)

    con = sqlite3.connect(_db_path())
    try:
        _ensure_schema(con)
        now = time.time()
        con.execute(
            "INSERT INTO operators (name, role, api_key_hash, revoked, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (req.name, req.role, h, 0, now, now),
        )
        con.commit()
        new_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"ok": True, "id": int(new_id), "name": req.name, "role": req.role, "api_key": api_key}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Operator key collision; retry")
    finally:
        con.close()

@router.post("/rotate")
def rotate_operator(req: OperatorRotate, request: Request):
    _require_admin(request)

    api_key = secrets.token_urlsafe(32)
    h = _hash_key(api_key)

    con = sqlite3.connect(_db_path())
    try:
        _ensure_schema(con)
        now = time.time()
        cur = con.execute("SELECT id,revoked FROM operators WHERE id=? LIMIT 1", (int(req.id),))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Operator not found")
        if int(row[1]) == 1:
            raise HTTPException(status_code=409, detail="Operator revoked")

        con.execute(
            "UPDATE operators SET api_key_hash=?, updated_at=? WHERE id=?",
            (h, now, int(req.id)),
        )
        con.commit()
        return {"ok": True, "id": int(req.id), "api_key": api_key}
    finally:
        con.close()

@router.post("/revoke")
def revoke_operator(req: OperatorRevoke, request: Request):
    _require_admin(request)

    con = sqlite3.connect(_db_path())
    try:
        _ensure_schema(con)
        now = time.time()
        cur = con.execute("SELECT id FROM operators WHERE id=? LIMIT 1", (int(req.id),))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Operator not found")
        con.execute("UPDATE operators SET revoked=1, updated_at=? WHERE id=?", (now, int(req.id)))
        con.commit()
        return {"ok": True, "id": int(req.id), "revoked": True}
    finally:
        con.close()
