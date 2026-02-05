
from apps.api.extensions import router as extensions_router
import os
from apps.api.extensions import router as extensions_router
import sqlite3
from apps.api.extensions import router as extensions_router
import hashlib
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from apps.api.auth_ops import lookup_operator, min_role_for_path, role_allows
from apps.api.rtp.state_api import router as rtp_state_router
from apps.api.agents_api import router as agents_router
from apps.api.extensions import router as extensions_router
# Use kernel_gate directly (do NOT import apps.api.rtp.public; it depends on flask_limiter)
try:
    from apps.api.rtp.kernel_gate import kernel_gate  # existing singleton if present
except Exception:
    from apps.api.rtp.kernel_gate import KernelGate
    kernel_gate = KernelGate()

app = FastAPI(title="Kasbah Core API", version="1.0.0")


@app.middleware("http")
async def kasbah_auth_middleware(request: Request, call_next):
    path = request.url.path

    # Public endpoints only
    if path in ("/health", "/openapi.json") or path.startswith("/docs") or path.startswith("/redoc"):
        return await call_next(request)

    # Enforce RBAC for protected routes
    min_role = min_role_for_path(path)
    if min_role is None:
        return await call_next(request)

    auth = request.headers.get("authorization", "") or request.headers.get("Authorization", "")
    api_key = ""
    if auth.lower().startswith("bearer "):
        api_key = auth.split(" ", 1)[1].strip()

    op = lookup_operator(api_key)
    if not op:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    if not role_allows(op.get("role", ""), min_role):
        return JSONResponse(status_code=403, content={"detail": "Forbidden"})

    request.state.operator = op
    return await call_next(request)


@app.get("/health")
def health_check():
    return {"status": "operational", "system": "Kasbah Core", "moats_active": 13}


@app.get("/api/rtp/status")
def rtp_status():
    return {
        "feedback_threat_level": float(getattr(kernel_gate, "feedback_threat_level", 0.0) or 0.0),
        "thermo_state": str(getattr(kernel_gate, "thermo_state", "CAUTIOUS") or "CAUTIOUS"),
        "topology_agents": int(getattr(kernel_gate, "topology_agents", 0) or 0),
    }


@app.post("/api/rtp/decide")
def rtp_decide(payload: Dict[str, Any], request: Request):
    op = getattr(request.state, "operator", None)
    if op:
        payload = dict(payload)
        payload["_operator_id"] = op.get("id")
        payload["_operator_role"] = op.get("role")
    try:
        return kernel_gate.decide(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rtp/consume")
def rtp_consume(payload: Dict[str, Any], request: Request):
    op = getattr(request.state, "operator", None)
    if op:
        payload = dict(payload)
        payload["_operator_id"] = op.get("id")
        payload["_operator_role"] = op.get("role")
    try:
        if hasattr(kernel_gate, "consume"):
            return kernel_gate.consume(payload)
        if hasattr(kernel_gate, "verify"):
            return kernel_gate.verify(payload)
        raise RuntimeError("kernel_gate missing consume/verify")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/rtp/audit")
def rtp_audit(limit: int = 50):
    try:
        if hasattr(kernel_gate, "audit") and hasattr(kernel_gate.audit, "get_recent_logs"):
            return kernel_gate.audit.get_recent_logs(int(limit))
        return []
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/rtp/audit/verify")
def rtp_audit_verify():
    db = os.environ.get("KASBAH_AUDIT_DB", "/app/data/rtp_audit.sqlite")
    con = sqlite3.connect(db)
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) FROM audit_log")
    total = int(cur.fetchone()[0])

    cur.execute("SELECT id, prev_hash, row_hash, payload_hash FROM audit_log ORDER BY id ASC")
    rows = cur.fetchall()
    con.close()

    bad_links = 0
    bad_hash = 0
    prev = "GENESIS"

    for _id, prev_hash, row_hash, payload_hash in rows:
        if prev_hash != prev:
            bad_links += 1
        recomputed = hashlib.sha256((prev_hash + payload_hash).encode("utf-8")).hexdigest()
        if recomputed != row_hash:
            bad_hash += 1
        prev = row_hash

    return {"ok": bad_links == 0 and bad_hash == 0, "db": db, "total_rows": total, "bad_links": bad_links, "bad_hash": bad_hash}


app.include_router(rtp_state_router)
app.include_router(agents_router)
