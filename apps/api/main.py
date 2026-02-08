import os
import time
import json
import hashlib
from typing import Dict, Optional, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt

# --- Local Imports (audit only; keep core minimal & stable) ---
from apps.api.rtp.audit import append_audit, read_audit

# --- Configuration ---
SIGN_MODE = os.getenv("KASBAH_SIGN_MODE", "hs256")  # hs256 | ed25519 (ed25519 not wired here)
JWT_SECRET = os.getenv("KASBAH_JWT_SECRET", "dev-only-change-me-in-production")
ISSUER = "kasbah-core"

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
REPLAY_PREFIX = os.getenv("KASBAH_REPLAY_PREFIX", "kasbah:replay:")

# TTL for replay lock; must be >= ticket ttl seconds
REPLAY_TTL_SEC = int(os.getenv("KASBAH_REPLAY_TTL_SEC", "600"))

# Ticket TTL in seconds (default 120s)
TICKET_TTL_SEC = int(os.getenv("KASBAH_TICKET_TTL_SEC", "120"))

# --- FastAPI App ---
app = FastAPI(title="Kasbah Core", version="1.0.0")


# --- Models ---
class DecisionRequest(BaseModel):
    tool_name: str
    agent_id: Optional[str] = None
    signals: Dict[str, Any] = {}
    usage: Dict[str, Any] = {}


class DecisionResponse(BaseModel):
    decision: str
    reason: str
    rule_id: str
    ticket: Optional[str] = None
    explain: Optional[str] = None


class ConsumeRequest(BaseModel):
    ticket: str
    tool_name: str
    agent_id: Optional[str] = None
    usage: Dict[str, Any] = {}


class ConsumeResponse(BaseModel):
    status: str
    action: str
    tool: str
    consumed_at: float


class AuditLogResponse(BaseModel):
    ts: float
    event: str
    agent_id: Optional[str] = None
    jti: Optional[str] = None


# --- Helpers ---
def _redis():
    try:
        import redis  # type: ignore
        return redis.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _now_ns() -> int:
    return time.time_ns()


def sign_ticket_jwt(payload: dict) -> str:
    payload = dict(payload)
    payload["iss"] = ISSUER
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_ticket_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=ISSUER)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid ticket")


def _hash_tool_args(tool_name: str, args: dict) -> str:
    blob = json.dumps({"tool": tool_name, "args": args}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _replay_key(jti: str) -> str:
    return f"{REPLAY_PREFIX}{jti}"


def _claim_replay_once(jti: str) -> None:
    """
    Replay moat: second claim fails.
    Fail CLOSED if redis is unavailable (safer).
    """
    r = _redis()
    if r is None:
        raise HTTPException(status_code=503, detail="replay moat unavailable")

    key = _replay_key(jti)
    ok = r.set(key, "1", nx=True, ex=REPLAY_TTL_SEC)
    if not ok:
        raise HTTPException(status_code=409, detail="replay")


# --- Endpoints ---
@app.get("/")
def root():
    return {"name": "Kasbah Core", "status": "running", "version": app.version}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/rtp/decide", response_model=DecisionResponse)
def rtp_decide(req: DecisionRequest):
    # Minimal policy for now: always allow. (You can re-wire moats later.)
    jti = hashlib.sha256(f"{req.tool_name}|{req.agent_id}|{_now_ns()}".encode("utf-8")).hexdigest()[:32]

    args = (req.usage or {}).get("args", {}) if isinstance(req.usage, dict) else {}
    tool_hash = _hash_tool_args(req.tool_name, args)

    payload = {
        "jti": jti,
        "tool_name": req.tool_name,
        "agent_id": req.agent_id or "anon",
        "args": args,
        "signals": req.signals or {},
        "issued_ns": _now_ns(),
        "ttl_sec": TICKET_TTL_SEC,
        "tool_hash": tool_hash,
    }

    token = sign_ticket_jwt(payload)

    try:
        append_audit("DECIDE", agent_id=req.agent_id or "anon", jti=jti)
    except Exception:
        pass

    return DecisionResponse(
        decision="ALLOW",
        reason="ok",
        rule_id="RTP-ALLOW-001",
        ticket=token,
        explain="Policy checks passed.",
    )


@app.post("/api/rtp/consume", response_model=ConsumeResponse)
def rtp_consume(req: ConsumeRequest):
    payload = verify_ticket_jwt(req.ticket)

    # TTL check
    issued_ns = int(payload.get("issued_ns", 0))
    ttl_sec = int(payload.get("ttl_sec", 0))
    if issued_ns <= 0 or ttl_sec <= 0:
        raise HTTPException(status_code=401, detail="Invalid ticket payload")

    age_sec = (time.time_ns() - issued_ns) / 1e9
    if age_sec > ttl_sec:
        raise HTTPException(status_code=401, detail="Expired ticket")

    # tool match
    if payload.get("tool_name") != req.tool_name:
        raise HTTPException(status_code=400, detail="tool mismatch")

    # agent match (if provided)
    if req.agent_id is not None and payload.get("agent_id") != req.agent_id:
        raise HTTPException(status_code=400, detail="agent mismatch")

    # replay moat
    jti = str(payload.get("jti") or "")
    if not jti:
        raise HTTPException(status_code=401, detail="Invalid ticket payload")
    _claim_replay_once(jti)

    try:
        append_audit("CONSUME", agent_id=req.agent_id or payload.get("agent_id") or "anon", jti=jti)
    except Exception:
        pass

    return ConsumeResponse(status="ALLOWED", action="execute", tool=req.tool_name, consumed_at=time.time())


@app.get("/api/rtp/audit", response_model=list[AuditLogResponse])
def rtp_audit(limit: int = 50):
    logs = read_audit(limit)
    return [AuditLogResponse(**x) for x in logs]
