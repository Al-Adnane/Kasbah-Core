
# __KASBAH_REPLAY_GUARD_V1__
def _ticket_fp(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()

def _remaining_ttl_from_payload(payload: dict, default_ttl: int = 600) -> int:
    """
    Computes remaining TTL seconds from verified ticket payload.
    Expected keys (best-effort):
      - ttl_sec (int)
      - issued_ns (int nanoseconds)
    Falls back to default_ttl if missing/invalid.
    """
    try:
        ttl = int(payload.get("ttl_sec") or default_ttl)
    except Exception:
        ttl = int(default_ttl)
    try:
        issued_ns = int(payload.get("issued_ns") or 0)
    except Exception:
        issued_ns = 0
    if issued_ns > 0:
        issued_s = issued_ns / 1e9
        remaining = int((issued_s + ttl) - time.time())
        return max(1, remaining)
    return max(1, ttl)

def _mark_consumed_once(ticket: str, payload: dict) -> bool:
    """
    Returns True if ticket is newly marked consumed, False if replay.
    Atomic in Redis. Fail-closed if Redis unavailable.
    """
    ttl = _remaining_ttl_from_payload(payload, 600)
    key = "kasbah:ticket:consumed:" + _ticket_fp(ticket)
    try:
        rc = _redis_client()  # exists in this file
    except Exception:
        rc = None
    if rc is None:
        return False
    try:
        ok = rc.set(key, "1", nx=True, ex=ttl)
        return bool(ok)
    except Exception:
        return False
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


APP_NAME = "Kasbah Core"
APP_VERSION = os.environ.get("KASBAH_VERSION", "dev")

API_KEY = os.environ.get("API_KEY", "dev-master-key").encode("utf-8")
TICKET_TTL_SEC = int(os.environ.get("TICKET_TTL_SEC", "600"))
KASBAH_AUTHZ = os.environ.get("KASBAH_AUTHZ", "0").strip().lower() in ("1", "true", "yes", "on")

DATA_DIR = Path(os.environ.get("KASBAH_DATA_DIR", ".kasbah"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_PATH = DATA_DIR / "audit.jsonl"


app = FastAPI(title=APP_NAME, version=APP_VERSION)


def _now_ns() -> int:
    return time.time_ns()


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _sign(payload_b64: str) -> str:
    sig = hmac.new(API_KEY, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return _b64url_encode(sig)


def _hash_tool_args(tool_name: str, args: Any) -> str:
    try:
        s = json.dumps({"tool": tool_name, "args": args}, sort_keys=True, separators=(",", ":"))
    except Exception:
        s = json.dumps({"tool": tool_name, "args": str(args)}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def append_audit(event: str, agent_id: str, jti: Optional[str], extra: Optional[Dict[str, Any]] = None) -> None:
    rec = {
        "ts_ns": _now_ns(),
        "event": event,
        "agent_id": agent_id,
        "jti": jti,
        "extra": extra or {},
    }
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")


class DecisionRequest(BaseModel):
    tool_name: str
    agent_id: Optional[str] = None
    signals: Optional[Dict[str, Any]] = None
    usage: Optional[Dict[str, Any]] = None

    principal: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    acting_as: Optional[str] = None


class DecisionResponse(BaseModel):
    decision: str
    decision_kind: str = "DECIDE_ALLOW"
    reason: str = "ok"
    rule_id: str = "RTP-ALLOW-001"
    ticket: str
    explain: Optional[str] = None


class ConsumeRequest(BaseModel):
    ticket: str
    tool_name: Optional[str] = None
    agent_id: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None


class ConsumeResponse(BaseModel):
    status: str
    action: str
    tool: str
    consumed_at: float


@dataclass
class AuthZResult:
    allow: bool
    reason: str


def _authz_check(principal: str, action: str, resource: str, acting_as: Optional[str]) -> AuthZResult:
    try:
        from apps.api.rtp.authz import check_access  # type: ignore
        az = check_access(principal=str(principal), action=str(action), resource=str(resource), acting_as=(str(acting_as) if acting_as else None))
        allow = bool(getattr(az, "allow", False))
        reason = str(getattr(az, "reason", "")) or str(getattr(az, "why", "")) or "no reason"
        return AuthZResult(allow=allow, reason=reason)
    except Exception as e:
        return AuthZResult(allow=False, reason=f"authz error: {e}")


def generate_ticket(tool_name: str, agent_id: str, args: Any, claims: Dict[str, Any]) -> str:
    jti = hashlib.sha256(f"{tool_name}|{agent_id}|{_now_ns()}".encode("utf-8")).hexdigest()[:32]
    payload = {
        "jti": jti,
        "tool_name": tool_name,
        "agent_id": agent_id,
        "issued_ns": _now_ns(),
        "ttl_sec": TICKET_TTL_SEC,
        "tool_hash": _hash_tool_args(tool_name, args),
        "claims": claims or {},
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig_b64 = _sign(payload_b64)
    return payload_b64 + "." + sig_b64


def verify_ticket(token: str, tool_name: str, args: Any) -> Dict[str, Any]:
    if "." not in token:
        raise HTTPException(status_code=400, detail="invalid ticket format")
    payload_b64, sig_b64 = token.split(".", 1)
    exp_sig = _sign(payload_b64)
    if not hmac.compare_digest(exp_sig, sig_b64):
        raise HTTPException(status_code=403, detail="bad signature")
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    if payload.get("tool_name") != tool_name:
        raise HTTPException(status_code=403, detail="tool mismatch")
    if payload.get("tool_hash") != _hash_tool_args(tool_name, args):
        raise HTTPException(status_code=403, detail="args mismatch")
    issued_ns = int(payload.get("issued_ns", 0))
    ttl_sec = int(payload.get("ttl_sec", 0))
    if issued_ns <= 0 or ttl_sec <= 0:
        raise HTTPException(status_code=403, detail="invalid ttl")
    age_sec = (time.time_ns() - issued_ns) / 1e9
    if age_sec > ttl_sec:
        raise HTTPException(status_code=403, detail="expired")
    return payload


@app.get("/")
def root():
    return {"name": APP_NAME, "status": "running", "version": APP_VERSION}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/rtp/decide", response_model=DecisionResponse)
def rtp_decide(req: DecisionRequest):
    agent_id = req.agent_id or "anon"
    args = (req.usage or {}).get("args", {}) if isinstance(req.usage, dict) else {}

    if KASBAH_AUTHZ:
        principal = req.principal or agent_id
        action = req.action
        resource = req.resource
        acting_as = req.acting_as
        if not principal or not action or not resource:
            res = {
                "decision": "DENY",
                "decision_kind": "AUTHZ_DENY",
                "reason": "missing principal/action/resource",
            }
            try:
                append_audit("AUTHZ_DENY", agent_id=agent_id, jti=None, extra=res)
            except Exception:
                pass
            raise HTTPException(status_code=403, detail=res["reason"])

        az = _authz_check(principal=principal, action=action, resource=resource, acting_as=acting_as)
        if not az.allow:
            try:
                append_audit("AUTHZ_DENY", agent_id=agent_id, jti=None, extra={"principal": principal, "action": action, "resource": resource, "acting_as": acting_as, "reason": az.reason})
            except Exception:
                pass
            raise HTTPException(status_code=403, detail=f"authz deny: {az.reason}")

        claims = {"principal": principal, "action": action, "resource": resource, "acting_as": acting_as}
    else:
        claims = {}

    token = generate_ticket(req.tool_name, agent_id, args, claims)

    try:
        payload = json.loads(_b64url_decode(token.split(".", 1)[0]).decode("utf-8"))
        append_audit("DECIDE", agent_id=agent_id, jti=payload.get("jti"), extra={"tool_name": req.tool_name})
    except Exception:
        pass

    return DecisionResponse(
        decision="ALLOW",
        decision_kind="DECIDE_ALLOW",
        reason="ok",
        rule_id="RTP-ALLOW-001",
        ticket=token,
        explain="Policy checks passed.",
    )


@app.post("/api/rtp/consume", response_model=ConsumeResponse)
def rtp_consume(req: ConsumeRequest, authorization: Optional[str] = Header(default=None)):
    ticket = req.ticket
    tool_name = req.tool_name or "unknown"
    agent_id = req.agent_id or "anon"
    args = (req.usage or {}).get("args", {}) if isinstance(req.usage, dict) else {}

    payload = verify_ticket(ticket, tool_name, args)


    # __KASBAH_REPLAY_GUARD_CALL_V1__
    if not _mark_consumed_once(str(ticket), payload):
        return {"status": "DENIED", "reason": "replay", "valid": False}
    if KASBAH_AUTHZ:
        claims = payload.get("claims", {}) or {}
        principal = claims.get("principal")
        action = claims.get("action")
        resource = claims.get("resource")
        acting_as = claims.get("acting_as")
        if not principal or not action or not resource:
            raise HTTPException(status_code=403, detail="missing authz claims")
        az = _authz_check(principal=str(principal), action=str(action), resource=str(resource), acting_as=(str(acting_as) if acting_as else None))
        if not az.allow:
            raise HTTPException(status_code=403, detail=f"authz deny: {az.reason}")

    try:
        append_audit("CONSUME", agent_id=agent_id, jti=payload.get("jti"), extra={"tool_name": tool_name})
    except Exception:
        pass

    return ConsumeResponse(status="ALLOWED", action="execute", tool=tool_name, consumed_at=time.time())


@app.get("/api/rtp/audit")
def rtp_audit(limit: int = 200, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    try:
        if not AUDIT_PATH.exists():
            return {"events": []}
        lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
        out = []
        for ln in lines[-max(1, min(limit, 2000)):]:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return {"events": out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


try:
    from apps.api.rtp.authz_api import router as authz_router  # type: ignore
    app.include_router(authz_router, prefix="/api/authz")
except Exception:
    pass
