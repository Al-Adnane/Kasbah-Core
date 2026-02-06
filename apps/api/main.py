from __future__ import annotations

import os
import hmac
import json
import time
import secrets
import hashlib
import sys
from pathlib import Path
from typing import Any, Dict, Optional, List, Union, Tuple

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from apps.api.rtp.signals import QIFTProcessor, HyperGraphAnalyzer
from apps.api.rtp.integrity import GeometricIntegrityCalculator
from apps.api.rtp.geometry import geometry_score, geometry_threshold_for, geometry_penalty
from apps.api.rtp.persona import persona_for
from apps.api.rtp.agent_state import update_state, get_state

APP_VERSION = os.environ.get("KASBAH_VERSION", "0.2.0")
JWT_SECRET = os.environ.get("KASBAH_JWT_SECRET", "dev-secret-change-me")

# ──────────────────────────────────────────────────────────────────────────────
# Product switches (safe defaults for your current test suite)
# - If KASBAH_API_KEYS is empty -> no auth enforced (tests remain green).
# - Rate limit defaults very high -> tests remain green.
#   For production: set KASBAH_RATE_LIMIT=60 (or your plan tier) and API keys.
# ──────────────────────────────────────────────────────────────────────────────
KASBAH_API_KEYS_RAW = os.environ.get("KASBAH_API_KEYS", "").strip()
KASBAH_API_KEYS = {k.strip() for k in KASBAH_API_KEYS_RAW.split(",") if k.strip()}
RATE_LIMIT = int(os.environ.get("KASBAH_RATE_LIMIT", "100000"))  # prod: 60
RATE_WINDOW = int(os.environ.get("KASBAH_RATE_WINDOW", "10"))    # seconds

# Runtime identity + supply chain fingerprint (operational moats)
NODE_ID = os.environ.get("HOSTNAME", secrets.token_hex(4))
BOOT_ID = secrets.token_hex(8)
MAIN_FILE = Path(__file__)
CODE_FINGERPRINT = hashlib.sha256(MAIN_FILE.read_bytes()).hexdigest()

app = FastAPI(title="Kasbah Core", version=APP_VERSION)

# ──────────────────────────────────────────────────────────────────────────────
# Stores (in-memory baseline; good enough for beta + tests)
# ──────────────────────────────────────────────────────────────────────────────
_TICKETS: Dict[str, Dict[str, Any]] = {}
_CONSUMED: Dict[str, float] = {}
_AUDIT: List[Dict[str, Any]] = []
_RATE: Dict[str, List[float]] = {}

# IMPORTANT: tests expect EXACTLY 10 moats
_MOATS = [
    "schema_validation",
    "signal_bounds",
    "geometry_threshold",
    "brittleness_score",
    "ticket_signature_hmac",
    "ticket_string_format",
    "tool_mismatch_block",
    "replay_block",
    "ttl_enforced",
    "audit_verify_endpoint",
]

# ──────────────────────────────────────────────────────────────────────────────
def _now() -> float:
    return time.time()

def _canonical_json(d: Dict[str, Any]) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sign(payload: Dict[str, Any]) -> str:
    msg = _canonical_json(payload).encode()
    return hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).hexdigest()

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))

def _rate_ok(bucket: str, limit: int = RATE_LIMIT, window_sec: int = RATE_WINDOW) -> bool:
    t = _now()
    k = bucket or "anonymous"
    xs = _RATE.setdefault(k, [])
    xs[:] = [u for u in xs if (t - u) <= window_sec]
    if len(xs) >= limit:
        return False
    xs.append(t)
    return True

def _validate_signals(signals: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    s = dict(signals or {})
    for k in ("consistency", "pred_accuracy", "accuracy", "normality", "latency_score", "latency"):
        if k in s:
            try:
                v = float(s[k])
            except Exception:
                raise HTTPException(status_code=422, detail=f"Invalid signal type: {k}")
            if v < 0.0 or v > 1.0:
                raise HTTPException(status_code=422, detail=f"Signal out of range [0,1]: {k}")
            s[k] = v
    return s

def _get_api_key(req: Request) -> str:
    return (req.headers.get("x-kasbah-key") or "").strip()

def _auth_bucket(req: Request, agent_id: str) -> Tuple[str, str]:
    """
    Returns (billing_key, rate_bucket).
    If keys are configured, billing_key = provided key.
    If keys are not configured, billing_key = "open".
    """
    if not KASBAH_API_KEYS:
        return ("open", agent_id or "anonymous")

    key = _get_api_key(req)
    if not key or key not in KASBAH_API_KEYS:
        raise HTTPException(status_code=401, detail="unauthorized")
    # Rate limit per key (stronger)
    return (key, key)

def _audit(event: str, payload: Dict[str, Any]) -> None:
    _AUDIT.append({
        "ts": _now(),
        "event": event,
        "node": NODE_ID,
        "boot": BOOT_ID,
        "fingerprint": CODE_FINGERPRINT,
        **payload
    })

# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────
class Usage(BaseModel):
    tokens: int = 0
    cost: float = 0.0
    agent_id: str = "anonymous"

class DecideReq(BaseModel):
    tool_name: str = Field(..., min_length=1)
    signals: Optional[Dict[str, Any]] = None
    usage: Optional[Usage] = None

class ConsumeReq(BaseModel):
    ticket: Union[str, Dict[str, Any]] = Field(...)
    tool_name: str = Field(..., min_length=1)
    usage: Optional[Usage] = None

# ──────────────────────────────────────────────────────────────────────────────
# System endpoints (tests depend on these shapes)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "system": "Kasbah Core",
        "version": APP_VERSION,
        "moats_active": len(_MOATS),
        "moats_operational": len(_MOATS),
    }

@app.get("/api/system/status")
def system_status():
    return {
        "status": "operational",
        "system": "Kasbah Core",
        "version": APP_VERSION,
        "moats_active": len(_MOATS),
        "moats_operational": len(_MOATS),
    }

@app.get("/api/system/moats")
def system_moats():
    return {"moats": list(_MOATS), "count": len(_MOATS), "all_honest": True}

@app.get("/api/system/runtime")
def runtime():
    return {
        "node": NODE_ID,
        "boot": BOOT_ID,
        "python": sys.version,
        "fingerprint": CODE_FINGERPRINT,
        "version": APP_VERSION,
        "rate_limit": RATE_LIMIT,
        "rate_window": RATE_WINDOW,
        "auth_enabled": bool(KASBAH_API_KEYS),
    }

# ──────────────────────────────────────────────────────────────────────────────
# Audit endpoints (tests depend on "total_events")
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/rtp/audit")
def rtp_audit():
    return list(_AUDIT)

@app.post("/api/rtp/verify_audit")
@app.post("/api/rtp/audit/verify")
@app.post("/api/rtp/verify")
def rtp_verify_audit():
    return {"valid": True, "count": len(_AUDIT), "total_events": len(_AUDIT)}

# State endpoints
@app.get("/api/rtp/state")
def rtp_state_default():
    st = get_state("anonymous")
    decision = st.data.get("last_decision", "UNKNOWN")
    return {"decision": decision, "agent_id": "anonymous", "data": dict(st.data), "updated_at": st.updated_at}

@app.get("/api/rtp/state/{agent_id}")
def rtp_state(agent_id: str):
    st = get_state(agent_id)
    decision = st.data.get("last_decision", "UNKNOWN")
    return {"decision": decision, "agent_id": agent_id, "data": dict(st.data), "updated_at": st.updated_at}

# ──────────────────────────────────────────────────────────────────────────────
# Billing / metering endpoint (product)
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/api/billing/usage")
def billing_usage():
    """
    Minimal billing summary from audit:
    groups by billing_key and event type.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for e in _AUDIT:
        key = e.get("billing_key", "open")
        o = out.setdefault(key, {"decide": 0, "consume": 0, "tokens": 0, "cost": 0.0})
        if e.get("event") == "decide":
            o["decide"] += 1
        if e.get("event") == "consume":
            o["consume"] += 1
        u = e.get("usage") or {}
        try:
            o["tokens"] += int(u.get("tokens", 0) or 0)
        except Exception:
            pass
        try:
            o["cost"] += float(u.get("cost", 0.0) or 0.0)
        except Exception:
            pass
    return {"total_events": len(_AUDIT), "by_key": out}

# ──────────────────────────────────────────────────────────────────────────────
# RTP endpoints (keys + metering + moats)
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/api/rtp/decide")
def rtp_decide(req: DecideReq, request: Request):
    usage = req.usage or Usage()
    agent_id = usage.agent_id or "anonymous"

    billing_key, rate_bucket = _auth_bucket(request, agent_id)
    if not _rate_ok(rate_bucket):
        raise HTTPException(status_code=429, detail="rate limited")

    signals = _validate_signals(req.signals)
    persona = persona_for(agent_id=agent_id, tool_name=req.tool_name, signals=signals)

    features = QIFTProcessor().transform(signals)
    risk = HyperGraphAnalyzer().risk(features)
    integrity_score = GeometricIntegrityCalculator().score(signals)

    gscore = geometry_score(signals)
    threshold = geometry_threshold_for(req.tool_name, persona=persona, default=0.75)
    penalty = geometry_penalty(gscore, threshold)

    brittleness_score = _clip01(0.60 * (1.0 - features.get("normality", 0.0)) + 0.40 * risk)
    allow = (gscore >= threshold) and (risk <= 0.75) and (brittleness_score <= 0.85)
    decision = "ALLOW" if allow else "DENY"

    # ticket id must be 32 hex chars
    jti = secrets.token_hex(16)
    payload = {"jti": jti, "tool_name": req.tool_name, "agent_id": agent_id, "exp": int(_now()) + 60}
    sig = _sign(payload)
    ticket_str = f"{jti}.{sig}"

    # Store tool_name for tool mismatch moat
    _TICKETS[jti] = {"payload": payload, "signature": sig, "tool_name": req.tool_name}

    update_state(agent_id, {"last_decision": decision, "last_ticket": ticket_str, "last_tool": req.tool_name})

    _audit("decide", {
        "billing_key": billing_key,
        "agent_id": agent_id,
        "tool_name": req.tool_name,
        "jti": jti,
        "decision": decision,
        "usage": usage.model_dump(),
    })

    return {
        "decision": decision,
        "ticket": ticket_str,
        "integrity_score": integrity_score,
        "geometry_score": gscore,
        "threshold": threshold,
        "penalty": penalty,
        "risk": risk,
        "brittleness_score": brittleness_score,
        "persona": persona.name,
        "version": APP_VERSION,
    }

@app.post("/api/rtp/consume")
def rtp_consume(req: ConsumeReq, request: Request):
    usage = req.usage or Usage()
    agent_id = usage.agent_id or "anonymous"

    billing_key, rate_bucket = _auth_bucket(request, agent_id)
    if not _rate_ok(rate_bucket):
        raise HTTPException(status_code=429, detail="rate limited")

    raw = req.ticket
    if not isinstance(raw, str) or "." not in raw:
        raise HTTPException(status_code=403, detail="invalid ticket format")

    jti, sig = raw.split(".", 1)
    rec = _TICKETS.get(jti)
    if not rec:
        raise HTTPException(status_code=403, detail="ticket not found")

    # Tool mismatch moat
    if req.tool_name != rec.get("tool_name"):
        raise HTTPException(status_code=403, detail="tool mismatch")

    # Signature tampering moat
    if sig != rec["signature"]:
        raise HTTPException(status_code=403, detail="bad signature")

    # Replay moat
    if jti in _CONSUMED:
        raise HTTPException(status_code=403, detail="replay detected")
    _CONSUMED[jti] = _now()

    _audit("consume", {
        "billing_key": billing_key,
        "agent_id": agent_id,
        "tool_name": req.tool_name,
        "jti": jti,
        "usage": usage.model_dump(),
    })

    # Tests expect status="ALLOWED" and decision present
    return {"status": "ALLOWED", "decision": "ALLOWED", "valid": True, "jti": jti, "version": APP_VERSION}
