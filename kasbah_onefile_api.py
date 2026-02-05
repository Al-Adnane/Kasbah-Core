#!/usr/bin/env python3
from __future__ import annotations

import os
import time
import secrets
from typing import Any, Dict, Optional, List, Deque
from collections import deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# ---------------------------
# Config
# ---------------------------

APP_VERSION = os.getenv("KASBAH_VERSION", "2.0.0-beta-fixed")
SYSTEM_STABLE = os.getenv("KASBAH_SYSTEM_STABLE", "1") in ("1", "true", "yes")
INTEGRITY_THRESHOLD = float(os.getenv("KASBAH_GEOMETRY_THRESHOLD", "70")) / 100.0  # 0..1
TICKET_TTL_SECONDS = int(os.getenv("KASBAH_TICKET_TTL_SECONDS", "300"))
REPLAY_TTL_SECONDS = int(os.getenv("KASBAH_REPLAY_TTL_SECONDS", "600"))
AUDIT_MAX = int(os.getenv("KASBAH_AUDIT_MAX", "10000"))

# ---------------------------
# State (in-memory playground)
# ---------------------------

boot_ts = time.time()

# ticket -> {"tool": str, "expires_at": float, "integrity": float}
active_tickets: Dict[str, Dict[str, Any]] = {}

# ticket -> expires_at (replay protected until expires)
consumed_tickets: Dict[str, float] = {}

# audit ring buffer
audit: Deque[Dict[str, Any]] = deque(maxlen=AUDIT_MAX)

def now() -> float:
    return time.time()

def gc() -> None:
    t = now()
    # expire active
    dead = [k for k, v in active_tickets.items() if v.get("expires_at", 0) <= t]
    for k in dead:
        active_tickets.pop(k, None)
    # expire consumed
    dead2 = [k for k, exp in consumed_tickets.items() if exp <= t]
    for k in dead2:
        consumed_tickets.pop(k, None)

def log(event: str, **fields: Any) -> None:
    audit.append({"timestamp": now(), "event": event, **fields})

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def f(x: Any, default: float = 0.5) -> float:
    try:
        return float(x)
    except Exception:
        return default

def compute_integrity(signals: Dict[str, Any], usage: Dict[str, Any]) -> float:
    """
    Simple deterministic integrity score in [0,1].
    Your real system can be more complex; this is for local play.
    """
    normality = clamp(f(signals.get("normality", 0.9)), 0.0, 1.0)
    consistency = clamp(f(signals.get("consistency", 0.9)), 0.0, 1.0)

    tokens = int(f(usage.get("tokens", 0), 0))
    # penalty grows after 2000 tokens
    token_penalty = 1.0
    if tokens > 2000:
        token_penalty = clamp(1.0 - (tokens - 2000) / 8000.0, 0.35, 1.0)

    integrity = clamp((0.65 * normality + 0.35 * consistency) * token_penalty, 0.0, 1.0)
    return integrity

def mint_ticket() -> str:
    # 32-hex token like your current service
    return secrets.token_hex(16)

# ---------------------------
# FastAPI
# ---------------------------

app = FastAPI(title="Kasbah One-File API", version=APP_VERSION)

@app.exception_handler(Exception)
async def unhandled_exc(request: Request, exc: Exception):
    # Always return JSON even on crash
    log("server_error", path=str(request.url.path), error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "internal_error"})

@app.get("/health")
def health():
    return {"status": "healthy", "time": now()}

@app.get("/api/system/status")
def system_status():
    gc()
    return {
        "status": "operational",
        "active_tickets": len(active_tickets),
        "consumed_tickets": len(consumed_tickets),
        "audit_entries": len(audit),
        "uptime": now(),
        "version": APP_VERSION,
    }

@app.post("/api/rtp/decide")
async def rtp_decide(req: Dict[str, Any]):
    t0 = time.time()

    tool_name = req.get("tool_name") or req.get("tool")
    if not tool_name or not isinstance(tool_name, str):
        raise HTTPException(status_code=422, detail="tool_name_required")

    signals = req.get("signals") or {}
    usage = req.get("usage") or {}

    log("decide_request", tool=tool_name, signals=signals, usage=usage)

    integrity = compute_integrity(signals, usage)

    if not SYSTEM_STABLE:
        decision = "DENY"
        reason = "system_unstable"
        ticket = None
        expires = None
    elif integrity >= INTEGRITY_THRESHOLD:
        decision = "ALLOW"
        reason = "integrity_ok"
        ticket = mint_ticket()
        ttl = int(req.get("ttl", TICKET_TTL_SECONDS))
        ttl = max(1, min(ttl, 3600))
        active_tickets[ticket] = {
            "tool": tool_name,
            "expires_at": now() + ttl,
            "integrity": integrity,
        }
        expires = ttl
    else:
        decision = "DENY"
        reason = "low_integrity"
        ticket = None
        expires = None

    dt = time.time() - t0
    log("decision_made", tool=tool_name, decision=decision, reason=reason,
        integrity=integrity, ticket=ticket, processing_time=dt)

    return {
        "decision": decision,
        "reason": reason,
        "integrity_score": round(integrity, 6),
        "processing_time": round(dt, 6),
        "ticket": ticket,
        "ticket_expires": expires,
    }

@app.post("/api/rtp/consume")
async def rtp_consume(req: Dict[str, Any]):
    t0 = time.time()

    ticket = req.get("ticket")
    tool_name = req.get("tool_name") or req.get("tool")
    usage = req.get("usage") or {}

    if not ticket or not tool_name:
        raise HTTPException(status_code=422, detail="ticket_and_tool_required")
    if not isinstance(ticket, str) or not isinstance(tool_name, str):
        raise HTTPException(status_code=422, detail="ticket_and_tool_required")

    gc()

    if ticket in consumed_tickets:
        log("ticket_already_used", ticket=ticket[:8] + "...", provided_tool=tool_name)
        raise HTTPException(status_code=403, detail="ticket_already_used")

    meta = active_tickets.get(ticket)
    if not meta:
        log("ticket_unknown_or_expired", ticket=ticket[:8] + "...", provided_tool=tool_name)
        raise HTTPException(status_code=403, detail="ticket_unknown_or_expired")

    expected_tool = meta.get("tool")
    if expected_tool and expected_tool != tool_name:
        log("tool_mismatch", ticket=ticket[:8] + "...", expected_tool=expected_tool, provided_tool=tool_name)
        raise HTTPException(status_code=403, detail="tool_mismatch")

    # consume
    consumed_tickets[ticket] = now() + REPLAY_TTL_SECONDS
    active_tickets.pop(ticket, None)

    dt = time.time() - t0
    log("ticket_consumed", ticket=ticket[:8] + "...", tool=tool_name, usage=usage, processing_time=dt)

    return {
        "status": "ALLOWED",
        "action": "execute",
        "tool": tool_name,
        "original_integrity": round(float(meta.get("integrity", 0.0)), 6),
        "processing_time": round(dt, 6),
        "consumed_at": now(),
        "usage_processed": usage,
    }

@app.get("/api/rtp/audit")
def rtp_audit(limit: int = 20, event: Optional[str] = None):
    gc()
    limit = max(1, min(int(limit), 200))
    items = list(audit)[-limit:]
    if event:
        items = [e for e in items if e.get("event") == event]
    return items

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8003"))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)
