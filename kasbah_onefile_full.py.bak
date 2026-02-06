from __future__ import annotations

import os, time, json, math, secrets, hashlib, hmac, statistics
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Deque, Tuple
from collections import deque, defaultdict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# ============================================================
# Kasbah One-File Full Playground API
# - Core: decide/consume/audit/replay/integrity/status
# - Extras (future hooks): metrics, moats registry, policy layer,
#   optional signature modes, audit chain, rate guards
# ============================================================

# -----------------------
# Config
# -----------------------
APP_VERSION = os.getenv("KASBAH_VERSION", "2.0.0-beta-fixed-onefile")
PORT = int(os.getenv("PORT", "8003"))

SYSTEM_STABLE = os.getenv("KASBAH_SYSTEM_STABLE", "1") in ("1", "true", "yes")

# Integrity threshold: your system uses KASBAH_GEOMETRY_THRESHOLD=70 in env
INTEGRITY_THRESHOLD = float(os.getenv("KASBAH_GEOMETRY_THRESHOLD", "70")) / 100.0  # 0..1

TICKET_TTL_SECONDS = int(os.getenv("KASBAH_TICKET_TTL_SECONDS", "300"))
REPLAY_TTL_SECONDS = int(os.getenv("KASBAH_REPLAY_TTL_SECONDS", "600"))

AUDIT_MAX = int(os.getenv("KASBAH_AUDIT_MAX", "20000"))
AUDIT_PERSIST_JSONL = os.getenv("KASBAH_AUDIT_PERSIST_JSONL", "0") in ("1", "true", "yes")
AUDIT_JSONL_PATH = os.getenv("KASBAH_AUDIT_JSONL_PATH", "./.kasbah_onefile_audit.jsonl")

# Replay lock: memory (default) or redis (optional)
REPLAY_LOCK_MODE = os.getenv("KASBAH_REPLAY_LOCK_MODE", "memory")  # memory|redis
REDIS_URL = os.getenv("KASBAH_REDIS_URL", "")

# Signature mode for tickets (future hook). Default: none.
# - none: tickets are random tokens
# - hs256: HMAC signature using KASBAH_JWT_SECRET (not JWT, just HMAC tag)
SIGN_MODE = os.getenv("KASBAH_SIGN_MODE", "none").lower()  # none|hs256
JWT_SECRET = os.getenv("KASBAH_JWT_SECRET", "REMOVED")

DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

# Basic rate guard (future hook; soft)
MAX_ACTIVE_TICKETS = int(os.getenv("KASBAH_MAX_ACTIVE_TICKETS", "50000"))

# -----------------------
# Optional Redis
# -----------------------
redis_client = None
if REPLAY_LOCK_MODE == "redis" and REDIS_URL:
    try:
        import redis  # type: ignore
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        redis_client = None
        REPLAY_LOCK_MODE = "memory"

# ============================================================
# Data + State
# ============================================================

boot_ts = time.time()

# ticket -> metadata
active_tickets: Dict[str, Dict[str, Any]] = {}

# ticket -> expires_at (replay protected)
consumed_tickets: Dict[str, float] = {}

# tool binding cache (for better mismatch logs)
ticket_tool: Dict[str, str] = {}

# metrics (in-memory)
metrics = defaultdict(int)
latencies_decide: Deque[float] = deque(maxlen=5000)
latencies_consume: Deque[float] = deque(maxlen=5000)

# audit ring buffer
audit: Deque[Dict[str, Any]] = deque(maxlen=AUDIT_MAX)

# audit chain (future hook): chain hash linking events
audit_chain_last = "0" * 64

# ============================================================
# Helpers
# ============================================================

def now() -> float:
    return time.time()

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def f(x: Any, default: float = 0.5) -> float:
    try:
        return float(x)
    except Exception:
        return default

def gc() -> None:
    """Garbage collect expired tickets (memory mode)."""
    t = now()
    dead_active = [k for k, v in active_tickets.items() if v.get("expires_at", 0) <= t]
    for k in dead_active:
        active_tickets.pop(k, None)
        ticket_tool.pop(k, None)

    dead_used = [k for k, exp in consumed_tickets.items() if exp <= t]
    for k in dead_used:
        consumed_tickets.pop(k, None)
        ticket_tool.pop(k, None)

def _chain_hash(prev: str, event: Dict[str, Any]) -> str:
    data = json.dumps(event, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256((prev + data).encode("utf-8")).hexdigest()

def audit_log(event: str, **fields: Any) -> None:
    """Append an audit event with optional chained integrity."""
    global audit_chain_last
    e = {"timestamp": now(), "event": event, **fields}
    audit_chain_last = _chain_hash(audit_chain_last, e)
    e["chain"] = audit_chain_last
    audit.append(e)

    if AUDIT_PERSIST_JSONL:
        try:
            os.makedirs(os.path.dirname(AUDIT_JSONL_PATH) or ".", exist_ok=True)
            with open(AUDIT_JSONL_PATH, "a", encoding="utf-8") as w:
                w.write(json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n")
        except Exception:
            # never break runtime for audit persistence
            pass

def p95(xs: List[float]) -> float:
    if not xs:
        return 0.0
    xs2 = sorted(xs)
    k = int(math.ceil(0.95 * len(xs2))) - 1
    return float(xs2[max(0, min(k, len(xs2)-1))])

# ============================================================
# Future-layer: Moats Registry (feature flag-ish)
# ============================================================

@dataclass
class MoatStatus:
    name: str
    enabled: bool
    notes: str

def moats_status() -> List[MoatStatus]:
    # “Exhaustive” list — some are real, some are hooks.
    # Keep enabled flags honest: only turn on what is actually implemented here.
    return [
        MoatStatus("moat1_replay_lock", True, f"mode={REPLAY_LOCK_MODE}"),
        MoatStatus("moat2_integrity_geometry", True, f"threshold={INTEGRITY_THRESHOLD:.2f}"),
        MoatStatus("moat3_audit_trail", True, f"ring={AUDIT_MAX} persist_jsonl={AUDIT_PERSIST_JSONL}"),
        MoatStatus("moat4_tool_binding", True, "ticket bound to tool_name"),
        MoatStatus("moat5_policy_layer", True, "simple allow/deny/human_approval policy map"),
        MoatStatus("moat6_signature_mode", SIGN_MODE in ("hs256",), f"mode={SIGN_MODE}"),
        MoatStatus("moat7_metrics", True, "in-memory request counters + latency windows"),
        MoatStatus("moat8_thermo_protocol", False, "hook only (not enforced)"),
        MoatStatus("moat9_moe_fusion", False, "hook only (not enforced)"),
        MoatStatus("moat10_qift_signals", True, "basic signal normalization; hook for richer transforms"),
        MoatStatus("moat11_attack_surface_guard", True, "reject missing required fields; soft cap on active tickets"),
        MoatStatus("moat12_audit_chain_hash", True, "sha256 chain linking events"),
        MoatStatus("moat13_compat_fields", True, "accept tool or tool_name; stable response shapes"),
    ]

# ============================================================
# Future-layer: Policy (simple, local)
# ============================================================

# Policy modes: allow, deny, human_approval
POLICY: Dict[str, str] = {
    "*": "allow",
    # example of dangerous tool requiring human approval:
    "shell.exec": "human_approval",
}

def policy_mode(tool_name: str) -> str:
    m = POLICY.get(tool_name, POLICY.get("*", "deny"))
    if m not in ("allow", "deny", "human_approval"):
        return "deny"
    return m

# ============================================================
# Integrity + Signals (real + hooks)
# ============================================================

def normalize_signals(signals: Dict[str, Any]) -> Dict[str, float]:
    # keep keys stable; clamp to [0,1]
    out = {}
    for k in ("normality", "consistency", "accuracy", "latency", "latency_score"):
        if k in signals:
            out[k] = clamp(f(signals.get(k), 0.5), 0.0, 1.0)
    # compatibility: if latency_score used, map to latency
    if "latency" not in out and "latency_score" in out:
        out["latency"] = out["latency_score"]
    return out

def compute_integrity(signals: Dict[str, Any], usage: Dict[str, Any]) -> float:
    """
    Geometric-ish integrity that behaves like your audits:
    lower normality and large token usage drop integrity below threshold.
    """
    s = normalize_signals(signals)

    normality = clamp(s.get("normality", 0.9), 0.001, 1.0)
    consistency = clamp(s.get("consistency", 0.9), 0.001, 1.0)
    accuracy = clamp(s.get("accuracy", 0.9), 0.001, 1.0)
    latency = clamp(s.get("latency", 0.9), 0.001, 1.0)

    # token penalty
    tokens = int(f((usage or {}).get("tokens", 0), 0))
    token_penalty = 1.0
    if tokens > 2000:
        token_penalty = clamp(1.0 - (tokens - 2000) / 8000.0, 0.35, 1.0)

    # weighted geometric mean
    w = {"consistency": 0.30, "accuracy": 0.30, "normality": 0.25, "latency": 0.15}
    integrity = (consistency ** w["consistency"]) * (accuracy ** w["accuracy"]) * (normality ** w["normality"]) * (latency ** w["latency"])
    return clamp(integrity * token_penalty, 0.0, 1.0)

# ============================================================
# Ticketing + Optional Signatures
# ============================================================

def mint_ticket() -> str:
    return secrets.token_hex(16)  # 32 hex chars

def sign_ticket(ticket: str, tool_name: str, exp: int, integrity: float) -> str:
    """
    Future hook:
    - none: return ticket as-is
    - hs256: return ticket.signature (hex)
    """
    if SIGN_MODE != "hs256":
        return ticket
    payload = f"{ticket}|{tool_name}|{exp}|{integrity:.6f}|{JWT_ISSUER}"
    sig = hmac.new(JWT_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{ticket}.{sig}"

def verify_ticket_signed(token: str, tool_name: str, exp: int, integrity: float) -> Tuple[bool, str]:
    if SIGN_MODE != "hs256":
        return True, "ok"
    if "." not in token:
        return False, "signature_missing"
    ticket, sig = token.split(".", 1)
    payload = f"{ticket}|{tool_name}|{exp}|{integrity:.6f}|{JWT_ISSUER}"
    expected = hmac.new(JWT_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, "signature_invalid"
    return True, "ok"

def ticket_core(token: str) -> str:
    # if hs256 mode, core ticket is before dot
    return token.split(".", 1)[0]

# ============================================================
# Replay lock (memory / redis optional)
# ============================================================

def mark_active(token: str, tool_name: str, ttl_s: int, integrity: float) -> None:
    """Store active ticket with tool binding and expiry."""
    core = ticket_core(token)
    exp = int(now() + ttl_s)

    if len(active_tickets) > MAX_ACTIVE_TICKETS:
        # soft cap; deny new tickets if flooded
        raise HTTPException(status_code=429, detail="too_many_active_tickets")

    if REPLAY_LOCK_MODE == "redis" and redis_client:
        # store tool + exp + integrity
        redis_client.hset(f"kasbah:active:{core}", mapping={"tool": tool_name, "exp": str(exp), "integrity": f"{integrity:.6f}"})
        redis_client.expire(f"kasbah:active:{core}", ttl_s)
    else:
        gc()
        active_tickets[core] = {"tool": tool_name, "expires_at": float(exp), "integrity": float(integrity)}
        ticket_tool[core] = tool_name

def consume_once(token: str, tool_name: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Return (ok, reason, meta)
    reason: ok | ticket_already_used | ticket_unknown_or_expired | tool_mismatch | signature_invalid
    """
    core = ticket_core(token)

    # memory path
    if REPLAY_LOCK_MODE != "redis" or not redis_client:
        gc()
        if core in consumed_tickets:
            return False, "ticket_already_used", None
        meta = active_tickets.get(core)
        if not meta:
            return False, "ticket_unknown_or_expired", None
        expected = meta.get("tool")
        if expected and expected != tool_name:
            return False, "tool_mismatch", meta

        exp = int(meta.get("expires_at", 0))
        ok, sig_reason = verify_ticket_signed(token, tool_name, exp, float(meta.get("integrity", 0.0)))
        if not ok:
            return False, sig_reason, meta

        consumed_tickets[core] = now() + REPLAY_TTL_SECONDS
        active_tickets.pop(core, None)
        return True, "ok", meta

    # redis path
    active_key = f"kasbah:active:{core}"
    used_key = f"kasbah:used:{core}"

    if redis_client.exists(used_key):
        return False, "ticket_already_used", None

    meta = redis_client.hgetall(active_key)
    if not meta:
        return False, "ticket_unknown_or_expired", None

    expected = meta.get("tool", "")
    if expected and expected != tool_name:
        return False, "tool_mismatch", meta

    exp = int(meta.get("exp", "0") or "0")
    integrity = float(meta.get("integrity", "0") or "0")
    ok, sig_reason = verify_ticket_signed(token, tool_name, exp, integrity)
    if not ok:
        return False, sig_reason, meta

    # mark used + delete active (best-effort atomic via pipeline)
    pipe = redis_client.pipeline()
    pipe.setex(used_key, REPLAY_TTL_SECONDS, "1")
    pipe.delete(active_key)
    pipe.execute()
    return True, "ok", meta

# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(title="Kasbah Full One-File", version=APP_VERSION)

@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    audit_log("server_error", path=str(request.url.path), error=str(exc))
    if DEBUG:
        raise
    return JSONResponse(status_code=500, content={"detail": "internal_error"})

@app.get("/health")
def health():
    metrics["health_requests"] += 1
    return {"status": "healthy", "time": now()}

@app.get("/api/system/status")
def system_status():
    metrics["status_requests"] += 1
    gc()
    # note: for redis mode, count is expensive; keep it approximate here
    active = len(active_tickets) if REPLAY_LOCK_MODE != "redis" else 0
    used = len(consumed_tickets) if REPLAY_LOCK_MODE != "redis" else 0
    return {
        "status": "operational",
        "active_tickets": active,
        "consumed_tickets": used,
        "audit_entries": len(audit),
        "uptime": now(),
        "version": APP_VERSION,
    }

@app.get("/api/system/metrics")
def system_metrics():
    gc()
    dlat = list(latencies_decide)
    clat = list(latencies_consume)
    return {
        "counts": dict(metrics),
        "decide_latency_ms": {
            "avg": (statistics.mean(dlat) * 1000.0) if dlat else 0.0,
            "p95": (p95(dlat) * 1000.0) if dlat else 0.0,
            "n": len(dlat),
        },
        "consume_latency_ms": {
            "avg": (statistics.mean(clat) * 1000.0) if clat else 0.0,
            "p95": (p95(clat) * 1000.0) if clat else 0.0,
            "n": len(clat),
        },
        "replay_lock_mode": REPLAY_LOCK_MODE,
        "sign_mode": SIGN_MODE,
    }

@app.get("/api/system/moats")
def system_moats():
    ms = moats_status()
    return {
        "enabled_count": sum(1 for m in ms if m.enabled),
        "total": len(ms),
        "moats": [m.__dict__ for m in ms],
    }

@app.get("/api/system/policy")
def system_policy():
    # read-only; avoid remote policy edits in a playground that might leak into habits
    return {"policy": POLICY}

@app.post("/api/rtp/decide")
async def rtp_decide(req: Dict[str, Any]):
    t0 = time.time()
    metrics["decide_requests"] += 1

    tool_name = req.get("tool_name") or req.get("tool")
    if not tool_name or not isinstance(tool_name, str):
        metrics["decide_422"] += 1
        raise HTTPException(status_code=422, detail="tool_name_required")

    signals = req.get("signals") or {}
    usage = req.get("usage") or {}

    audit_log("decide_request", tool=tool_name, signals=normalize_signals(signals), usage=usage)

    # policy gate first
    pm = policy_mode(tool_name)
    if pm == "deny":
        dt = time.time() - t0
        latencies_decide.append(dt)
        audit_log("decision_made", tool=tool_name, decision="DENY", reason="policy_deny", integrity=0.0, ticket=None, processing_time=dt)
        metrics["decide_deny"] += 1
        return {"decision": "DENY", "reason": "policy_deny", "integrity_score": 0.0, "processing_time": round(dt, 6), "ticket": None, "ticket_expires": None}

    if pm == "human_approval":
        dt = time.time() - t0
        latencies_decide.append(dt)
        audit_log("decision_made", tool=tool_name, decision="DENY", reason="human_approval_required", integrity=0.0, ticket=None, processing_time=dt)
        metrics["decide_deny"] += 1
        return {"decision": "DENY", "reason": "human_approval_required", "integrity_score": 0.0, "processing_time": round(dt, 6), "ticket": None, "ticket_expires": None}

    integrity = compute_integrity(signals, usage)

    if not SYSTEM_STABLE:
        decision, reason, token, expires = "DENY", "system_unstable", None, None
        metrics["decide_deny"] += 1
    elif integrity >= INTEGRITY_THRESHOLD:
        decision, reason = "ALLOW", "integrity_ok"
        raw = mint_ticket()
        ttl = int(req.get("ttl", TICKET_TTL_SECONDS))
        ttl = max(1, min(ttl, 3600))
        token = sign_ticket(raw, tool_name, int(now()+ttl), integrity)
        mark_active(token, tool_name, ttl, integrity)
        expires = ttl
        metrics["decide_allow"] += 1
    else:
        decision, reason, token, expires = "DENY", "low_integrity", None, None
        metrics["decide_deny"] += 1

    dt = time.time() - t0
    latencies_decide.append(dt)

    audit_log("decision_made", tool=tool_name, decision=decision, reason=reason, integrity=integrity, ticket=(ticket_core(token) if token else None), processing_time=dt)

    return {
        "decision": decision,
        "reason": reason,
        "integrity_score": round(integrity, 6),
        "processing_time": round(dt, 6),
        "ticket": token if token else None,
        "ticket_expires": expires,
    }

@app.post("/api/rtp/consume")
async def rtp_consume(req: Dict[str, Any]):
    t0 = time.time()
    metrics["consume_requests"] += 1

    token = req.get("ticket")
    tool_name = req.get("tool_name") or req.get("tool")
    usage = req.get("usage") or {}

    if not token or not tool_name:
        metrics["consume_422"] += 1
        raise HTTPException(status_code=422, detail="ticket_and_tool_required")
    if not isinstance(token, str) or not isinstance(tool_name, str):
        metrics["consume_422"] += 1
        raise HTTPException(status_code=422, detail="ticket_and_tool_required")

    ok, reason, meta = consume_once(token, tool_name)
    if not ok:
        metrics[f"consume_{reason}"] += 1
        audit_log(reason, ticket=ticket_core(token)[:8] + "...", expected_tool=(meta.get("tool") if isinstance(meta, dict) else None), provided_tool=tool_name)
        raise HTTPException(status_code=403, detail=reason)

    dt = time.time() - t0
    latencies_consume.append(dt)
    metrics["consume_ok"] += 1

    original_integrity = 0.0
    if isinstance(meta, dict):
        original_integrity = float(meta.get("integrity", 0.0) or 0.0)

    audit_log("ticket_consumed", ticket=ticket_core(token)[:8] + "...", tool=tool_name, usage=usage, processing_time=dt)

    return {
        "status": "ALLOWED",
        "action": "execute",
        "tool": tool_name,
        "original_integrity": round(original_integrity, 6),
        "processing_time": round(dt, 6),
        "consumed_at": now(),
        "usage_processed": usage,
    }

@app.get("/api/rtp/audit")
def rtp_audit(limit: int = 20, event: Optional[str] = None):
    metrics["audit_requests"] += 1
    gc()
    limit = max(1, min(int(limit), 200))
    items = list(audit)[-limit:]
    if event:
        items = [e for e in items if e.get("event") == event]
    return items

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT, reload=False)
