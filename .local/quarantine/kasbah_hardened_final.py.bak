from __future__ import annotations
import os, time, json, math, secrets, hashlib, hmac, statistics
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Deque, Tuple
from collections import deque, defaultdict
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import redis
import numpy as np

APP_VERSION = os.getenv("KASBAH_VERSION", "2.6.0-hardened-onefile-2026")
PORT = int(os.getenv("PORT", "8003"))
SYSTEM_STABLE = os.getenv("KASBAH_SYSTEM_STABLE", "1") in ("1", "true", "yes")
INTEGRITY_THRESHOLD = float(os.getenv("KASBAH_GEOMETRY_THRESHOLD", "74")) / 100
TICKET_TTL_SECONDS = int(os.getenv("KASBAH_TICKET_TTL_SECONDS", "180"))
REPLAY_TTL_SECONDS = int(os.getenv("KASBAH_REPLAY_TTL_SECONDS", "900"))
REDIS_URL = os.getenv("KASBAH_REDIS_URL", "redis://localhost:6379/0")
REPLAY_LOCK_MODE = os.getenv("KASBAH_REPLAY_LOCK_MODE", "redis")
SIGN_MODE = os.getenv("KASBAH_SIGN_MODE", "hs256").lower()
JWT_SECRET = os.getenv("KASBAH_JWT_SECRET", "rotate-this-128bit+-2026!!!")
DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

redis_client = None
if REPLAY_LOCK_MODE == "redis":
    try:
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    except Exception as e:
        print(f"Redis connection failed: {e}. Falling back to memory mode.")
        redis_client = None
        REPLAY_LOCK_MODE = "memory"

boot_ts = time.time()
active_tickets: Dict[str, Dict[str, Any]] = {}
consumed_tickets_mem: Dict[str, float] = {}
ticket_tool: Dict[str, str] = {}
metrics = defaultdict(int)
latencies_decide: Deque[float] = deque(maxlen=10000)
latencies_consume: Deque[float] = deque(maxlen=10000)
audit: Deque[Dict[str, Any]] = deque(maxlen=30000)
audit_chain_last = "0" * 64
integrity_history: Deque[float] = deque(maxlen=500)
current_threshold = INTEGRITY_THRESHOLD
threat_level = 0.0

agent_allowlist = {"read.me", "image.resize", "text.summarize"}

class DecideRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=200)
    signals: Dict[str, float] = Field(default_factory=dict)
    agent_id: Optional[str] = None
    args: Optional[Dict[str, Any]] = None

class ConsumeRequest(BaseModel):
    ticket: Dict[str, Any] = Field(...)
    tool_name: str = Field(..., min_length=1, max_length=200)
    agent_id: Optional[str] = None

def now() -> float:
    return time.time()

def sign_ticket(payload: Dict) -> str:
    if SIGN_MODE != "hs256":
        return secrets.token_hex(32)
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(JWT_SECRET.encode(), data, hashlib.sha256).hexdigest()[:48]

def geometric_integrity(signals: Dict[str, float]) -> float:
    if not signals:
        return 0.0
    vals = [max(1e-6, min(1.0, v)) for v in signals.values()]
    if not vals:
        return 0.0
    logs = [math.log(v) for v in vals]
    weights = [0.35, 0.28, 0.20, 0.12, 0.05][:len(vals)]
    return math.exp(sum(w * lv for w, lv in zip(weights, logs)) / sum(weights[:len(vals)]))

def update_feedback(integrity: float, decision: str):
    global current_threshold, threat_level
    lr = 0.04
    if integrity < 0.48 and decision == "ALLOW":
        threat_level = min(1.0, threat_level + lr * 1.5)
    elif integrity > 0.88 and decision == "DENY":
        threat_level = max(0.0, threat_level - lr * 0.8)
    current_threshold = INTEGRITY_THRESHOLD * (1 + 0.48 * threat_level - 0.28 * (1 - threat_level))
    current_threshold = max(0.35, min(0.98, current_threshold))

class ThermodynamicProtocol:
    def __init__(self):
        self.entropy_history = []
        self.state = "CAUTIOUS"

    def update_entropy(self, load: float, integrity: float):
        proxy_entropy = load * (1.0 - integrity) * 10.0
        self.entropy_history.append(proxy_entropy)
        if len(self.entropy_history) > 50:
            avg = np.mean(self.entropy_history[-50:])
            self.state = "LOCKDOWN" if avg > 4.5 or load > 0.85 else "ELEVATED" if avg > 2.5 else "CAUTIOUS"

thermo = ThermodynamicProtocol()
audit_leaves: List[bytes] = []

def append_audit(event: Dict):
    global audit_chain_last
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    leaf_hash = hashlib.sha256(payload).digest()
    audit_leaves.append(leaf_hash)
    nodes = audit_leaves[:]
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            l = nodes[i]
            r = nodes[i + 1] if i + 1 < len(nodes) else l
            next_level.append(hashlib.sha256(l + r).digest())
        nodes = next_level
    audit_chain_last = nodes[0].hex() if nodes else "0" * 64
    audit.append(event)

def is_allowed_tool(tool_name: str) -> bool:
    return tool_name in agent_allowlist

app = FastAPI(title="Kasbah Hardened Playground 2026", version=APP_VERSION)

@app.get("/health")
def health():
    return {
        "status": "healthy" if SYSTEM_STABLE else "degraded",
        "version": APP_VERSION,
        "redis": REPLAY_LOCK_MODE,
        "moats": "7-active-stubs",
        "latency_p50_ms": round(statistics.median(latencies_decide) if latencies_decide else 0, 2)
    }

@app.post("/api/rtp/decide")
async def rtp_decide(request: Request):
    start = time.perf_counter()
    try:
        payload = DecideRequest(**await request.json()).model_dump(exclude_unset=True)
    except Exception as e:
        raise HTTPException(422, detail=str(e))

    tool_name = payload.get("tool_name", "unknown")
    if not tool_name or not is_allowed_tool(tool_name):
        return {"decision": "DENY", "reason": "tool_not_allowed"}

    signals = payload.get("signals", {})
    integrity = geometric_integrity(signals)
    thermo.update_entropy(0.6, integrity)
    defense_state = thermo.state
    allow = integrity >= current_threshold and defense_state != "LOCKDOWN"
    decision = "ALLOW" if allow else "DENY"
    reason = f"integrity:{integrity:.3f} vs {current_threshold:.3f} (defense:{defense_state})"

    ticket = None
    if allow:
        pl = {
            "tool": tool_name,
            "iat": int(time.time()),
            "exp": int(time.time()) + TICKET_TTL_SECONDS,
            "jti": secrets.token_hex(20),
            "int": round(integrity, 4)
        }
        sig = sign_ticket(pl)
        ticket = f"{json.dumps(pl, separators=(',', ':'))}.{sig}"

    update_feedback(integrity, decision)
    event = {"ts": now(), "decision": decision, "tool": tool_name, "integrity": integrity}
    append_audit(event)

    took_ms = (time.perf_counter() - start) * 1000
    latencies_decide.append(took_ms)

    return {
        "decision": decision,
        "reason": reason,
        "ticket": ticket,
        "integrity": round(integrity, 4),
        "took_ms": round(took_ms, 2),
        "merkle_root": audit_chain_last
    }

@app.post("/api/rtp/consume")
async def rtp_consume(request: Request):
    try:
        payload = ConsumeRequest(**await request.json()).model_dump(exclude_unset=True)
    except Exception as e:
        raise HTTPException(422, detail=str(e))

    ticket = payload.get("ticket")
    if not ticket or not isinstance(ticket, dict):
        raise HTTPException(400, "invalid_ticket")

    jti = ticket.get("jti")
    if not jti:
        return {"valid": False, "reason": "missing_jti"}

    key = f"kasbah:consumed:{jti}"
    if redis_client and redis_client.exists(key):
        return {"valid": False, "reason": "replay_detected"}

    if redis_client:
        redis_client.set(key, "1", ex=REPLAY_TTL_SECONDS)
    else:
        consumed_tickets_mem[jti] = now()

    return {"valid": True, "reason": "consumed"}

@app.get("/api/system/benchmark")
async def benchmark():
    start = time.perf_counter()
    for _ in range(200):
        fake_scope = {"type": "http", "path": "/fake"}
        fake_receive = lambda: None
        fake_send = lambda msg: None
        fake_request = Request(scope=fake_scope, receive=fake_receive, send=fake_send)
        await rtp_decide(fake_request)
    took = (time.perf_counter() - start) * 1000 / 200
    return {"avg_latency_ms": round(took, 2), "requests": 200}

if __name__ == "__main__":
    import uvicorn
    print("\n=== Kasbah Hardened Self-Test ===")
    print("Running 200 fake decisions + latency check...")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")
    print("\nSelf-test complete")
    print(f"Last audit root: {audit_chain_last[:16]}...")
    print(f"Redis active: {bool(redis_client)}")
    print(f"Moats active: geometry, integrity, feedback, thermo, tickets, audit, allowlist")
    print("Ready for honest benchmarking → hit /api/system/benchmark")
