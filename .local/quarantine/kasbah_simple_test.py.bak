#!/usr/bin/env python3
"""
Kasbah Simple Test – Minimal, Sync-only, No venv hell version
Run with: python3 kasbah_simple_test.py
Test in another tab:
  curl http://127.0.0.1:8003/health
  curl http://127.0.0.1:8003/benchmark
  curl -X POST http://127.0.0.1:8003/decide -H "Content-Type: application/json" -d '{"tool":"read.me","signals":{"c":0.95,"a":0.92}}'
"""

import os, time, json, math, secrets, hashlib, hmac
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional

app = FastAPI(title="Kasbah Simple Test", version="minimal-sync-2026")

PORT = 8003
JWT_SECRET = "rotate-this-128bit+-2026!!!"
AGENT_ALLOWLIST = {"read.me", "image.resize", "text.summarize"}

def sign(payload: Dict) -> str:
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

@app.get("/health")
def health():
    return {"status": "ok", "version": "minimal-sync", "port": PORT}

@app.get("/benchmark")
def benchmark():
    start = time.perf_counter()
    for _ in range(20):  # small count to avoid killing machine
        fake_payload = {"tool": "read.me", "signals": {"c": 0.95, "a": 0.92}}
        # simulate decide work
        _ = geometric_integrity(fake_payload.get("signals", {}))
    took = (time.perf_counter() - start) * 1000 / 20
    return {"avg_latency_ms": round(took, 2), "requests": 20}

@app.post("/decide")
def decide(request: Request):
    try:
        payload = request.json()
    except:
        raise HTTPException(422, detail="Invalid JSON")

    tool = payload.get("tool", "unknown")
    if tool not in AGENT_ALLOWLIST:
        return {"decision": "DENY", "reason": "tool not allowed"}

    signals = payload.get("signals", {})
    integrity = geometric_integrity(signals)
    allow = integrity >= 0.74

    ticket = None
    if allow:
        pl = {
            "tool": tool,
            "iat": int(time.time()),
            "exp": int(time.time()) + 180,
            "jti": secrets.token_hex(20),
            "int": round(integrity, 4)
        }
        sig = sign(pl)
        ticket = f"{json.dumps(pl, separators=(',',':'))}.{sig}"

    return {
        "decision": "ALLOW" if allow else "DENY",
        "reason": f"integrity {integrity:.3f}",
        "ticket": ticket,
        "integrity": round(integrity, 4)
    }

if __name__ == "__main__":
    import uvicorn
    print(f"Starting Kasbah Simple Test on port {PORT}")
    print("Test endpoints:")
    print(f"  curl http://127.0.0.1:{PORT}/health")
    print(f"  curl http://127.0.0.1:{PORT}/benchmark")
    print(f"  curl -X POST http://127.0.0.1:{PORT}/decide -H 'Content-Type: application/json' -d '{{ \"tool\": \"read.me\", \"signals\": {{ \"c\":0.95, \"a\":0.92 }} }}'")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
