from fastapi import FastAPI, HTTPException
from datetime import datetime, timezone
import uuid

from models import Intent, Decision

app = FastAPI(title="Kasbah Core", version="0.4.0")

# Policy thresholds (simple + explicit)
HARD_BLOCK_THRESHOLD = 80
APPROVAL_THRESHOLD = 50

# In-memory store (ok for demo; we'll add persistence later)
DECISIONS: list[Decision] = []

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_decision(decision_id: str) -> Decision:
    for d in reversed(DECISIONS):
        if d.id == decision_id:
            return d
    raise HTTPException(status_code=404, detail="Decision not found")

@app.get("/")
def root():
    return {"name": "Kasbah Core", "status": "running", "version": app.version}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/decide", response_model=Decision)
def decide(intent: Intent):
    decision_id = str(uuid.uuid4())

    if intent.risk >= HARD_BLOCK_THRESHOLD:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
            decision="block",
            reason="Hard block threshold exceeded",
            approved=False,
        )
        DECISIONS.append(d)
        return d

    if intent.risk >= APPROVAL_THRESHOLD:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
            decision="requires_approval",
            reason="Approval required for elevated risk",
            approved=None,
        )
        DECISIONS.append(d)
        return d

    d = Decision(
        id=decision_id,
        timestamp=now_iso(),
        agent=intent.agent,
        action=intent.action,
        risk=intent.risk,
        decision="allow",
        reason="Risk acceptable",
        approved=True,
    )
    DECISIONS.append(d)
    return d

@app.get("/decisions")
def list_decisions(limit: int = 50):
    return DECISIONS[-limit:]

@app.get("/pending")
def pending():
    return [d for d in DECISIONS if d.decision == "requires_approval" and d.approved is None]
from fastapi import Body
from pydantic import BaseModel
from typing import Dict, Literal, Optional

class GuardRequest(BaseModel):
    prompt: str
    tool: str = ""
    args: Optional[Dict] = None

class GuardResponse(BaseModel):
    decision: Literal["ALLOW", "BLOCK", "APPROVAL", "STRICT_BLOCK"]
    reason: str
    health_score: float

@app.post("/guard", response_model=GuardResponse)
def guard_endpoint(request: GuardRequest = Body(...)):
    text = (request.prompt + request.tool + str(request.args or {})).lower()
    
    decision = "ALLOW"
    reason = "Passed basic check"
    
    if "payment" in text or "$" in text or "paypal" in text or "send" in text:
        decision = "BLOCK"
        reason = "Blocked money movement attempt (Money Watcher persona)"
    
    # Placeholder integrity — replace with real geometric call later
    health = 85.0
    
    return GuardResponse(
        decision=decision,
        reason=reason,
        health_score=health
    )

from fastapi import Body
from pydantic import BaseModel
from typing import Dict, Literal, Optional, Any

class GuardRequest(BaseModel):
    prompt: str
    tool: str = ""
    args: Optional[Dict[str, Any]] = None

class GuardResponse(BaseModel):
    decision: Literal["ALLOW", "BLOCK", "APPROVAL", "STRICT_BLOCK"]
    reason: str
    health_score: float

def _geometric_integrity(self, signals: Dict[str, float]) -> float:
    """Weighted geometric mean – multiplicative penalty on weak signals"""
    keys = ["consistency", "pred_accuracy", "normality"]
    scores = [max(0.01, signals.get(k, 0.95)) for k in keys]
    weights = [0.50, 0.30, 0.20]
    
    prod = 1.0
    for s, w in zip(scores, weights):
        prod *= s ** w
    
    score = (prod ** (1 / sum(weights))) * 100
    return round(score, 1)

@app.post("/guard", response_model=GuardResponse)
def guard_endpoint(request: GuardRequest = Body(...)):
    text = (request.prompt + request.tool + str(request.args or {})).lower()
    
    # Step 1: Simple persona-based rule check (your Money Watcher example)
    decision = "ALLOW"
    reason = "Passed basic check"
    
    if any(word in text for word in ["payment", "$", "paypal", "venmo", "charge", "subscribe"]):
        decision = "BLOCK"
        reason = "Blocked money movement attempt (Money Watcher persona)"
    
    # Step 2: Real signal collection & geometric scoring
    # Replace this with your actual signals.py / kernel_gate.py call
    # Example placeholder signals (in real code: call your compute_signals())
    signals = {
        "consistency": 0.94,      # tool usage stability
        "pred_accuracy": 0.85,    # prediction match
        "normality": 0.72         # timing/pattern normalcy
    }
    
    health = _geometric_integrity(signals)  # your weighted geometric mean
    
    if health < 70:
        if decision == "ALLOW":
            decision = "STRICT_BLOCK"
        reason += f" | Low integrity ({health}%) – escalated"
    
    # Step 3: TODO – hook your real kernel gating, crypto audit chain, etc.
    # Example:
    # moat_result = kernel_gate.guard(request.prompt, request.tool, request.args)
    # decision = moat_result["decision"]
    # reason = moat_result["reason"]
    # log_audit(request, decision, reason, health)  # your audit.py
    
    return GuardResponse(
        decision=decision,
        reason=reason,
        health_score=health
    )