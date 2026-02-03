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
