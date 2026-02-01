from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from typing import List

app = FastAPI(title="Kasbah Core", version="0.1.0")

# ---- Models ----

class Intent(BaseModel):
    agent: str
    action: str
    risk: int  # 0-100

class Decision(BaseModel):
    timestamp: str
    agent: str
    action: str
    risk: int
    decision: str
    reason: str
    stage: str  # RTP semantic label (rooting for now)

# ---- In-memory store (v0 only) ----

DECISIONS: List[Decision] = []

# ---- Routes ----

@app.get("/")
def root():
    return {
        "name": "Kasbah Core",
        "tagline": "The Fortress for AI Agents",
        "status": "running",
    }
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
import uuid
import os
import jwt  # PyJWT


app = FastAPI(title="Kasbah Core", version="0.2.0")

# -----------------------
# Config (MVP)
# -----------------------
JWT_SECRET = os.getenv("KASBAH_JWT_SECRET", "REMOVED")
JWT_ISSUER = "kasbah-core"
TICKET_TTL_SECONDS = int(os.getenv("KASBAH_TICKET_TTL_SECONDS", "120"))  # 2 minutes default

# Simple policy threshold (approval required above this, block above hard-block)
APPROVAL_THRESHOLD = int(os.getenv("KASBAH_APPROVAL_THRESHOLD", "50"))
HARD_BLOCK_THRESHOLD = int(os.getenv("KASBAH_HARD_BLOCK_THRESHOLD", "85"))

# -----------------------
# Models
# -----------------------
class Intent(BaseModel):
    agent: str
    action: str
    risk: int  # 0-100


class Decision(BaseModel):
    id: str
    timestamp: str
    agent: str
    action: str
    risk: int
    decision: str  # allow | block | requires_approval
    reason: str
    stage: str  # RTP semantic label (rooting for now)
    approved: Optional[bool] = None  # None=pending, True/False resolved


class ApproveRequest(BaseModel):
    approve: bool
    note: Optional[str] = None


class TicketIssueResponse(BaseModel):
    decision_id: str
    ticket: str
    expires_at: str


class TicketVerifyRequest(BaseModel):
    ticket: str


class TicketVerifyResponse(BaseModel):
    ok: bool
    decision_id: str
    agent: str
    action: str
    exp: int


# -----------------------
# In-memory state (MVP)
# -----------------------
DECISIONS: List[Decision] = []
DECISION_BY_ID: Dict[str, Decision] = {}
USED_JTI: set = set()  # one-time-use ticket ids


# -----------------------
# Helpers
# -----------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_decision(decision_id: str) -> Decision:
    d = DECISION_BY_ID.get(decision_id)
    if not d:
        raise HTTPException(status_code=404, detail="Decision not found")
    return d

def record(d: Decision) -> Decision:
    DECISIONS.append(d)
    DECISION_BY_ID[d.id] = d
    return d

def sign_ticket(decision: Decision) -> TicketIssueResponse:
    # One-time ticket id
    jti = str(uuid.uuid4())
    exp_dt = datetime.now(timezone.utc) + timedelta(seconds=TICKET_TTL_SECONDS)
    payload = {
        "iss": JWT_ISSUER,
        "jti": jti,
        "exp": int(exp_dt.timestamp()),
        "decision_id": decision.id,
        "agent": decision.agent,
        "action": decision.action,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return TicketIssueResponse(decision_id=decision.id, ticket=token, expires_at=exp_dt.isoformat())

def verify_ticket(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=JWT_ISSUER)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Ticket expired")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid ticket issuer")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid ticket")

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="Missing jti")

    if jti in USED_JTI:
        raise HTTPException(status_code=401, detail="Ticket already used")

    return payload


# -----------------------
# Routes
# -----------------------
@app.get("/")
def root():
    return {
        "name": "Kasbah Core",
        "tagline": "The Fortress for AI Agents",
        "status": "running",
        "version": app.version,
    }

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/decide")
def decide(intent: Intent):
    if intent.risk < 0 or intent.risk > 100:
        raise HTTPException(status_code=400, detail="risk must be between 0 and 100")

    decision_id = str(uuid.uuid4())

    # v0 policy
    if intent.risk >= HARD_BLOCK_THRESHOLD:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
            decision="block",
            reason="Hard block threshold exceeded",
            stage="rooting",
            approved=False,
        )
        return record(d)

    if intent.risk >= APPROVAL_THRESHOLD:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
            decision="requires_approval",
            reason="Approval required for elevated risk",
            stage="rooting",
            approved=None,
        )
        return record(d)

    d = Decision(
        id=decision_id,
        timestamp=now_iso(),
        agent=intent.agent,
        action=intent.action,
        risk=intent.risk,
        decision="allow",
        reason="Risk acceptable",
        stage="rooting",
        approved=True,
    )
    return record(d)

@app.get("/decisions")
def list_decisions(limit: int = 50):
    return DECISIONS[-limit:]

@app.get("/pending")
def pending():
    return [d for d in DECISIONS if d.decision == "requires_approval" and d.approved is None]

@app.post("/approve/{decision_id}")
def approve(decision_id: str, req: ApproveRequest):
    d = get_decision(decision_id)
    if d.decision != "requires_approval":
        raise HTTPException(status_code=400, detail="Decision does not require approval")
    if d.approved is not None:
        raise HTTPException(status_code=400, detail="Decision already resolved")

    d.approved = bool(req.approve)
    d.decision = "allow" if d.approved else "block"
    d.reason = (req.note or "Approved by human") if d.approved else (req.note or "Denied by human")
    return d

@app.post("/ticket/issue/{decision_id}")
def ticket_issue(decision_id: str):
    d = get_decision(decision_id)
    if d.decision != "allow" or d.approved is not True:
        raise HTTPException(status_code=403, detail="Ticket can only be issued for allowed decisions")

    return sign_ticket(d)

@app.post("/ticket/verify")
def ticket_verify(req: TicketVerifyRequest):
    payload = verify_ticket(req.ticket)

    # mark one-time use
    USED_JTI.add(payload["jti"])

    # optional: ensure decision still exists and is allowed
    decision_id = payload.get("decision_id")
    d = get_decision(decision_id)
    if d.decision != "allow" or d.approved is not True:
        raise HTTPException(status_code=403, detail="Decision is not currently allowed")

    return TicketVerifyResponse(
        ok=True,
        decision_id=decision_id,
        agent=payload.get("agent", ""),
        action=payload.get("action", ""),
        exp=payload.get("exp", 0),
    )

