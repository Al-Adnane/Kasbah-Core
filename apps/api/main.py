from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import uuid
import os
from typing import Optional
import jwt  # PyJWT
import json
import time
from rtp.audit import append_audit
import hashlib
from pathlib import Path
ALWAYS_APPROVAL_TOOLS = {"shell.exec"}
RISK_DENY = 80


app = FastAPI(title="Kasbah Core", version="0.2.0")

@app.on_event("startup")
def _load_state():
    load_decisions_from_log()
    load_used_jti_from_log()

# -----------------------
# Config (MVP)
# -----------------------
JWT_SECRET = os.getenv("KASBAH_JWT_SECRET", "dev-only-change-me")
JWT_ISSUER = "kasbah-core"
SIGN_MODE = os.getenv("KASBAH_SIGN_MODE", "hs256")  # hs256 | ed25519
ED25519_PRIVATE_KEY_PATH = Path(os.getenv("KASBAH_ED25519_PRIVATE_KEY_PATH", ".kasbah/ed25519_private.pem"))
ED25519_PUBLIC_KEY_PATH = Path(os.getenv("KASBAH_ED25519_PUBLIC_KEY_PATH", ".kasbah/ed25519_public.pem"))

TICKET_TTL_SECONDS = int(os.getenv("KASBAH_TICKET_TTL_SECONDS", "120"))  # 2 minutes default
DECISIONS_LOG_PATH = Path(os.getenv("KASBAH_DECISIONS_LOG_PATH", ".kasbah/decisions.jsonl"))
USED_JTI_LOG_PATH = Path(os.getenv("KASBAH_USED_JTI_LOG_PATH", ".kasbah/used_jti.jsonl"))

# Simple policy threshold (approval required above this, block above hard-block)
APPROVAL_THRESHOLD = int(os.getenv("KASBAH_APPROVAL_THRESHOLD", "50"))
HARD_BLOCK_THRESHOLD = int(os.getenv("KASBAH_HARD_BLOCK_THRESHOLD", "85"))
ALWAYS_REQUIRE_APPROVAL = {
    "shell.exec",
    "fs.write",
    "fs.delete",
    "net.post",
    "wallet.send",
}

# -----------------------
# Models
# -----------------------
class Intent(BaseModel):
    agent: str
    action: str
    risk: int  # 0-100
    loop_count_10s: int = 0
    error: bool = False


class Decision(BaseModel):
    id: str
    timestamp: str
    agent: str
    action: str
    risk: int
    brittleness_score: Optional[float] = None
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
def persist_decision(d: Decision):
    DECISIONS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS_LOG_PATH.open("a") as f:
        f.write(json.dumps(d.dict()) + "\n")
def decision_binding_hash(d: Decision) -> str:
    # stable string of what we are binding tickets to
    s = f"{d.id}|{d.agent}|{d.action}|{d.risk}|{d.decision}|{d.approved}|{d.stage}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
def load_decisions_from_log():
    if not DECISIONS_LOG_PATH.exists():
        return
    for line in DECISIONS_LOG_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        d = Decision(**obj)
        DECISION_BY_ID[d.id] = d
    # rebuild DECISIONS list from latest map
    DECISIONS.clear()
    DECISIONS.extend(DECISION_BY_ID.values())
def persist_used_jti(jti: str):
    USED_JTI_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with USED_JTI_LOG_PATH.open("a") as f:
        f.write(json.dumps({"jti": jti}) + "\n")
def _load_ed25519_private():
    data = ED25519_PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def _load_ed25519_public():
    data = ED25519_PUBLIC_KEY_PATH.read_bytes()
    return serialization.load_pem_public_key(data)

def _b64url_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    import base64
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sign_ticket_ed25519(payload: dict) -> str:
    # payload is JSON; signature is over bytes(payload_json)
    msg = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    priv = _load_ed25519_private()
    sig = priv.sign(msg)
    return _b64url_encode(msg) + "." + _b64url_encode(sig)

def verify_ticket_ed25519(token: str) -> dict:
    try:
        msg_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid ticket")
    msg = _b64url_decode(msg_b64)
    sig = _b64url_decode(sig_b64)
    pub = _load_ed25519_public()
    try:
        pub.verify(sig, msg)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid ticket")
    payload = json.loads(msg.decode("utf-8"))
    # exp check
    exp = payload.get("exp")
    if not isinstance(exp, int):
        raise HTTPException(status_code=401, detail="Invalid ticket")
    if int(datetime.now(timezone.utc).timestamp()) > exp:
        raise HTTPException(status_code=401, detail="Ticket expired")
    if payload.get("iss") != JWT_ISSUER:
        raise HTTPException(status_code=401, detail="Invalid ticket issuer")
    return payload

def load_used_jti_from_log():
    if not USED_JTI_LOG_PATH.exists():
        return
    for line in USED_JTI_LOG_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        jti = obj.get("jti")
        if jti:
            USED_JTI.add(jti)

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
    persist_decision(d)
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
        "binding": decision_binding_hash(decision),
    }

    if SIGN_MODE == "ed25519":
        token = sign_ticket_ed25519(payload)
    else:
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return TicketIssueResponse(
        decision_id=decision.id,
        ticket=token,
        expires_at=exp_dt.isoformat(),
    )

def verify_ticket(token: str) -> dict:
    if SIGN_MODE == "ed25519":
        payload = verify_ticket_ed25519(token)
    else:
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


    # composite brittleness score (risk + loop + error)
    score = float(intent.risk)
    loop_penalty = min(intent.loop_count_10s / 50.0, 1.0) * 40.0  # 0..40
    score += loop_penalty
    if intent.error:
        score += 20.0
    score = min(score, 100.0)
    # hard-stop runaway loops (v1 safety rule)
    if intent.loop_count_10s >= 200:
        score = 100.0


    # v1 policy: dangerous tools always require human approval
    if intent.action in ALWAYS_REQUIRE_APPROVAL:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
        brittleness_score=round(score, 2),
            decision="requires_approval",
            reason=f"Action '{intent.action}' requires human approval",
            stage="rooting",
            approved=None,
        )
        return record(d)

    # v0 policy
    if score >= HARD_BLOCK_THRESHOLD:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
        brittleness_score=round(score, 2),
            decision="block",
            reason="Hard block threshold exceeded",
            stage="rooting",
            approved=False,
        )
        return record(d)

    if score >= APPROVAL_THRESHOLD:
        d = Decision(
            id=decision_id,
            timestamp=now_iso(),
            agent=intent.agent,
            action=intent.action,
            risk=intent.risk,
        brittleness_score=round(score, 2),
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
        brittleness_score=round(score, 2),
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

@app.post("/approve_latest")
def approve_latest():
    # Approve the most recent pending requires_approval decision
    for d in reversed(DECISIONS):
        if d.decision == "requires_approval" and d.approved is None:
            d.approved = True
            persist_decision(d)
            return d
    raise HTTPException(status_code=404, detail="No pending decision")

@app.post("/approve/{decision_id}")
def approve(decision_id: str):
    d = get_decision(decision_id)
    if d.approved is not None:
        raise HTTPException(status_code=409, detail="Decision already resolved")
    d.approved = True
    persist_decision(d)
    return d

@app.post("/ticket/issue/{decision_id}")
def ticket_issue(decision_id: str):
    d = get_decision(decision_id)

    if d.decision == "block":
        raise HTTPException(status_code=403, detail="Decision is blocked; ticket cannot be issued")

    if d.decision == "requires_approval":
        if d.approved is not True:
            raise HTTPException(status_code=403, detail="Approval required before issuing ticket")
        return sign_ticket(d)

    if d.decision != "allow":
        raise HTTPException(status_code=400, detail=f"Unsupported decision state: {d.decision}")

    if d.approved is not True:
        raise HTTPException(status_code=403, detail="Decision is not approved; ticket cannot be issued")

    return sign_ticket(d)

    # Normal allow path
    if d.decision != "allow":
        raise HTTPException(status_code=400, detail=f"Unsupported decision state: {d.decision}")

    if d.approved is not True:
        raise HTTPException(status_code=403, detail="Decision is not approved; ticket cannot be issued")

    return sign_ticket(d)
@app.post("/ticket/verify")
def ticket_verify(req: TicketVerifyRequest):
    payload = verify_ticket(req.ticket)
    decision_id = payload.get("decision_id")
    if not decision_id:
        raise HTTPException(status_code=401, detail="Missing decision_id")

    d = get_decision(decision_id)

    # Authorization: allow if decision is allow+approved OR requires_approval+approved
    if d.decision == "block":
        raise HTTPException(status_code=403, detail="Decision is blocked")

    if d.decision == "requires_approval":
        if d.approved is not True:
            raise HTTPException(status_code=403, detail="Approval required")
    elif d.decision == "allow":
        if d.approved is not True:
            raise HTTPException(status_code=403, detail="Decision is not approved")
    else:
        raise HTTPException(status_code=403, detail="Decision is not currently allowed")

    # Mark one-time use ONLY AFTER authorization checks pass
    USED_JTI.add(payload["jti"])
    persist_used_jti(payload["jti"])

    return {
        "ok": True,
        "decision_id": decision_id,
        "agent": payload.get("agent"),
        "action": payload.get("action"),
        "exp": payload.get("exp"),
    }
@app.get("/audit/{decision_id}")
def audit(decision_id: str):
    if not DECISIONS_LOG_PATH.exists():
        return []
    events = []
    for line in DECISIONS_LOG_PATH.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("id") == decision_id:
            events.append(obj)
    return events

@app.post("/admin/compact")
def compact_logs():
    # Compact decisions log: keep only latest record per decision id
    if DECISIONS_LOG_PATH.exists():
        latest = {}
        for line in DECISIONS_LOG_PATH.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            did = obj.get("id")
            if did:
                latest[did] = obj

        tmp = DECISIONS_LOG_PATH.with_suffix(".jsonl.tmp")
        with tmp.open("w") as f:
            for obj in latest.values():
                f.write(json.dumps(obj) + "\n")
        tmp.replace(DECISIONS_LOG_PATH)

    # Compact used jti log: keep unique
    if USED_JTI_LOG_PATH.exists():
        seen = set()
        tmp2 = USED_JTI_LOG_PATH.with_suffix(".jsonl.tmp")
        with tmp2.open("w") as f:
            for line in USED_JTI_LOG_PATH.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                jti = obj.get("jti")
                if jti and jti not in seen:
                    seen.add(jti)
                    f.write(json.dumps({"jti": jti}) + "\n")
        tmp2.replace(USED_JTI_LOG_PATH)

    return {"ok": True}
from fastapi import Body
from rtp import KernelGate, KernelEnforcer

_rtp_gate = KernelGate(tpm_enabled=False, policy={"shell.exec": "allow"})
_rtp_enforcer = KernelEnforcer(_rtp_gate)

from rtp.audit import append_audit
import time

@app.post("/api/rtp/decide")
async def rtp_decide(payload: dict = Body(...)):
    tool = payload.get("tool", "unknown.tool")
    args = payload.get("args", {})
    risk = int(payload.get("risk", 0))
    system_stable = bool(payload.get("system_stable", False))
    limits = payload.get("limits", {"maxTokens": 2000, "maxCostCents": 500})

    # ---- POLICY CONSTANTS (local to avoid touching other files)
    ALWAYS_APPROVAL_TOOLS = {"shell.exec"}
    RISK_DENY = 80

    # ---- 1) HARD TOOL GATE (always first)
    if tool in ALWAYS_APPROVAL_TOOLS:
        append_audit({
            "ts": time.time(),
            "event": "DENY",
            "tool": tool,
            "reason": "needs_approval",
            "rule_id": "RTP-TOOL-001",
        })
        return {
            "decision": "DENY",
            "reason": "needs_approval",
            "rule_id": "RTP-TOOL-001",
            "explain": f"{tool} requires human approval.",
            "ticket": None,
        }

    # ---- 2) SYSTEM STABILITY
    if not system_stable:
        append_audit({
            "ts": time.time(),
            "event": "DENY",
            "tool": tool,
            "reason": "system_unstable",
            "rule_id": "RTP-SYS-001",
        })
        return {
            "decision": "DENY",
            "reason": "system_unstable",
            "rule_id": "RTP-SYS-001",
            "explain": "System flagged unstable.",
            "ticket": None,
        }

    # ---- 3) RISK THRESHOLD
    if risk >= RISK_DENY:
        append_audit({
            "ts": time.time(),
            "event": "DENY",
            "tool": tool,
            "reason": "risk_threshold",
            "rule_id": "RTP-RISK-001",
        })
        return {
            "decision": "DENY",
            "reason": "risk_threshold",
            "rule_id": "RTP-RISK-001",
            "explain": f"Risk score {risk} exceeds threshold.",
            "ticket": None,
        }

    # ---- 4) OTHERWISE: ALLOW + ISSUE TICKET (existing gate)
    ticket = _rtp_gate.generate_ticket(
        tool_name=tool,
        args=args,
    )

    append_audit({
        "ts": time.time(),
        "event": "ALLOW",
        "tool": tool,
        "reason": "ok",
        "rule_id": "RTP-ALLOW-001",
        "jti": ticket.get("jti") if isinstance(ticket, dict) else None,
    })

    return {
        "decision": "ALLOW",
        "reason": "ok",
        "rule_id": "RTP-ALLOW-001",
        "explain": "Policy checks passed.",
        "ticket": ticket,
    }

@app.post("/api/rtp/consume")
async def rtp_consume(payload: dict = Body(...)):
    tool = payload.get("tool")
    jti = payload.get("jti")
    usage = payload.get("usage", {"tokens": 0, "cost": 0})

    if not tool or not jti:
        return {"valid": False, "reason": "tool and jti required"}

    res = _rtp_enforcer.intercept_execution(tool, jti, usage)

    return {
        "valid": res.valid,
        "reason": res.reason,
        "remaining_budget": res.remaining_budget,
    }

# -----------------------
# RTP Audit Endpoint
# -----------------------
from rtp.audit import read_audit

@app.get("/api/rtp/audit")
def rtp_audit(limit: int = 200):
    return read_audit(limit)

