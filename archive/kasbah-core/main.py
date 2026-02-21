from fastapi import FastAPI

app = FastAPI(title="Kasbah Core", version="0.3.0")

@app.get("/")
def root():
    return {"name": "Kasbah Core", "status": "running", "version": app.version}

@app.get("/health")
def health():
    return {"ok": True}
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
    
    health = 85.0  # placeholder - add your geometric scoring here later
    
    return GuardResponse(
        decision=decision,
        reason=reason,
        health_score=health
    )