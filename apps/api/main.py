from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Kasbah Core", version="0.1.0")


class Intent(BaseModel):
    agent: str
    action: str
    risk: int  # 0-100


@app.get("/")
def root():
    return {
        "name": "Kasbah Core",
        "tagline": "The Fortress for AI Agents",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/decide")
def decide(intent: Intent):
    # v0 policy: block high-risk intents
    if intent.risk > 70:
        return {"decision": "block", "reason": "Risk too high", "risk": intent.risk}
    return {"decision": "allow", "reason": "Risk acceptable", "risk": intent.risk}

