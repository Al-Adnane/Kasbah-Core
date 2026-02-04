from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict
import uvicorn

# Import the Kernel Gate
from rtp.kernel_gate import KernelGate

app = FastAPI(title="Kasbah Core API", version="1.0.0")

# Initialize System
kernel_gate = KernelGate()

class DecisionRequest(BaseModel):
    tool_name: str
    agent_id: Optional[str] = "anonymous"
    usage: Optional[Dict] = {}
    signals: Dict

@app.get("/health")
def health_check():
    return {
        "status": "operational",
        "system": "Kasbah Core",
        "moats_active": 13
    }

@app.post("/api/rtp/decide")
def decide(request: DecisionRequest):
    try:
        result = kernel_gate.decide(request.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rtp/audit")
def get_audit(limit: int = 10):
    return kernel_gate.audit.get_recent_logs(limit)

@app.get("/api/rtp/status")
def system_status():
    return {
        "feedback_threat_level": kernel_gate.feedback_loop.threat_level,
        "thermo_state": kernel_gate.thermo.get_defense_state(),
        "topology_agents": len(kernel_gate.topology.graph)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
