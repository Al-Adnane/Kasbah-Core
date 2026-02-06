from fastapi import FastAPI, HTTPException
from typing import Dict, Any
import time
import secrets

app = FastAPI()

# Simplified sandbox for demo purposes
@app.post("/api/playground/execute")
async def playground_execute(code: str, agent_config: Dict[str, Any]):
    """Execute user code in sandbox, show Kasbah analysis (DEMO ONLY)"""
    
    # Parse tool from pseudo-code
    tool_name = "unknown"
    if "database" in code.lower():
        tool_name = "database.query"
    elif "shell" in code.lower() or "rm" in code.lower() or "delete" in code.lower():
        tool_name = "shell.execute"
    elif "api" in code.lower() or "http" in code.lower():
        tool_name = "api.call"
    elif "file" in code.lower():
        tool_name = "file.access"
    
    # Simulate Kasbah analysis
    start_time = time.time()
    
    # Check for malicious patterns
    is_malicious = any(pattern in code.lower() for pattern in [
        "rm -rf", "delete from", "drop table", "format c:", 
        "shutdown", "kill", "inject", "malware", "virus"
    ])
    
    # Generate mock decision
    if is_malicious:
        decision = {
            "decision": "DENY",
            "reason": "malicious_pattern_detected",
            "brittleness_score": 0.94,
            "integrity_score": 0.23,
            "threat_probability": 0.98,
            "execution_time_ms": 6.7,
            "ticket_id": None,
            "moat_breakdown": {
                "brittleness": {"score": 0.94, "status": "CRITICAL"},
                "integrity": {"score": 0.23, "status": "COMPROMISED"},
                "threat_forecast": {"probability": 0.98, "level": "EXTREME"},
                "pattern_detection": "Adversarial attack pattern detected"
            }
        }
    else:
        decision = {
            "decision": "ALLOW",
            "reason": "safe_operation",
            "brittleness_score": 0.45,
            "integrity_score": 0.92,
            "threat_probability": 0.12,
            "execution_time_ms": 4.2,
            "ticket_id": f"kasbah_tkt_{secrets.token_hex(16)}",
            "moat_breakdown": {
                "brittleness": {"score": 0.45, "status": "SAFE"},
                "integrity": {"score": 0.92, "status": "EXCELLENT"},
                "threat_forecast": {"probability": 0.12, "level": "LOW"},
                "pattern_detection": "Normal operation pattern"
            }
        }
    
    # Track for leaderboard
    if decision["decision"] == "DENY":
        # In production, store in database
        pass
    
    decision["processing_time_ms"] = (time.time() - start_time) * 1000
    
    return decision

@app.get("/api/playground/leaderboard")
async def get_playground_leaderboard():
    """Get leaderboard of failed attack attempts"""
    return {
        "total_attempts": 12749,
        "successful_bypasses": 0,
        "top_attempts": [
            {
                "username": "hacker_joe",
                "attack_type": "FGSM adversarial",
                "blocked_in_ms": 3.2,
                "timestamp": "2026-02-05T14:32:11Z"
            },
            {
                "username": "security_sue",
                "attack_type": "SQL injection",
                "blocked_in_ms": 5.7,
                "timestamp": "2026-02-05T11:15:42Z"
            },
            {
                "username": "ai_researcher",
                "attack_type": "Adversarial pattern",
                "blocked_in_ms": 2.1,
                "timestamp": "2026-02-04T19:03:28Z"
            }
        ]
    }
