import os
import json
from typing import Any, Dict, Optional

import requests
from fastapi import APIRouter, HTTPException, Request

from apps.api.rtp.kernel_gate import kernel_gate

router = APIRouter(prefix="/api/proxy", tags=["proxy"])

OPENAI_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions")


@router.post("/openai/chat")
def openai_chat(payload: Dict[str, Any], request: Request):
    """
    Minimal OpenAI proxy behind Kasbah RBAC + RTP.
    Expects:
      {
        "agent_id": "...",
        "model": "gpt-4o-mini" (or any),
        "messages": [{"role":"user","content":"..."}],
        "signals": {...}   # optional; defaults safe
      }
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not set in environment")

    agent_id = payload.get("agent_id", "anonymous")
    model = payload.get("model", "gpt-4o-mini")
    messages = payload.get("messages", [])
    signals = payload.get("signals") or {
        "consistency": 0.95,
        "accuracy": 0.95,
        "normality": 0.95,
        "latency_score": 0.95,
    }

    # RTP gate BEFORE outbound call
    decision = kernel_gate.decide({
        "tool_name": "openai.chat",
        "agent_id": agent_id,
        "signals": signals,
        "args": {"model": model},
        "_operator_id": getattr(getattr(request, "state", None), "operator", {}).get("id") if hasattr(request, "state") else None,
    })

    if decision.get("decision") != "ALLOW":
        raise HTTPException(status_code=403, detail={"kasbah": decision})

    # Forward to OpenAI
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {"model": model, "messages": messages}

    try:
        r = requests.post(OPENAI_URL, headers=headers, data=json.dumps(body), timeout=30)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream connection error: {e!r}")

    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail={"upstream_status": r.status_code, "upstream_body": r.text, "kasbah": decision})

    return {"kasbah": decision, "upstream": r.json()}
