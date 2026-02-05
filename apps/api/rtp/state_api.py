from fastapi import APIRouter
from apps.api.rtp.agent_state import get_state

router = APIRouter()

@router.get("/api/rtp/agent/{agent_id}/state")
def agent_state(agent_id: str):
    return get_state(agent_id)
