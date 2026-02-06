from fastapi import APIRouter

router = APIRouter(prefix="/api/agents", tags=["agents"])

@router.get("/health")
def agents_health():
    return {"ok": True}
