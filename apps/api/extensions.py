from fastapi import APIRouter

router = APIRouter(prefix="/api/extensions", tags=["extensions"])

@router.get("/health")
def extensions_health():
    return {"ok": True}
