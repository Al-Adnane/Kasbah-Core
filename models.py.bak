from pydantic import BaseModel, Field
from typing import Optional, Literal

DecisionState = Literal["allow", "requires_approval", "block"]

class Intent(BaseModel):
    agent: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    risk: int = Field(..., ge=0, le=100)

class Decision(BaseModel):
    id: str
    timestamp: str
    agent: str
    action: str
    risk: int
    decision: DecisionState
    reason: str
    stage: str = "rooting"
    approved: Optional[bool] = None
