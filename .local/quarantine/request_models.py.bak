from pydantic import BaseModel, Field, validator, ConfigDict
from typing import Dict, Any, Optional, List
from datetime import datetime

class BaseRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')  # Reject extra fields

class DecideRequest(BaseRequest):
    tool_name: str = Field(..., min_length=1, max_length=100, description="Name of the tool being requested")
    signals: Dict[str, float] = Field(default_factory=dict, description="Security signals for decision making")
    usage: Dict[str, Any] = Field(default_factory=dict, description="Usage context and metadata")
    ttl: Optional[int] = Field(default=300, ge=1, le=3600, description="Time-to-live in seconds")
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=100, description="ID of the requesting agent")
    
    @validator('signals')
    def validate_signals(cls, v):
        for key, val in v.items():
            if not isinstance(val, (int, float)):
                raise ValueError(f"Signal '{key}' must be numeric, got {type(val)}")
            if not (0.0 <= val <= 1.0):
                raise ValueError(f"Signal '{key}' must be between 0 and 1, got {val}")
        return v
    
    @validator('tool_name')
    def validate_tool_name(cls, v):
        # Prevent path traversal in tool names
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError(f"Invalid tool name: {v}")
        return v

class ConsumeRequest(BaseRequest):
    ticket_id: str = Field(..., min_length=10, max_length=256, description="Ticket ID to consume")
    tool_name: str = Field(..., min_length=1, max_length=100, description="Expected tool name for validation")
    agent_id: Optional[str] = Field(default=None, description="ID of the consuming agent")
    
    @validator('ticket_id')
    def validate_ticket_id(cls, v):
        # Basic ticket ID validation
        if not v.startswith('kasbah_tkt_'):
            raise ValueError("Invalid ticket ID format")
        return v

class OperatorKeyRequest(BaseRequest):
    operator_id: str = Field(..., min_length=1, max_length=50, description="Operator ID")
    ttl_days: Optional[int] = Field(default=90, ge=1, le=365, description="Key validity in days")
    description: Optional[str] = Field(default="", max_length=200, description="Key description")

class AgentConfig(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=100)
    allowed_tools: List[str] = Field(default_factory=list, description="Tools this agent can use")
    rate_limit: Optional[int] = Field(default=1000, ge=1, description="Requests per minute")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
