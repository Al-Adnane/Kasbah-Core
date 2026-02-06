from pydantic import BaseModel, Field, validator, confloat, conint
from typing import Dict, Any, Optional, List
import re

class DecideRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=100)
    signals: Dict[str, confloat(ge=0.0, le=1.0)] = Field(default_factory=dict)
    usage: Optional[Dict[str, Any]] = Field(default_factory=dict)
    ttl: conint(ge=1, le=3600) = Field(default=300)
    agent_id: Optional[str] = Field(None, min_length=1, max_length=100)
    
    @validator('tool_name')
    def validate_tool_name(cls, v):
        if re.search(r'[./\\]', v):
            raise ValueError('Tool name cannot contain path characters')
        if len(v) > 100:
            raise ValueError('Tool name too long')
        return v
    
    @validator('signals')
    def validate_signals(cls, v):
        if not isinstance(v, dict):
            raise ValueError('Signals must be a dictionary')
        
        for key, value in v.items():
            if not isinstance(value, (int, float)):
                raise ValueError(f'Signal {key} must be numeric')
            if not 0 <= value <= 1:
                raise ValueError(f'Signal {key} must be between 0 and 1')
        
        return v
    
    class Config:
        extra = 'forbid'

class ConsumeRequest(BaseModel):
    ticket_id: str = Field(..., min_length=20, max_length=100)
    tool_name: str = Field(..., min_length=1, max_length=100)
    agent_id: Optional[str] = Field(None)
    
    @validator('ticket_id')
    def validate_ticket_id(cls, v):
        if not v.startswith('kasbah_tkt_'):
            raise ValueError('Invalid ticket format')
        return v
