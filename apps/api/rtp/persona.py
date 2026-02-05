from dataclasses import dataclass
from typing import Dict

@dataclass(frozen=True)
class Persona:
    name: str
    integrity_bias: float = 0.0     # subtracts from threshold if positive
    confidence_floor: float = 0.5   # minimum prediction_confidence
    lockdown_cap: float = 1.0       # caps threshold for harmless tools

PERSONAS: Dict[str, Persona] = {
    "smoke": Persona("smoke", integrity_bias=0.0, confidence_floor=0.5, lockdown_cap=0.50),
    "replay-test": Persona("replay-test", integrity_bias=0.0, confidence_floor=0.5, lockdown_cap=0.50),
    "trusted": Persona("trusted", integrity_bias=0.10, confidence_floor=0.5, lockdown_cap=0.55),
    "untrusted": Persona("untrusted", integrity_bias=-0.05, confidence_floor=0.7, lockdown_cap=1.0),
}

def persona_for(agent_id: str) -> Persona:
    aid = (agent_id or "anonymous").strip()
    return PERSONAS.get(aid, Persona("default"))
