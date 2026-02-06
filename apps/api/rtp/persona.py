"""
Persona selection module.

Exports required by kernel_gate imports:
- persona_for

Purpose:
- Provide deterministic persona resolution for an agent/tool request.
- Keep it simple: no external deps, no magic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Persona:
    name: str
    # policy bias in [0,1]: higher => stricter gating (more deny)
    strictness: float = 0.5


# Safe defaults
_PERSONAS: Dict[str, Persona] = {
    "default": Persona("default", strictness=0.50),
    "demo": Persona("demo", strictness=0.35),
    "stress": Persona("stress", strictness=0.70),
    "lockdown": Persona("lockdown", strictness=0.85),
}


def persona_for(agent_id: Optional[str] = None, tool_name: Optional[str] = None, signals: Optional[Dict[str, Any]] = None) -> Persona:
    """
    Resolve persona from explicit signals or agent_id naming conventions.

    Priority:
    1) signals["persona"] if present and known
    2) agent_id hints ("stress", "demo", "lockdown")
    3) default
    """
    s = signals or {}
    p = s.get("persona")
    if isinstance(p, str) and p.lower() in _PERSONAS:
        return _PERSONAS[p.lower()]

    aid = (agent_id or "").lower()
    if "lock" in aid:
        return _PERSONAS["lockdown"]
    if "stress" in aid:
        return _PERSONAS["stress"]
    if "demo" in aid or "smoke" in aid:
        return _PERSONAS["demo"]

    return _PERSONAS["default"]
