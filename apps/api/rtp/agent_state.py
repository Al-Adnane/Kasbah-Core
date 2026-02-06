"""
Agent state store (in-memory, process-local).

Exports required by other modules:
- get_state(agent_id)
- update_state(agent_id, updates)   # expected by kernel_gate
- set_state(agent_id, data)
- patch_state(agent_id, updates)
- reset_state(agent_id=None)

Deterministic, thread-safe, no persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from time import time
from typing import Any, Dict, Optional


@dataclass
class AgentState:
    agent_id: str
    created_at: float = field(default_factory=lambda: time())
    updated_at: float = field(default_factory=lambda: time())
    data: Dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.updated_at = time()


_lock = RLock()
_state_store: Dict[str, AgentState] = {}


def get_state(agent_id: str) -> AgentState:
    if not agent_id:
        agent_id = "anonymous"
    with _lock:
        st = _state_store.get(agent_id)
        if st is None:
            st = AgentState(agent_id=agent_id)
            _state_store[agent_id] = st
        return st


def set_state(agent_id: str, data: Dict[str, Any]) -> AgentState:
    with _lock:
        st = get_state(agent_id)
        st.data = dict(data or {})
        st.touch()
        return st


def patch_state(agent_id: str, updates: Dict[str, Any]) -> AgentState:
    with _lock:
        st = get_state(agent_id)
        st.data.update(dict(updates or {}))
        st.touch()
        return st


def update_state(agent_id: str, updates: Dict[str, Any]) -> AgentState:
    """
    Compatibility export expected by kernel_gate.
    Semantics: merge updates into existing state (same as patch_state).
    """
    return patch_state(agent_id, updates)


def reset_state(agent_id: Optional[str] = None) -> None:
    with _lock:
        if agent_id:
            _state_store.pop(agent_id, None)
        else:
            _state_store.clear()
