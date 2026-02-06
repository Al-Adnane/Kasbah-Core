from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

@dataclass
class Operator:
    operator_id: str
    role: str = "viewer"

def lookup_operator(api_key: Optional[str]) -> Optional[Operator]:
    return None

def min_role_for_path(path: str, method: str = "GET") -> str:
    return "viewer"

def role_allows(role: str, required: str) -> bool:
    order = {"viewer": 0, "operator": 1, "admin": 2}
    return order.get(role, -1) >= order.get(required, 999)
