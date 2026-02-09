from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


DATA_DIR = os.environ.get("KASBAH_DATA_DIR", ".kasbah")
AUTHZ_PATH = os.path.join(DATA_DIR, "authz.json")

# Default safe posture: deny unless explicitly allowed
DEFAULT_EFFECT = os.environ.get("KASBAH_AUTHZ_DEFAULT", "deny").strip().lower()


def _now() -> int:
    return int(time.time())


def _ensure_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def _load() -> Dict[str, Any]:
    _ensure_dir()
    if not os.path.exists(AUTHZ_PATH):
        return {"version": 1, "updated_at": _now(), "rules": []}
    try:
        with open(AUTHZ_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f) or {}
        if "rules" not in obj or not isinstance(obj["rules"], list):
            obj["rules"] = []
        if "version" not in obj:
            obj["version"] = 1
        return obj
    except Exception:
        return {"version": 1, "updated_at": _now(), "rules": []}


def _save(obj: Dict[str, Any]) -> None:
    _ensure_dir()
    obj["updated_at"] = _now()
    tmp = AUTHZ_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, AUTHZ_PATH)


def _norm(s: Optional[str]) -> str:
    return (s or "").strip()


def _match(pattern: str, value: str) -> bool:
    # Very small matcher: exact or wildcard "*"
    if pattern == "*":
        return True
    return pattern == value


@dataclass
class AuthZResult:
    allow: bool
    reason: str
    matched_rule: Optional[Dict[str, Any]] = None


def check_access(
    principal: str,
    action: str,
    resource: str,
    acting_as: Optional[str] = None,
) -> AuthZResult:
    principal = _norm(principal)
    action = _norm(action).lower()
    resource = _norm(resource)
    acting_as = _norm(acting_as) or None

    if not principal:
        return AuthZResult(False, "missing principal")
    if not action:
        return AuthZResult(False, "missing action")
    if not resource:
        return AuthZResult(False, "missing resource")

    obj = _load()
    rules: List[Dict[str, Any]] = obj.get("rules", [])

    # Most specific first: exact matches beat wildcards
    def score(r: Dict[str, Any]) -> int:
        sc = 0
        sc += 10 if r.get("principal") not in ("*", None) else 0
        sc += 10 if r.get("action") not in ("*", None) else 0
        sc += 10 if r.get("resource") not in ("*", None) else 0
        sc += 5 if r.get("acting_as") not in ("*", None, "") else 0
        return sc

    rules_sorted = sorted(rules, key=score, reverse=True)

    for r in rules_sorted:
        rp = _norm(r.get("principal"))
        ra = _norm(r.get("action")).lower()
        rr = _norm(r.get("resource"))
        ras = _norm(r.get("acting_as")) or None

        if not _match(rp or "*", principal):
            continue
        if not _match(ra or "*", action):
            continue
        if not _match(rr or "*", resource):
            continue

        # acting_as: if rule specifies it, must match
        if ras and acting_as is not None and not _match(ras, acting_as):
            continue
        if ras and acting_as is None and ras != "*":
            continue

        eff = _norm(r.get("effect")).lower() or "deny"
        if eff == "allow":
            return AuthZResult(True, "allowed by rule", matched_rule=r)
        return AuthZResult(False, "denied by rule", matched_rule=r)

    if DEFAULT_EFFECT == "allow":
        return AuthZResult(True, "allowed by default")
    return AuthZResult(False, "no matching allow rule (default deny)")


def grant_rule(
    principal: str,
    action: str,
    resource: str,
    effect: str = "allow",
    acting_as: Optional[str] = None,
    note: str = "",
) -> Dict[str, Any]:
    principal = _norm(principal) or "*"
    action = _norm(action).lower() or "*"
    resource = _norm(resource) or "*"
    effect = _norm(effect).lower() or "allow"
    acting_as = _norm(acting_as) or None

    obj = _load()
    rules: List[Dict[str, Any]] = obj.get("rules", [])

    rule = {
        "id": f"r{_now()}{len(rules)+1}",
        "principal": principal,
        "action": action,
        "resource": resource,
        "acting_as": acting_as,
        "effect": effect,
        "note": note,
        "created_at": _now(),
    }
    rules.append(rule)
    obj["rules"] = rules
    _save(obj)
    return rule


def revoke_rule(rule_id: str) -> bool:
    rule_id = _norm(rule_id)
    if not rule_id:
        return False
    obj = _load()
    rules: List[Dict[str, Any]] = obj.get("rules", [])
    before = len(rules)
    rules = [r for r in rules if _norm(r.get("id")) != rule_id]
    obj["rules"] = rules
    _save(obj)
    return len(rules) != before


def list_rules() -> List[Dict[str, Any]]:
    obj = _load()
    rules: List[Dict[str, Any]] = obj.get("rules", [])
    return rules
