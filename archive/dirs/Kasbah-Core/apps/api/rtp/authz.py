from __future__ import annotations

import json
import os
import time
import uuid
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
    except FileNotFoundError:
        return {"version": 1, "updated_at": _now(), "rules": []}
    except Exception:
        import logging as _logging
        _logging.error("authz: rules file corrupted — default deny in effect")
        # Fail-closed: return empty rules so DEFAULT_EFFECT (deny) applies
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
    ccl_level: Optional[int] = None,
    delegation_pre_verified: bool = False,
) -> AuthZResult:
    """
    Check authorization for principal/action/resource.

    New parameters (v1.1):
      ccl_level: assessed CCL risk level (0-5). Rules may set max_ccl ceiling.
      delegation_pre_verified: if True, delegation chain was already validated
        by authz_pipeline — skip re-validation here to avoid double-checking.
    """
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

    # Delegation chain validation (only when acting_as provided and not pre-verified)
    if acting_as and not delegation_pre_verified:
        try:
            from core.moats.delegation_chain import verify_delegation_chain
            dv = verify_delegation_chain(
                claimed_grantee_id=principal,
                claimed_grantor_id=acting_as,
                action=action,
                resource=resource,
            )
            if not dv.valid:
                return AuthZResult(False, f"delegation_invalid: {dv.reason}")
        except ImportError:
            pass  # delegation_chain module not available; fall through to rule check

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

        # Rule expiry check — use >= so rule expires exactly at expires_at, not 1s later
        r_expires = r.get("expires_at")
        if r_expires is not None:
            try:
                if _now() >= int(r_expires):
                    continue
            except (ValueError, TypeError):
                continue  # Malformed expires_at — skip rule

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

        # CCL ceiling check — max_ccl=0 means NO content is permitted (blocks all CCL including 0)
        r_max_ccl = r.get("max_ccl")
        if r_max_ccl is not None and ccl_level is not None:
            try:
                _r_max = int(r_max_ccl)
                _c_lvl = int(ccl_level)
                # max_ccl=0 blocks everything; otherwise block if ccl_level exceeds ceiling
                if _r_max == 0 or _c_lvl > _r_max:
                    return AuthZResult(
                        False,
                        f"ccl_ceiling_exceeded: action ccl={_c_lvl} > rule max_ccl={_r_max}",
                        matched_rule=r,
                    )
            except (ValueError, TypeError):
                return AuthZResult(False, "ccl_ceiling_invalid: malformed max_ccl value", matched_rule=r)

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
    expires_at: Optional[int] = None,
    max_ccl: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Grant an authorization rule.

    New parameters (v1.1):
      expires_at: epoch seconds after which this rule is ignored (None = no expiry).
      max_ccl: maximum CCL level this rule permits (0-5). Actions with higher CCL
               are denied even if the rule otherwise matches.
    """
    principal = _norm(principal) or "*"
    action = _norm(action).lower() or "*"
    resource = _norm(resource) or "*"
    effect = _norm(effect).lower() or "allow"
    acting_as = _norm(acting_as) or None

    obj = _load()
    rules: List[Dict[str, Any]] = obj.get("rules", [])

    if expires_at is not None and int(expires_at) < _now():
        raise ValueError("expires_at must be in the future")
    if max_ccl is not None and not (0 <= int(max_ccl) <= 5):
        raise ValueError("max_ccl must be between 0 and 5 inclusive")

    rule: Dict[str, Any] = {
        "id": str(uuid.uuid4()),  # collision-free regardless of creation rate
        "principal": principal,
        "action": action,
        "resource": resource,
        "acting_as": acting_as,
        "effect": effect,
        "note": note,
        "created_at": _now(),
    }
    if expires_at is not None:
        rule["expires_at"] = int(expires_at)
    if max_ccl is not None:
        rule["max_ccl"] = int(max_ccl)

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
