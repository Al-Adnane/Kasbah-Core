from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .authz import check_access, grant_rule, revoke_rule, list_rules


router = APIRouter(prefix="/api/authz", tags=["authz"])

ADMIN_KEY = os.environ.get("KASBAH_ADMIN_KEY", "dev-master-key")


def _is_admin(authz: Optional[str]) -> bool:
    if not authz:
        return False
    # accept: "Bearer <key>" or raw key
    v = authz.strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    return v == ADMIN_KEY


class CheckReq(BaseModel):
    principal: str
    action: str
    resource: str
    acting_as: Optional[str] = None


class GrantReq(BaseModel):
    principal: str
    action: str
    resource: str
    effect: str = "allow"
    acting_as: Optional[str] = None
    note: str = ""


class RevokeReq(BaseModel):
    rule_id: str


@router.post("/check")
def authz_check(req: CheckReq) -> Dict[str, Any]:
    az = check_access(
        principal=req.principal,
        action=req.action,
        resource=req.resource,
        acting_as=req.acting_as,
    )
    return {
        "allow": az.allow,
        "reason": az.reason,
        "matched_rule": az.matched_rule,
    }


@router.post("/grant")
def authz_grant(req: GrantReq, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    rule = grant_rule(
        principal=req.principal,
        action=req.action,
        resource=req.resource,
        effect=req.effect,
        acting_as=req.acting_as,
        note=req.note,
    )
    return {"ok": True, "rule": rule}


@router.post("/revoke")
def authz_revoke(req: RevokeReq, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    ok = revoke_rule(req.rule_id)
    return {"ok": ok}


@router.get("/list")
def authz_list(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    return {"rules": list_rules()}
