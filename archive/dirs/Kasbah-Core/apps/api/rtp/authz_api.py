from __future__ import annotations

import hmac
import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, validator

from .authz import check_access, grant_rule, revoke_rule, list_rules

# Pipeline + new modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "core", "moats"))
from agent_identity import issue_credential, revoke_credential, list_credentials
from delegation_chain import grant_delegation, revoke_delegation, list_delegations
from spend_ledger import set_spend_policy, get_spend_summary
from authz_pipeline import authorize, AuthZPipelineRequest


router = APIRouter(prefix="/api/authz", tags=["authz"])

ADMIN_KEY = os.environ.get("KASBAH_ADMIN_KEY", "dev-master-key")

_MAX_CCL_TEXT = 32_768   # 32 KB cap on CCL text input
_MAX_CATEGORIES = 50     # max number of CCL category strings


def _is_admin(authz: Optional[str]) -> bool:
    """Constant-time admin key comparison to prevent timing attacks."""
    if not authz:
        return False
    v = authz.strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    # Always compare against the full key — constant time regardless of match
    return hmac.compare_digest(v, ADMIN_KEY)


# ── Existing models (unchanged) ───────────────────────────────────────────────

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
    expires_at: Optional[int] = None
    max_ccl: Optional[int] = None


class RevokeReq(BaseModel):
    rule_id: str


# ── New models ────────────────────────────────────────────────────────────────

class CredentialIssueReq(BaseModel):
    agent_id: str
    ttl_seconds: Optional[int] = None
    parent_agent_id: Optional[str] = None
    max_delegation_depth: int = 3


class CredentialRevokeReq(BaseModel):
    agent_id: str


class DelegateReq(BaseModel):
    grantor_id: str
    grantor_secret: str
    grantee_id: str
    action_scope: str
    resource_scope: str
    ttl_seconds: int = 3600
    parent_token_id: Optional[str] = None


class DelegateRevokeReq(BaseModel):
    token_id: str


class BudgetSetReq(BaseModel):
    principal: str
    max_tokens_per_minute: int = 100_000
    max_tokens_per_day: int = 5_000_000
    max_cost_cents_per_day: int = 5000
    max_cost_cents_total: Optional[int] = None
    hard_block_on_exceed: bool = True

    @validator("max_tokens_per_minute", "max_tokens_per_day", "max_cost_cents_per_day")
    def must_be_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("policy limits must be non-negative")
        return v

    @validator("max_cost_cents_total")
    def total_must_be_non_negative(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 0:
            raise ValueError("max_cost_cents_total must be non-negative")
        return v


class PipelineCheckReq(BaseModel):
    principal: str
    action: str
    resource: str
    acting_as: Optional[str] = None
    agent_secret: Optional[str] = None
    ccl_text: Optional[str] = None
    ccl_score: int = 0
    ccl_categories: List[str] = []
    estimated_tokens: int = 0
    estimated_cost_cents: int = 0
    require_ticket: bool = False
    tenant_id: str = "default"

    @validator("estimated_tokens", "estimated_cost_cents", "ccl_score")
    def must_be_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be non-negative")
        return v

    @validator("ccl_text")
    def ccl_text_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > _MAX_CCL_TEXT:
            raise ValueError(f"ccl_text exceeds maximum length of {_MAX_CCL_TEXT}")
        return v

    @validator("ccl_categories")
    def ccl_categories_limit(cls, v: List[str]) -> List[str]:
        if len(v) > _MAX_CATEGORIES:
            raise ValueError(f"ccl_categories exceeds maximum of {_MAX_CATEGORIES} items")
        return v


# ── Existing endpoints (unchanged) ────────────────────────────────────────────

@router.post("/check")
def authz_check(req: CheckReq) -> Dict[str, Any]:
    try:
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
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="authz check failed")


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
        expires_at=req.expires_at,
        max_ccl=req.max_ccl,
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


# ── New endpoints ─────────────────────────────────────────────────────────────

@router.post("/credential/issue")
def credential_issue(
    req: CredentialIssueReq,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Issue a new agent credential. Returns secret ONCE — store it securely."""
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    try:
        cred, raw_secret = issue_credential(
            agent_id=req.agent_id,
            ttl_seconds=req.ttl_seconds,
            parent_agent_id=req.parent_agent_id,
            max_delegation_depth=req.max_delegation_depth,
        )
        return {
            "ok": True,
            "agent_id": cred.agent_id,
            "credential_id": cred.credential_id,
            "secret": raw_secret,   # shown once
            "expires_at": cred.expires_at,
            "max_delegation_depth": cred.max_delegation_depth,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/credential/revoke")
def credential_revoke(
    req: CredentialRevokeReq,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    ok = revoke_credential(req.agent_id)
    return {"ok": ok}


@router.get("/credential/list")
def credential_list(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    return {"credentials": list_credentials()}


@router.post("/delegate")
def delegate(req: DelegateReq) -> Dict[str, Any]:
    """
    Grant a delegation token. Grantor must provide their secret for verification.
    No admin key needed — the grantor's credential is the proof of authorization.
    """
    try:
        token = grant_delegation(
            grantor_id=req.grantor_id,
            grantor_secret=req.grantor_secret,
            grantee_id=req.grantee_id,
            action_scope=req.action_scope,
            resource_scope=req.resource_scope,
            ttl_seconds=req.ttl_seconds,
            parent_token_id=req.parent_token_id,
        )
        return {
            "ok": True,
            "token_id": token.token_id,
            "grantor_id": token.grantor_id,
            "grantee_id": token.grantee_id,
            "action_scope": token.action_scope,
            "resource_scope": token.resource_scope,
            "expires_at": token.expires_at,
            "depth": token.depth,
        }
    except ValueError as e:
        # Sanitize error message — never echo grantor_secret back in responses
        msg = str(e)
        if req.grantor_secret and req.grantor_secret in msg:
            msg = msg.replace(req.grantor_secret, "***")
        raise HTTPException(status_code=400, detail=msg)
    except Exception:
        raise HTTPException(status_code=500, detail="delegation failed")


@router.post("/delegate/revoke")
def delegate_revoke(
    req: DelegateRevokeReq,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    ok = revoke_delegation(req.token_id)
    return {"ok": ok}


@router.post("/budget/set")
def budget_set(
    req: BudgetSetReq,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    policy = set_spend_policy(
        principal=req.principal,
        max_tokens_per_minute=req.max_tokens_per_minute,
        max_tokens_per_day=req.max_tokens_per_day,
        max_cost_cents_per_day=req.max_cost_cents_per_day,
        max_cost_cents_total=req.max_cost_cents_total,
        hard_block_on_exceed=req.hard_block_on_exceed,
    )
    return {"ok": True, "policy": {
        "principal": policy.principal,
        "max_tokens_per_minute": policy.max_tokens_per_minute,
        "max_tokens_per_day": policy.max_tokens_per_day,
        "max_cost_cents_per_day": policy.max_cost_cents_per_day,
        "max_cost_cents_total": policy.max_cost_cents_total,
        "hard_block_on_exceed": policy.hard_block_on_exceed,
    }}


@router.get("/budget/{principal}")
def budget_summary(
    principal: str,
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not _is_admin(authorization):
        raise HTTPException(status_code=403, detail="admin required")
    return get_spend_summary(principal)


@router.post("/pipeline/check")
def pipeline_check(req: PipelineCheckReq) -> Dict[str, Any]:
    """
    Full 7-stage authorization pipeline.
    Preferred endpoint for agent authorization decisions.
    """
    try:
        result = authorize(AuthZPipelineRequest(
            principal=req.principal,
            action=req.action,
            resource=req.resource,
            acting_as=req.acting_as,
            agent_secret=req.agent_secret,
            ccl_text=req.ccl_text,
            ccl_score=req.ccl_score,
            ccl_categories=req.ccl_categories,
            estimated_tokens=req.estimated_tokens,
            estimated_cost_cents=req.estimated_cost_cents,
            require_ticket=req.require_ticket,
            tenant_id=req.tenant_id,
        ))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="pipeline authorization failed")

    response: Dict[str, Any] = {
        "allow": result.allow,
        "reason": result.reason,
        "stage_failed": result.stage_failed,
        "ccl_level": result.ccl_level,
        "audit_entry_id": result.audit_entry_id,
        "budget_remaining": result.budget_remaining,
        "delegation_chain": result.delegation_chain,
    }
    if result.ticket:
        from dataclasses import asdict
        response["ticket"] = asdict(result.ticket)
    return response
