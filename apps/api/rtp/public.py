from typing import Any, Dict

def _ensure_dict(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        return result
    if hasattr(result, "__dict__"):
        return dict(result.__dict__)
    return {"ok": False, "reason": "invalid_verifier_return", "detail": repr(result)}

def rtp_verify(ticket: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stable public entrypoint for verifying/consuming RTP tickets.

    Canonical path:
      KernelEnforcer.store_ticket + KernelEnforcer.intercept_execution
    """
    from apps.api.main import _rtp_enforcer
    from apps.api.rtp.kernel_gate import ExecutionTicket

    # 1) If a direct verifier exists, use it
    for name in ("verify", "verify_ticket", "verify_and_consume", "consume", "consume_ticket", "enforce", "check"):
        fn = getattr(_rtp_enforcer, name, None)
        if callable(fn):
            out = _ensure_dict(fn(ticket))
            out["_verifier"] = "_rtp_enforcer.%s" % name
            return out

    # 2) Canonical path: store + intercept
    t = ExecutionTicket(
        jti=ticket.get("jti"),
        tool_name=ticket.get("tool_name") or ticket.get("tool"),
        args=ticket.get("args") or {},
        timestamp=int(ticket.get("timestamp") or ticket.get("timestamp_ns") or 0),
        issued_mono_ns=int(ticket.get("issued_mono_ns") or 0),
        ttl=int(ticket.get("ttl") or ticket.get("ttl_ns") or 0),
        binary_hash=ticket.get("binary_hash") or "",
        signature=ticket.get("signature") or "",
        resource_limits=ticket.get("resource_limits") or {},
    )

    _rtp_enforcer.store_ticket(t)
        usage_signals = ticket.get("signals") or {}
    usage_agent_id = ticket.get("agent_id") or ticket.get("session_id") or "anon"
    usage = {"tokens": 0, "cost": 0, "signals": usage_signals, "agent_id": usage_agent_id}
    res = _rtp_enforcer.intercept_execution(t.tool_name, t.jti, usage)

    if hasattr(res, "valid"):
        return {
            "ok": bool(res.valid),
            "reason": getattr(res, "reason", "unknown"),
            "remaining_budget": getattr(res, "remaining_budget", None),
            "_verifier": "_rtp_enforcer.intercept_execution",
        }

    out = _ensure_dict(res)
    out["_verifier"] = "_rtp_enforcer.intercept_execution"
    return out
