from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_cors import CORS

# Enable CORS for all routes
CORS(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute", "1000 per hour"],
    storage_uri="memory://",
)
def rtp_verify(ticket):
    """
    Public verifier entrypoint (demo-safe).
    Always routes through KernelEnforcer.intercept_execution so usage/signals are enforced.
    """
    from apps.api.main import _rtp_enforcer
    from apps.api.rtp.kernel_gate import ExecutionTicket

    usage_signals = ticket.get("signals") or {}
    usage_agent_id = ticket.get("agent_id") or ticket.get("session_id") or "anon"
    usage = {"tokens": 0, "cost": 0, "signals": usage_signals, "agent_id": usage_agent_id}

    et = ExecutionTicket(
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

    _rtp_enforcer.store_ticket(et)
    res = _rtp_enforcer.intercept_execution(et.tool_name, et.jti, usage)

    if hasattr(res, "valid"):
        return {
            "ok": bool(res.valid),
            "reason": getattr(res, "reason", "unknown"),
            "remaining_budget": getattr(res, "remaining_budget", None),
            "_verifier": "_rtp_enforcer.intercept_execution",
        }
    return res
