"""
Thin adapter exposing the real Kasbah RTP kernel as a callable decide_fn.

This file MUST stay small.
No logic. No policy. No adapters.
"""

from typing import Dict, Any

# Import your existing kernel entrypoint
# Adjust import if needed, but do NOT refactor kernel code.
try:
    from apps.api.main import _rtp_gate
except Exception:
    # fallback for alternate layouts
    from kasbah_main import _rtp_gate  # type: ignore


def kernel_decide(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonical kernel decision function.

    Input:
      {
        actor_id,
        action,
        signals,
        context
      }

    Output:
      kernel decision dict (opaque to adapters)
    """
    actor_id = req.get("actor_id")
    action = req.get("action")
    signals = req.get("signals", {})

    # delegate fully to RTP kernel
    res = _rtp_gate.decide(
        tool_name=action,
        agent_id=actor_id,
        signals=signals,
    )

    # kernel output is authoritative; return as-is
    return res
