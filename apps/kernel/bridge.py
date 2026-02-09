from __future__ import annotations

from typing import Any, Dict, Optional, Callable
from apps.adapters.loader import load_adapter
from apps.kernel.contracts import normalize_decision_response

# Kernel decision function signature:
# decide_fn(req: dict) -> dict
# This bridge is intentionally lightweight and does not embed business logic.

def run_governed_action(
    *,
    adapter_id: str,
    raw_event: Dict[str, Any],
    decide_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
    enforce: bool = True,
) -> Dict[str, Any]:
    """
    Bridge flow:
      raw_event -> adapter.build_decision_request -> kernel decide -> (optional) adapter.enforce_decision

    - Adapters DO NOT override kernel decision.
    - Kernel output is treated as authoritative.
    """
    adapter = load_adapter(adapter_id)

    req = adapter.build_decision_request(raw_event)
    if not isinstance(req, dict):
        raise TypeError("adapter.build_decision_request must return dict")

    decision = normalize_decision_response(decide_fn(req))

    outcome: Optional[Dict[str, Any]] = None
    if enforce:
        # enforcement is downstream; still cannot change kernel decision
        outcome = adapter.enforce_decision(decision, raw_event)
        if outcome is None:
            outcome = {}

    # report outcome (best-effort, non-fatal)
    try:
        _fb = adapter.report_outcome(outcome or {})
    except Exception:
        _fb = None

    return {
        "adapter_id": adapter_id,
        "request": req,
        "decision": decision,
        "outcome": outcome,
        "feedback": _fb,
    }
