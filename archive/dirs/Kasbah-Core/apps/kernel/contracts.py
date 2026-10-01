from typing import Dict, Any, Literal, Optional

Decision = Literal["ALLOW", "DENY", "ESCALATE"]
KernelState = Literal["NORMAL", "WATCH", "LOCKDOWN"]

KernelDecisionRequest = Dict[str, Any]
KernelDecisionResponse = Dict[str, Any]

def normalize_decision_response(res: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal sanity normalization; keep kernel output opaque beyond basics.
    out = dict(res or {})
    if "decision" not in out:
        out["decision"] = "DENY"
    if "kernel_state" not in out:
        out["kernel_state"] = "NORMAL"
    if "risk_score" not in out:
        out["risk_score"] = 1.0
    if "threshold" not in out:
        out["threshold"] = 0.0
    return out
