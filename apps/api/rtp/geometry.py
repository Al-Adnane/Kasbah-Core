"""
Geometry module.

Exports required by kernel_gate imports:
- geometry_score(signals) -> float in [0,1]
- geometry_threshold_for(tool_name, persona=None, default=0.75) -> float in [0,1]
- geometry_penalty(score, threshold) -> float in [0,1]

Meaning:
- "geometry_score" is a normalized integrity-like score derived from signals
- "threshold" is the minimum score needed to pass (may vary by tool/persona)
- "penalty" is how much to reduce allowance when below threshold

No external deps. Deterministic. Robust to missing keys.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def _clip01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def _getf(d: Dict[str, Any], *keys: str, default: float = 0.0) -> float:
    for k in keys:
        if k in d:
            try:
                return float(d[k])
            except Exception:
                return float(default)
    return float(default)


def geometry_score(signals: Optional[Dict[str, Any]]) -> float:
    """
    Compute a bounded score in [0,1] from signals.
    Uses common normalized keys if present:
      - consistency
      - pred_accuracy / accuracy
      - normality
      - latency_score
    """
    s = signals or {}
    c = _clip01(_getf(s, "consistency", default=0.0))
    a = _clip01(_getf(s, "pred_accuracy", "accuracy", default=0.0))
    n = _clip01(_getf(s, "normality", default=0.0))
    l = _clip01(_getf(s, "latency_score", "latency", default=1.0))
    # Weighted mean
    score = _clip01(0.35 * c + 0.30 * a + 0.25 * n + 0.10 * l)
    return score


def geometry_threshold_for(tool_name: str, persona: Optional[Any] = None, default: float = 0.75) -> float:
    """
    Return threshold in [0,1]. Tool-specific + persona strictness adjustment.
    Persona may be an object with `strictness` attribute in [0,1].
    """
    base = float(default)

    # Tool-specific tightening (keep conservative but not insane)
    t = (tool_name or "").lower()
    if any(x in t for x in ("shell", "exec", "write", "delete", "rm", "sudo")):
        base = max(base, 0.85)
    elif any(x in t for x in ("read", "me", "get", "list", "status")):
        base = max(base, 0.70)

    # Persona strictness bumps threshold slightly
    strictness = None
    if persona is not None:
        strictness = getattr(persona, "strictness", None)
    if strictness is not None:
        try:
            base = base + 0.10 * (float(strictness) - 0.5)
        except Exception:
            pass

    return _clip01(base)


def geometry_penalty(score: float, threshold: float) -> float:
    """
    Penalty in [0,1] applied when score < threshold.
    0 means no penalty; 1 means maximum penalty.
    """
    s = _clip01(float(score))
    th = _clip01(float(threshold))
    if s >= th:
        return 0.0
    # Linear penalty scaled by how far below threshold we are
    gap = (th - s) / (th if th > 0 else 1.0)
    return _clip01(gap)
