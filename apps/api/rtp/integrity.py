"""
Integrity signals module.

Exports required by kernel_gate imports:
- GeometricIntegrityCalculator
- BidirectionalFeedbackLoop

Design goals:
- Deterministic, bounded scoring in [0, 1]
- Robust to missing / malformed signals
- No external dependencies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time
from typing import Any, Dict, Optional


def _clip01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def _getf(d: Dict[str, Any], *keys: str, default: float = 0.0) -> float:
    """
    Get first existing numeric value from keys in dict.
    Non-numeric values become default.
    """
    for k in keys:
        if k in d:
            try:
                return float(d[k])
            except Exception:
                return float(default)
    return float(default)


@dataclass
class GeometricIntegrityCalculator:
    """
    Computes an integrity score from signals.

    Expected signal keys (any subset is fine):
    - consistency
    - pred_accuracy / accuracy
    - normality
    - latency_score

    Higher is better for all except: none (we assume all already normalized).
    """
    weights: Dict[str, float] = field(default_factory=lambda: {
        "consistency": 0.35,
        "pred_accuracy": 0.30,
        "normality": 0.25,
        "latency_score": 0.10,
    })

    def score(self, signals: Optional[Dict[str, Any]]) -> float:
        s = signals or {}
        c = _clip01(_getf(s, "consistency", default=0.0))
        a = _clip01(_getf(s, "pred_accuracy", "accuracy", default=0.0))
        n = _clip01(_getf(s, "normality", default=0.0))
        l = _clip01(_getf(s, "latency_score", "latency", default=1.0))

        w = self.weights
        denom = (w.get("consistency", 0) + w.get("pred_accuracy", 0) +
                 w.get("normality", 0) + w.get("latency_score", 0)) or 1.0

        val = (
            w.get("consistency", 0) * c +
            w.get("pred_accuracy", 0) * a +
            w.get("normality", 0) * n +
            w.get("latency_score", 0) * l
        ) / denom

        return _clip01(val)

    def details(self, signals: Optional[Dict[str, Any]]) -> Dict[str, float]:
        s = signals or {}
        return {
            "consistency": _clip01(_getf(s, "consistency", default=0.0)),
            "pred_accuracy": _clip01(_getf(s, "pred_accuracy", "accuracy", default=0.0)),
            "normality": _clip01(_getf(s, "normality", default=0.0)),
            "latency_score": _clip01(_getf(s, "latency_score", "latency", default=1.0)),
        }


@dataclass
class BidirectionalFeedbackLoop:
    """
    Minimal feedback loop placeholder:
    - Ingests outcomes
    - Maintains a rolling trust scalar per agent/tool if you choose to plug it later

    For now: stable, no-op bias correction with bounded multipliers.
    """
    decay: float = 0.98
    floor: float = 0.50
    ceil: float = 1.10

    _memory: Dict[str, Dict[str, float]] = field(default_factory=dict)
    _last: float = field(default_factory=lambda: time())

    def _key(self, agent_id: str, tool_name: str) -> str:
        return f"{agent_id or 'anonymous'}::{tool_name or '*'}"

    def update(self, agent_id: str, tool_name: str, success: bool) -> None:
        k = self._key(agent_id, tool_name)
        mem = self._memory.setdefault(k, {"m": 1.0})
        m = float(mem.get("m", 1.0))
        # gentle reinforcement / penalty
        if success:
            m = min(self.ceil, m * 1.01)
        else:
            m = max(self.floor, m * 0.99)
        mem["m"] = m
        self._last = time()

    def multiplier(self, agent_id: str, tool_name: str) -> float:
        k = self._key(agent_id, tool_name)
        mem = self._memory.get(k)
        if not mem:
            return 1.0
        return _clip01(float(mem.get("m", 1.0))) if self.ceil <= 1.0 else float(mem.get("m", 1.0))
