"""
Signals processing module.

Exports required by kernel_gate imports:
- SignalTracker
- QIFTProcessor (must provide .transform() for legacy callers)
- HyperGraphAnalyzer

Deterministic, no external deps, robust to missing inputs.
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
    for k in keys:
        if k in d:
            try:
                return float(d[k])
            except Exception:
                return float(default)
    return float(default)


@dataclass
class SignalTracker:
    _last: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def key(self, agent_id: str, tool_name: str) -> str:
        return f"{agent_id or 'anonymous'}::{tool_name or '*'}"

    def update(self, agent_id: str, tool_name: str, signals: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        k = self.key(agent_id, tool_name)
        s = dict(signals or {})
        s["_ts"] = time()
        self._last[k] = s
        return s

    def last(self, agent_id: str, tool_name: str) -> Dict[str, Any]:
        return dict(self._last.get(self.key(agent_id, tool_name), {}))


@dataclass
class QIFTProcessor:
    """
    Minimal processor that normalizes raw signals.

    IMPORTANT: legacy callers expect `.transform(signals)`.
    We provide `.transform()` as an alias to `.process()`.
    """

    def process(self, signals: Optional[Dict[str, Any]]) -> Dict[str, float]:
        s = signals or {}
        out = {
            "consistency": _clip01(_getf(s, "consistency", default=0.0)),
            "pred_accuracy": _clip01(_getf(s, "pred_accuracy", "accuracy", default=0.0)),
            "normality": _clip01(_getf(s, "normality", default=0.0)),
            "latency_score": _clip01(_getf(s, "latency_score", "latency", default=1.0)),
        }
        out["threat"] = _clip01(1.0 - out["normality"])
        return out

    def transform(self, signals: Optional[Dict[str, Any]]) -> Dict[str, float]:
        return self.process(signals)


@dataclass
class HyperGraphAnalyzer:
    def risk(self, features: Dict[str, float]) -> float:
        c = _clip01(features.get("consistency", 0.0))
        a = _clip01(features.get("pred_accuracy", 0.0))
        t = _clip01(features.get("threat", 0.0))
        return _clip01(0.50 * t + 0.25 * (1.0 - c) + 0.25 * (1.0 - a))
