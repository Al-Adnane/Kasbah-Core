"""
Policy module.

Exports required by kernel_gate imports:
- MoEHorizonFusion
- ThermodynamicProtocol

Goal:
- Deterministic, bounded gating decisions
- No external deps
- Safe defaults: deny when uncertain, allow only when signals are strong

This module does NOT claim MoE or thermodynamics; the names are kept
only because other code imports them.
"""

from __future__ import annotations

from dataclasses import dataclass
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
class ThermodynamicProtocol:
    """
    Converts features into a 'stability' scalar in [0,1].
    Higher stability => more likely to allow execution.

    Uses simple energy metaphor:
    - higher threat increases "entropy" (bad)
    - higher consistency & accuracy reduce entropy (good)
    """
    threat_weight: float = 0.50
    consistency_weight: float = 0.25
    accuracy_weight: float = 0.25

    def stability(self, features: Dict[str, Any]) -> float:
        threat = _clip01(_getf(features, "threat", default=0.0))
        consistency = _clip01(_getf(features, "consistency", default=0.0))
        acc = _clip01(_getf(features, "pred_accuracy", "accuracy", default=0.0))

        entropy = _clip01(
            self.threat_weight * threat
            + self.consistency_weight * (1.0 - consistency)
            + self.accuracy_weight * (1.0 - acc)
        )
        # stability is inverse of entropy
        return _clip01(1.0 - entropy)


@dataclass
class MoEHorizonFusion:
    """
    Fuses multiple "horizons" of signals into a final decision score.

    Inputs (expected but optional):
    - features: processed/normalized signal dict
    - risk: float in [0,1] higher is worse
    - system_stable: bool
    - policy_mode: 'allow'/'deny'/'human_approval' (optional)

    Output:
    - score in [0,1] where higher is better for allowing execution.
    """
    min_score_allow: float = 0.75

    def score(
        self,
        features: Optional[Dict[str, Any]] = None,
        risk: Optional[float] = None,
        system_stable: bool = True,
        policy_mode: str = "deny",
    ) -> float:
        f = features or {}
        r = _clip01(float(risk)) if risk is not None else _clip01(_getf(f, "risk", default=0.0))

        # Base from integrity-like signals
        consistency = _clip01(_getf(f, "consistency", default=0.0))
        acc = _clip01(_getf(f, "pred_accuracy", "accuracy", default=0.0))
        normality = _clip01(_getf(f, "normality", default=0.0))
        latency = _clip01(_getf(f, "latency_score", "latency", default=1.0))

        base = _clip01(0.35 * consistency + 0.30 * acc + 0.25 * normality + 0.10 * latency)

        # Penalize by risk
        base = _clip01(base * (1.0 - 0.60 * r))

        # Hard penalty if system is unstable
        if not system_stable:
            base = _clip01(base * 0.50)

        # Respect explicit policy modes conservatively
        pm = (policy_mode or "deny").lower()
        if pm == "allow":
            return _clip01(max(base, 0.80))  # allow mode biases upward but still bounded
        if pm == "human_approval":
            return _clip01(min(base, 0.74))  # keep below auto-allow threshold
        # deny mode stays as-is
        return base

    def decide(
        self,
        features: Optional[Dict[str, Any]] = None,
        risk: Optional[float] = None,
        system_stable: bool = True,
        policy_mode: str = "deny",
    ) -> Dict[str, Any]:
        s = self.score(features=features, risk=risk, system_stable=system_stable, policy_mode=policy_mode)
        return {
            "score": s,
            "allow": bool(s >= self.min_score_allow),
            "policy_mode": policy_mode,
        }
