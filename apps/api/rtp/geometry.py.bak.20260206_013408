from __future__ import annotations
from typing import Dict, Tuple
import math
import os

# Default threshold: cosine similarity must be >= this value to be considered "on-manifold"
DEFAULT_GEOM_THRESHOLD = float(os.environ.get("KASBAH_GEOMETRY_THRESHOLD", "0.92"))

def _vec_from_signals(signals) -> Tuple[float, float, float, float]:
    # supports dict or object
    def get(k, default=1.0):
        if isinstance(signals, dict):
            return signals.get(k, default)
        return getattr(signals, k, default)

    c = float(get("consistency", 1.0))
    a = float(get("accuracy", 1.0))
    n = float(get("normality", 1.0))
    l = float(get("latency_score", 1.0))
    # clamp 0..1
    c = max(0.0, min(1.0, c))
    a = max(0.0, min(1.0, a))
    n = max(0.0, min(1.0, n))
    l = max(0.0, min(1.0, l))
    return (c, a, n, l)

def cosine(u: Tuple[float, ...], v: Tuple[float, ...]) -> float:
    du = math.sqrt(sum(x*x for x in u))
    dv = math.sqrt(sum(x*x for x in v))
    if du == 0.0 or dv == 0.0:
        return 0.0
    return sum(ux*vx for ux, vx in zip(u, v)) / (du*dv)

def tool_target(tool_name: str) -> Tuple[float, float, float, float]:
    # Start with strict targets for read.me; expand later per tool
    if tool_name == "read.me":
        return (0.95, 0.95, 0.95, 0.90)
    return (0.90, 0.90, 0.90, 0.85)

def geometry_score(tool_name: str, signals) -> float:
    v = _vec_from_signals(signals)
    t = tool_target(tool_name)
    s = cosine(v, t)
    # clamp -1..1 to 0..1-ish (cosine is 0..1 here due to positive vectors, but be safe)
    if s < 0.0: s = 0.0
    if s > 1.0: s = 1.0
    return s

def geometry_threshold_for(tool_name: str) -> float:
    # allow env var to be "0.92" OR "92" OR "95" style
    thr = DEFAULT_GEOM_THRESHOLD
    # If mis-set as percent (e.g., 70, 92, 95), convert to 0.xx
    if thr > 1.0:
        thr = thr / 100.0
    # clamp
    if thr < 0.0:
        thr = 0.0
    if thr > 1.0:
        thr = 1.0
    return thr

def geometry_penalty(score: float, threshold: float) -> float:
    """
    Returns an additive threshold penalty in [0, 0.5].
    If score >= threshold -> 0.
    If score is far below -> stronger penalty.
    """
    if score >= threshold:
        return 0.0
    gap = threshold - score  # 0..1
    # scale: gap 0.02 => 0.05 penalty, gap 0.10 => 0.25, cap 0.5
    pen = min(0.5, max(0.0, gap * 2.5))
    return pen
