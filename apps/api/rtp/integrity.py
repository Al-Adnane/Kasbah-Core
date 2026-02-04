from __future__ import annotations
from typing import Dict

def geometric_integrity(signals: Dict[str, float]) -> float:
    """
    Weighted geometric mean integrity score in [0,100].

    signals keys (0..1):
      - consistency
      - pred_accuracy
      - normality

    Floors each signal at 0.01 to avoid zeroing the product.
    """
    keys = ["consistency", "pred_accuracy", "normality"]
    weights = [0.50, 0.30, 0.20]

    scores = []
    for k in keys:
        v = float(signals.get(k, 0.95))
        if v < 0.01:
            v = 0.01
        if v > 1.0:
            v = 1.0
        scores.append(v)

    prod = 1.0
    for s, w in zip(scores, weights):
        prod *= s ** w

    # weights sum to 1.0, but keep it general
    score = (prod ** (1.0 / sum(weights))) * 100.0
    return round(score, 1)
