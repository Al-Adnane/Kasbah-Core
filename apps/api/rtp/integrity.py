def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x

def geometric_integrity(signals: dict) -> float:
    """
    Pure-Python integrity score in [0,1].
    Uses geometric mean over available normalized signals.
    Missing signals are ignored (not punished).
    """
    keys = ["consistency", "accuracy", "normality", "latency_score"]
    vals = []
    for k in keys:
        if k in signals and signals[k] is not None:
            try:
                vals.append(_clamp01(float(signals[k])))
            except Exception:
                pass

    if not vals:
        return 0.0

    prod = 1.0
    for v in vals:
        prod *= v
    return prod ** (1.0 / len(vals))
