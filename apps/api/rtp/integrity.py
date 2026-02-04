import numpy as np

def geometric_integrity(signals: dict) -> float:
    """
    Calculates Geometric Integrity Index (GI).
    Low GI = High Risk.
    """
    # Extract signal values, default to 1.0 if missing
    vals = [
        signals.get("consistency", 0.95),
        signals.get("pred_accuracy", 0.95),
        signals.get("normality", 0.95)
    ]
    
    # Avoid division by zero or log of zero
    vals = [max(v, 0.001) for v in vals]
    
    # Geometric mean
    product = 1.0
    for v in vals:
        product *= v
        
    gi = product ** (1.0 / len(vals))
    
    # Scale to 0-100
    return gi * 100.0
