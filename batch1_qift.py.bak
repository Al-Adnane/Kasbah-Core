
def transform(signals):
    transformed = {}
    for key, val in signals.items():
        new_val = val * 0.95
        transformed[key] = max(0.0, min(1.0, new_val))
    return transformed
        