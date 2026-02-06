
import math
def calculate(transformed_signals):
    weights = {"consistency": 0.3, "accuracy": 0.3, "normality": 0.2, "latency_score": 0.2}
    product = 1.0
    for key, weight in weights.items():
        val = transformed_signals.get(key, 0.5)
        val = max(0.001, min(1.0, val))
        product *= math.pow(val, weight)
    return round(product, 4)
        