import os

files = {
    "batch1_qift.py": """
def transform(signals):
    transformed = {}
    for key, val in signals.items():
        new_val = val * 0.95
        transformed[key] = max(0.0, min(1.0, new_val))
    return transformed
        """,

    "batch1_integrity.py": """
import math
def calculate(transformed_signals):
    weights = {"consistency": 0.3, "accuracy": 0.3, "normality": 0.2, "latency_score": 0.2}
    product = 1.0
    for key, weight in weights.items():
        val = transformed_signals.get(key, 0.5)
        val = max(0.001, min(1.0, val))
        product *= math.pow(val, weight)
    return round(product, 4)
        """,

    "batch1_policy.py": """
def decide(score, threshold=0.5):
    if score >= threshold:
        return "ALLOW", f"Score {score} >= Threshold {threshold}"
    return "DENY", f"Score {score} < Threshold {threshold}"
        """,

    "test_batch1.py": """
import sys
from batch1_qift import transform
from batch1_integrity import calculate
from batch1_policy import decide

print("🧪 BATCH 1 INTEGRATION TEST")
print("="*50)

good = {"consistency": 0.95, "accuracy": 0.90, "normality": 0.88, "latency_score": 0.92}
t1 = transform(good)
s1 = calculate(t1)
d1, r1 = decide(s1)
print(f"Good: Score={s1}, Dec={d1}")

bad = {"consistency": 0.10, "accuracy": 0.15, "normality": 0.05, "latency_score": 0.10}
t2 = transform(bad)
s2 = calculate(t2)
d2, r2 = decide(s2)
print(f"Bad:  Score={s2}, Dec={d2}")

if d1 == "ALLOW" and d2 == "DENY":
    print("✅ PASS")
    sys.exit(0)
else:
    print("❌ FAIL")
    sys.exit(1)
        """
}

for name, content in files.items():
    with open(name, "w") as f:
        f.write(content)

print("✅ Files created. Running test...")
os.system("python3 test_batch1.py")
