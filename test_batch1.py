
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
        