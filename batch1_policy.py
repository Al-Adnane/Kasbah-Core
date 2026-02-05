
def decide(score, threshold=0.5):
    if score >= threshold:
        return "ALLOW", f"Score {score} >= Threshold {threshold}"
    return "DENY", f"Score {score} < Threshold {threshold}"
        