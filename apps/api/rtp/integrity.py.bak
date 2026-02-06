"""
Integrity Moat: Geometric Mean & Bidirectional Feedback
"""
import math
from typing import Dict, List

class GeometricIntegrityCalculator:
    """Moat 2: Weighted Geometric Mean Integrity"""
    
    def __init__(self):
        self.history = []
    
    def calculate(self, metrics: Dict[str, float]) -> float:
        """
        Calculates integrity using weighted geometric mean.
        I(t) = (prod(s_i ^ w_i))
        """
        weights = {
            "consistency": 0.3,
            "accuracy": 0.3,
            "normality": 0.2,
            "latency": 0.2
        }
        
        product = 1.0
        for key, weight in weights.items():
            val = metrics.get(key, 0.5)  # Default 0.5 if missing
            # Clamp value between 0.001 and 1.0 to avoid math errors
            val = max(0.001, min(1.0, val))
            product *= math.pow(val, weight)
            
        integrity_score = product
        return integrity_score

class BidirectionalFeedbackLoop:
    """Moat 1: Bidirectional Closed-Loop Feedback"""
    
    def __init__(self):
        self.threat_level = 0.0  # P_threat
        self.learning_rate = 0.1
    
    def update(self, integrity: float, action_outcome: str):
        """
        Updates system threat sensitivity based on history.
        If integrity was low but action was ALLOW, increase sensitivity.
        """
        if integrity < 0.5 and action_outcome == "ALLOW":
            self.threat_level = min(1.0, self.threat_level + self.learning_rate)
        elif integrity > 0.8 and action_outcome == "DENY":
            self.threat_level = max(0.0, self.threat_level - self.learning_rate)
            
        return self.threat_level
    
    def get_threshold(self) -> float:
        """Returns dynamic threshold based on threat level"""
        # Base threshold 0.5, ranges from 0.2 to 0.8
        return 0.5 + (self.threat_level * 0.3)
