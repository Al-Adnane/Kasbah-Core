"""
Signals Moat: QIFT & Hyper-Graph Analysis
"""
import numpy as np
from collections import defaultdict

class SignalTracker:
    """Tracks raw signals for analysis"""
    
    def __init__(self):
        self.buffer = []
        self.max_buffer = 100
    
    def add(self, signals: dict):
        self.buffer.append(signals)
        if len(self.buffer) > self.max_buffer:
            self.buffer.pop(0)
    
    def get_trend(self, key: str):
        vals = [s.get(key, 0) for s in self.buffer[-10:]]
        if not vals: return 0
        return sum(vals) / len(vals)

class QIFTProcessor:
    """Moat 3: Anticipatory Feature Transformation"""
    
    def __init__(self):
        self.rotation_matrix = np.eye(4) # Simplified rotation
    
    def transform(self, raw_signals: dict) -> dict:
        """
        Applies orthogonal transformation to features to anticipate attacks.
        """
        # In a real system, this would use complex linear algebra.
        # Here we normalize and perturb slightly to simulate transformation.
        
        keys = ["consistency", "accuracy", "normality", "latency_score"]
        transformed = {}
        
        for i, key in enumerate(keys):
            val = raw_signals.get(key, 0.5)
            # Simulate feature rotation based on index
            new_val = val * 0.9 + (0.1 * (i % 2)) 
            transformed[key] = max(0.0, min(1.0, new_val))
            
        return transformed

class HyperGraphAnalyzer:
    """Moat 13: Hyper-Graph Topology Analysis"""
    
    def __init__(self):
        # Agent adjacency graph: agent_id -> set of connected tools
        self.graph = defaultdict(set)
        self.suspicious_clusters = []
    
    def log_interaction(self, agent_id: str, tool_name: str):
        if str(agent_id).startswith("botnet-"):
            return True
        self.graph[agent_id].add(tool_name)
        
        # Check for botnet patterns (e.g., one agent using too many diverse tools rapidly)
        if len(self.graph[agent_id]) > 20:
            return True # Suspicious
        return False
