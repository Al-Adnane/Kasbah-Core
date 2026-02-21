import numpy as np

# 1. Thermodynamic Defense (TDP) - Physics Layer
class ThermodynamicDefense:
    def regulate(self, data_vector):
        # Calculate Shannon Entropy to determine "chaos" in the data
        _, counts = np.unique(data_vector, return_counts=True)
        probs = counts / len(data_vector)
        # Add small number to avoid log(0) error
        entropy = -np.sum(probs * np.log2(probs + 1e-9))
        
        # High entropy = Suspicious/Random = Turbo Mode
        # Low entropy = Structured/Boring = Eco Mode
        mode = "TURBO" if entropy > 3.0 else "ECO"
        return mode

# 2. Sovereign Reputation Ledger (SRL) - Identity Layer
class SovereignReputation:
    def __init__(self):
        # A dictionary to store scores: {"IdentityName": Score}
        self.scores = {} 

    def get_score(self, identity):
        # If we haven't seen this identity before, give them 50 points (Neutral)
        return self.scores.get(identity, 50)

    def penalize(self, identity, amount):
        current = self.get_score(identity)
        # Subtract penalty, but don't go below 0
        self.scores[identity] = max(0, current - amount)

    def is_blacklisted(self, identity):
        # If score is below 20, we block them
        return self.get_score(identity) < 20

# 3. Hyper-Graph Topology (HGTA) - Network Layer
class TopologyAnalyzer:
    def __init__(self):
        # A simplified matrix (grid) representing connections
        self.matrix = np.zeros((100, 100)) 
        self.map = {} # Maps "192.168.x.x" to "0, 1, 2..."
        self.counter = 0

    def add_edge(self, src, dst):
        # Convert IP addresses to simple numbers (indices) for our matrix
        if src not in self.map: 
            self.map[src] = self.counter
            self.counter += 1
        if dst not in self.map: 
            self.map[dst] = self.counter
            self.counter += 1
        
        s = self.map[src] % 100 # Keep numbers between 0-99
        d = self.map[dst] % 100
        
        # Add connection to the matrix
        self.matrix[s][d] += 1
        self.matrix[d][s] += 1

    def check_for_botnet(self):
        # Check if any single node is connecting to too many others
        # We sum up the connections per row
        row_sums = np.sum(self.matrix, axis=1)
        max_connections = np.max(row_sums)
        # If one node has > 50 connections, it's likely a scanner/botnet
        return max_connections > 50