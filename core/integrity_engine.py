import numpy as np

class GeometricMeanIntegrityController:
    """
    Moat #2: Calculates System Integrity Index I(t) using Weighted Geometric Mean.
    Sensitive to the 'weakest link'.
    """
    def __init__(self):
        self.weights = {'ics': 1.0, 'mfe': 1.0, 'ocs': 1.0}

    def calculate_I_t(self, metrics):
        """
        metrics = {'ics': float, 'mfe': float, 'ocs': float}
        """
        ics = max(metrics.get('ics', 1e-9), 1e-9) # Avoid log(0)
        mfe = max(metrics.get('mfe', 1e-9), 1e-9)
        ocs = max(metrics.get('ocs', 1e-9), 1e-9)

        w_ics = self.weights['ics']
        w_mfe = self.weights['mfe']
        w_ocs = self.weights['ocs']
        sum_w = w_ics + w_mfe + w_ocs

        # The Formula: (Prod(x^w))^(1/sum_w)
        product = (ics ** w_ics) * (mfe ** w_mfe) * (ocs ** w_ocs)
        integrity_index = product ** (1.0 / sum_w)
        
        return integrity_index

    def modulate_tau(self, current_tau, integrity_index):
        """
        Moat #1: Integrity modulates the Detection Threshold.
        If Integrity drops, Tau tightens (gets harder to pass).
        """
        # Simple inverse relationship for demo
        return 0.5 + (1.0 - integrity_index) * 0.5