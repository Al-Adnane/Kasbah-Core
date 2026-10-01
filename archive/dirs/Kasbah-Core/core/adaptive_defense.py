import numpy as np

class AdaptiveDefenseController:
    """
    Combines Moat #3 (QIFT Rotation) and Moat #4 (Dual Horizon Forecasting).
    """
    def __init__(self):
        self.theta = 0.0

    def forecast_threat(self, input_vector):
        """
        Moat #4: Dual Horizon Forecasting.
        LSTM (Short) vs Transformer (Long).
        """
        # Simulate LSTM vs Transformer
        lstm_pred = np.mean(input_vector) * 0.9
        transformer_pred = np.mean(input_vector) * 1.1
        
        # Logic: If data is chaotic (high variance), trust Long-term (Transformer)
        variance = np.var(input_vector)
        if variance > 0.1:
            threat_prob = 0.8 # High Threat
        else:
            threat_prob = 0.2
            
        return threat_prob

    def apply_qift(self, input_vector, threat_prob):
        """
        Moat #3: Anticipatory Feature Transformation.
        Rotates features orthogonally based on threat.
        """
        # Calculate Rotation Angle
        theta = threat_prob * (np.pi / 4) # Max 45 degrees
        
        # Simulate Rotation (Givens rotation on first 2 dims for demo)
        x, y = input_vector[0], input_vector[1]
        x_new = x * np.cos(theta) - y * np.sin(theta)
        y_new = x * np.sin(theta) + y * np.cos(theta)
        
        transformed = input_vector.copy()
        transformed[0] = x_new
        transformed[1] = y_new
        
        return transformed