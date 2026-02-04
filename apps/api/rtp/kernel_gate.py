"""
Kernel Gate: The Core Orchestrator
Integrates all 13 Moats (Implemented: 1, 2, 3, 5, 6, 7, 11, 13)
"""
from .integrity import GeometricIntegrityCalculator, BidirectionalFeedbackLoop
from .signals import SignalTracker, QIFTProcessor, HyperGraphAnalyzer
from .audit import AuditLogger
from .policy import MoEHorizonFusion, ThermodynamicProtocol

class KernelGate:
    def __init__(self):
        # Initialize Moat Components
        print("🔧 Initializing KernelGate Moats...")
        
        # Moat 2: Integrity
        self.integrity_calc = GeometricIntegrityCalculator()
        
        # Moat 1: Feedback
        self.feedback_loop = BidirectionalFeedbackLoop()
        
        # Moat 3: QIFT
        self.qift = QIFTProcessor()
        
        # Moat 13: Topology
        self.topology = HyperGraphAnalyzer()
        
        # Moat 7 & 5: Audit & Crypto
        self.audit = AuditLogger()
        
        # Moat 6 & 11: Policy
        self.moe = MoEHorizonFusion()
        self.thermo = ThermodynamicProtocol()
        
        # Global state
        self.signal_tracker = SignalTracker()
        
        print("✅ All Moats Initialized.")

    def decide(self, payload: dict) -> dict:
        """
        Main Decision Pipeline:
        1. Analyze Topology (Moat 13)
        2. Transform Signals (Moat 3)
        3. Calculate Integrity (Moat 2)
        4. Fuse Predictions (Moat 6)
        5. Check Thermodynamics (Moat 11)
        6. Apply Feedback Threshold (Moat 1)
        7. Log Decision (Moat 7, 5)
        """
        
        tool_name = payload.get("tool_name", "unknown")
        agent_id = payload.get("agent_id", "anonymous")
        raw_signals = payload.get("signals", {})
        
        # --- Moat 13: Topology Analysis ---
        is_botnet = self.topology.log_interaction(agent_id, tool_name)
        
        # --- Moat 3: QIFT Transformation ---
        transformed_signals = self.qift.transform(raw_signals)
        
        # --- Moat 2: Geometric Integrity ---
        integrity_score = self.integrity_calc.calculate(transformed_signals)
        
        # --- Moat 6: MoE Horizon Fusion ---
        prediction_confidence = self.moe.predict(transformed_signals)
        
        # --- Moat 11: Thermodynamic Check ---
        # Simulate load based on request rate (simplified)
        current_load = 0.6 # Placeholder
        self.thermo.update_entropy(current_load, 1.0 - integrity_score)
        defense_state = self.thermo.get_defense_state()
        
        # --- Decision Logic ---
        # Base threshold adjusted by Feedback Loop (Moat 1)
        threshold = self.feedback_loop.get_threshold()
        
        # If in LOCKDOWN, require higher score
        if defense_state == "LOCKDOWN":
            threshold += 0.2
        
        # Final Decision
        allow = False
        reason = ""
        
        if is_botnet:
            allow = False
            reason = "Moat 13: Suspicious topology pattern detected"
        elif integrity_score >= threshold and prediction_confidence > 0.5:
            allow = True
            reason = f"Integrity {integrity_score:.2f} > Threshold {threshold:.2f}"
        else:
            allow = False
            reason = f"Integrity {integrity_score:.2f} < Threshold {threshold:.2f}"
        
        decision_str = "ALLOW" if allow else "DENY"
        
        # --- Moat 1: Feedback Update ---
        self.feedback_loop.update(integrity_score, decision_str)
        
        # --- Moat 7 & 5: Audit & Cryptography ---
        audit_entry = self.audit.log(agent_id, tool_name, decision_str, integrity_score)
        
        return {
            "decision": decision_str,
            "reason": reason,
            "integrity_score": round(integrity_score, 4),
            "threshold": round(threshold, 4),
            "defense_state": defense_state,
            "audit_signature": audit_entry["signature"],
            "merkle_root": audit_entry["current_root"][:16] + "..."
        }
