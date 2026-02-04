import sys
import numpy as np
from datetime import datetime

# --- IMPORT REAL ENGINES ---
from core.integrity_engine import GeometricMeanIntegrityController
from core.adaptive_defense import AdaptiveDefenseController
from crypto.secure_core import CryptoSecureCore

# --- IMPORT EXISTING ADVANCED & BUSINESS LAYERS ---
from advanced.defense_layer import ThermodynamicDefense, SovereignReputation, TopologyAnalyzer
from business_logic.revenue_features import RevenueFeatures

class KasbahEngine:
    def __init__(self):
        # 1. Load Core Integrity (Moat #2)
        self.iic = GeometricMeanIntegrityController()
        
        # 2. Load Adaptive Defense (Moat #3 & #4)
        self.adaptive = AdaptiveDefenseController()
        
        # 3. Load Crypto Core (CCB & IMIL)
        self.crypto = CryptoSecureCore()

        # 4. Load Advanced Moats (TDP, SRL, HGTA)
        self.tdp = ThermodynamicDefense()
        self.srl = SovereignReputation()
        self.hgta = TopologyAnalyzer()
        
        # 5. Load Revenue Features
        self.biz = RevenueFeatures()
        
        # Initial State
        self.tau = 0.5
        print("KASBAH ENGINE: FULL ARCHITECTURE LOADED")

    def process_packet(self, src_ip, dst_ip, payload_data):
        print(f"--- Processing {src_ip} -> {dst_ip} ---")

        # --- LAYER 0: TOPOLOGY (HGTA) ---
        self.hgta.add_edge(src_ip, dst_ip)
        if self.hgta.check_for_botnet():
            print("[HGTA] Botnet alert!")

        # --- LAYER 1: REPUTATION (SRL) ---
        if self.srl.is_blacklisted(src_ip):
            print(f"[SRL] BLOCKED (Blacklisted Identity)")
            return

        # --- LAYER 2: PHYSICS (TDP) ---
        mode = self.tdp.regulate(payload_data)
        self.biz.track_savings(mode)

        # --- LAYER 3: CORE INTEGRITY & FORECASTING (REAL LOGIC) ---
        
        # 1. Get Metrics (Simulated for demo: ICS, MFE, OCS)
        # In reality, these come from system sensors
        metrics = {'ics': 0.9, 'mfe': 0.9, 'ocs': 0.9} 
        
        # 2. Calculate Integrity (Moat #2: Geometric Mean)
        I_t = self.iic.calculate_I_t(metrics)
        
        # 3. Forecast Threat (Moat #4: MoE)
        P_threat = self.adaptive.forecast_threat(payload_data)
        
        # 4. Modulate Tau (Moat #1: Feedback Loop)
        # Low Integrity -> Tighten Detection
        self.tau = self.iic.modulate_tau(self.tau, I_t)

        # --- LAYER 4: DEFENSE TRANSFORMATION (Moat #3: QIFT) ---
        # Rotate features pre-emptively
        transformed_data = self.adaptive.apply_qift(payload_data, P_threat)

        # --- LAYER 5: CRYPTO VERIFICATION (CCB) ---
        # Every modulaton of Tau must be signed
        sig = self.crypto.sign_command("MOD_TAU", {"val": self.tau})
        is_valid = self.crypto.verify_command("MOD_TAU", {"val": self.tau}, sig)
        
        if not is_valid:
            print("[CRYPTO] SECURITY ALERT: Signature Invalid!")
            return

        # --- LAYER 6: DETECTION (Fixed Logic) ---
        # If Threat > 0.6, we always detect it for the demo
        detected = (P_threat > 0.6)

        if detected:
            self.srl.penalize(src_ip, 20)
            
            # Log to IMIL (Merkle Ledger)
            self.crypto.update_merkle_ledger({"action": "BLOCK", "src": src_ip})

            if self.biz.shadow_mode:
                print(f"[SHADOW] Attack detected (Threat: {P_threat:.2f}). Allowed for demo.")
                self.biz.log_decision("ALLOWED", f"Anomaly (Shadow Mode). Threat: {P_threat:.2f}")
            else:
                print(f"[ACTIVE] Attack blocked (Threat: {P_threat:.2f}).")
                self.biz.log_decision("BLOCKED", f"Anomaly Detected. Threat: {P_threat:.2f}")
        else:
            print(f"[SAFE] Traffic passed. Integrity: {I_t:.2f}")
            self.biz.log_decision("ALLOWED", f"Benign Traffic. Integrity: {I_t:.2f}")

# --- CINEMATIC DEMO LOOP ---
if __name__ == "__main__":
    engine = KasbahEngine()
    
    # Scenarios
    print(">>> SCENARIO 1: High Entropy Attack (Triggers QIFT Rotation)...")
    high_entropy = np.random.rand(10)
    engine.process_packet("192.168.1.10", "10.0.0.5", high_entropy)

    print("\n>>> SCENARIO 2: Low Entropy Traffic (Saves Money)...")
    low_entropy = np.array([1.0]*10)
    engine.process_packet("192.168.1.11", "10.0.0.5", low_entropy)
    
    # Force a detection scenario
    print("\n>>> SCENARIO 3: Severe Attack Detected (Shadow Mode)...")
    # Manually force high threat for demo
    engine.adaptive.forecast_threat = lambda x: 0.9 
    engine.process_packet("192.168.1.99", "10.0.0.5", high_entropy)
    
    print("\n*** CUSTOMER SEES VALUE ***")
    engine.biz.export_audit_report()

    # UPGRADE SCENARIO
    print("\n>>> SCENARIO 4: Upgrading to PRO License...")
    engine.biz.toggle_shadow_mode(False)
    
    print("\n>>> SCENARIO 5: Same Attack Hits Again (Pro Mode BLOCKS it)...")
    engine.process_packet("192.168.1.99", "10.0.0.5", high_entropy)