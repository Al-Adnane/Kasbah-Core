import sys
import numpy as np

# Import the modules we just created
from advanced.defense_layer import ThermodynamicDefense, SovereignReputation, TopologyAnalyzer
from business_logic.revenue_features import RevenueFeatures

# Mocking the core detection since we don't have the original legacy files in this setup
class MockCore:
    def detect_anomaly(self, data):
        # Simulate a 20% chance of finding an anomaly
        return np.random.rand() > 0.8

class KasbahEngine:
    def __init__(self):
        # 1. Load Advanced Moats
        self.tdp = ThermodynamicDefense()
        self.srl = SovereignReputation()
        self.hgta = TopologyAnalyzer()
        
        # 2. Load Revenue Features
        self.biz = RevenueFeatures()
        
        # 3. Load Core Detection
        self.core = MockCore()
        
        print("KASBAH ENGINE: INITIALIZED")

    def process_packet(self, src_ip, dst_ip, payload_data):
        """
        The Complete Pipeline
        """
        print(f"--- Processing Packet {src_ip} -> {dst_ip} ---")

        # --- LAYER 0: TOPOLOGY (HGTA) ---
        self.hgta.add_edge(src_ip, dst_ip)
        if self.hgta.check_for_botnet():
            print("[HGTA] ALERT: Botnet topology detected!")
            # In real code, we might trigger global curfew here

        # --- LAYER 1: REPUTATION (SRL) ---
        if self.srl.is_blacklisted(src_ip):
            print(f"[SRL] BLOCKED (Bad Reputation)")
            self.biz.log_decision("BLOCKED", "Identity score < 20")
            return

        # --- LAYER 2: PHYSICS (TDP) ---
        mode = self.tdp.regulate(payload_data)
        self.biz.track_savings(mode)

        # --- LAYER 3: CORE DETECTION ---
        is_anomaly = self.core.detect_anomaly(payload_data)
        
        # --- LAYER 4: REVENUE / SHADOW MODE ---
        if is_anomaly:
            # Penalize reputation
            self.srl.penalize(src_ip, 10)
            
            if self.biz.shadow_mode:
                print(f"[SHADOW MODE] Anomaly detected. Allowed for demo.")
                self.biz.log_decision("ALLOWED", "Anomaly (Shadow Mode)")
            else:
                print(f"[ACTIVE MODE] Blocking malicious packet.")
                self.biz.log_decision("BLOCKED", "Anomaly Detected")
        else:
            print("[CORE] Traffic looks normal.")
            self.biz.log_decision("ALLOWED", "Benign Traffic")

# --- CINEMATIC DEMO LOOP (For Investors) ---
if __name__ == "__main__":
    engine = KasbahEngine()
    
    # Create specific data types to force behavior
    # 1. High Entropy Data (Random) -> Triggers TURBO Mode
    high_entropy_data = np.random.rand(10)
    
    # 2. Low Entropy Data (Structured) -> Triggers ECO Mode (Saves Money)
    low_entropy_data = np.array([1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0])

    # SCENARIO 1: Normal Traffic (TURBO MODE)
    print(">>> SCENARIO 1: Processing Normal Traffic...")
    engine.process_packet("192.168.1.1", "10.0.0.5", high_entropy_data)

    # SCENARIO 2: Show Cost Savings (ECO MODE)
    print("\n>>> SCENARIO 2: Structured Traffic (Saving Money)...")
    engine.process_packet("192.168.1.2", "10.0.0.5", low_entropy_data)

    # SCENARIO 3: Attack detected, but blocked by SHADOW MODE
    print("\n>>> SCENARIO 3: Simulated Attack (Shadow Mode catches it)...")
    # We force the mock core to return True (Anomaly) by hacking the internal state for the demo
    engine.core.detect_anomaly = lambda x: True 
    engine.process_packet("192.168.1.99", "10.0.0.5", high_entropy_data)
    
    # --- SALES PITCH ---
    print("\n*** CUSTOMER SEES VALUE ***")
    print(f"[SALES] You saved ${engine.biz.cost_savings:.2f} on compute costs.")
    engine.biz.export_audit_report()

    # SCENARIO 4: Upgrade to PRO and BLOCK for real
    print("\n>>> SCENARIO 4: Upgrading to PRO License...")
    engine.biz.toggle_shadow_mode(False)
    
    print("\n>>> SCENARIO 5: Same Attack Hits Again (Pro Mode BLOCKS it)...")
    engine.process_packet("192.168.1.99", "10.0.0.5", high_entropy_data)