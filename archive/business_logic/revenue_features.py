import json
from datetime import datetime

class RevenueFeatures:
    def __init__(self):
        # Feature 1: Shadow Mode (Safe Mode)
        self.shadow_mode = True  # DEFAULT: We start in Safe Mode
        self.audit_log = []      # Stores the "Immutable Audit Trail"
        self.cost_savings = 0    # TDP Savings Tracker

    def toggle_shadow_mode(self, is_enabled):
        self.shadow_mode = is_enabled
        status = "SHADOW (PASSIVE)" if is_enabled else "ACTIVE BLOCKING"
        print(f"[REVENUE] System switched to: {status}")

    def log_decision(self, decision, details):
        """
        Feature 2: The 'Audit Button' Data Source.
        In real life, this writes to an immutable ledger.
        """
        entry = {
            "timestamp": str(datetime.now()),
            "decision": decision, # "BLOCKED" or "ALLOWED"
            "reason": details,
            "signature_hash": "0xSIMULATED_ZK_PROOF" # Placeholder for VSM
        }
        self.audit_log.append(entry)

    def export_audit_report(self):
        """
        THE CONVERSION FEATURE:
        Generates the report the CISO buys.
        """
        print("\n=== GENERATING AUDIT REPORT (SOC2 READY) ===")
        for entry in self.audit_log[-5:]: # Show last 5 events
            print(f"{entry['timestamp']} | {entry['decision']} | {entry['reason']}")
        print("=== END REPORT ===\n")

    def track_savings(self, mode):
        """
        Feature 3: Compute Savings Logic.
        If we are in ECO mode, we save money.
        """
        if mode == "ECO":
            self.cost_savings += 0.05 # $0.05 saved per packet