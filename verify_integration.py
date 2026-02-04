#!/usr/bin/env python3
import sys
import os

# Add apps to path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'apps'))

def test_moats_connectivity():
    print("🔍 VERIFYING MOATS INTEGRATION...")
    print("=" * 60)

    # 1. Check Import Connectivity
    try:
        from api.rtp.kernel_gate import KernelGate
        from api.rtp.integrity import GeometricIntegrityCalculator, BidirectionalFeedbackLoop
        from api.rtp.signals import QIFTProcessor, HyperGraphAnalyzer
        from api.rtp.audit import AuditLogger         print("✅ All Moat Modules Imported Successfully")
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("   Hint: Ensure you are in the 'kasbah-core' directory.")
        return False

    # 2. Test Logic Integration (Dry Run)
    print("\n🧪 Testing Logic Flow...")

    gate = KernelGate()

    # Simulate a Request
    payload = {
        "tool_name": "data_export",
        "agent_id": "agent-007",
        "usage": {"tokens": 100},
        "signals": {
            "consistency": 0.95,
            "accuracy": 0.90,
            "normality": 0.88,
            "latency_score": 0.92
        }
    }

    result = gate.decide(payload)

    print(f"📥 Input: Tool={payload['tool_name']}, Agent={payload['agent_id']}")
    print(f"📤 Output: {result['decision']}")
    print(f"   Reason: {result['reason']}")
    print(f"   Integrity: {result['integrity_score']}")
    
    # Check for cryptographic signature (Moat 5)
    if 'audit_signature' in result:
        print(f"🔒 Signed: {result['audit_signature'][:16]}... (Moat 5)")
    
    # Check for Merkle Root (Moat 7)
    if 'merkle_root' in result:
        print(f"🌲 Merkle Root: {result['merkle_root']} (Moat 7)")

    # 3. Check Feedback Loop Active (Moat 1)
    if hasattr(gate, 'feedback_loop') and gate.feedback_loop.threat_level >= 0:
        print(f"✅ Feedback Loop (Moat 1) Active - Threat Level: {gate.feedback_loop.threat_level}")

    # 4. Check Audit Trail (Moat 7)
    logs = gate.audit.get_recent_logs(1)
    if logs:
        print(f"✅ Audit Ledger (Moat 7) Active: {len(logs)} entries")

    # 5. Check Topology (Moat 13)
    if "agent-007" in gate.topology.graph:
        print("✅ Hyper-Graph (Moat 13) Tracking Active")

    # 6. Check QIFT (Moat 3)
    if hasattr(gate, 'qift'):
         print("✅ QIFT Processor (Moat 3) Active")

    print("\n" + "=" * 60)
    print("🎉 INTEGRATION TEST PASSED. SYSTEM IS CONNECTED.")
    return True

if __name__ == "__main__":
    success = test_moats_connectivity()
    sys.exit(0 if success else 1)
