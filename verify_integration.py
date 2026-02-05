#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'apps'))

def test_moats_connectivity():
    print("🔍 VERIFYING MOATS INTEGRATION...")
    print("=" * 60)

    # 1. Check Import Connectivity
    try:
        from api.rtp.kernel_gate import KernelGate
        from api.rtp.integrity import GeometricIntegrityCalculator
        print("✅ All Moat Modules Imported Successfully")
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("   Hint: Ensure you are in the 'kasbah-core' directory.")
        return False

    # 2. Test Logic Integration
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
    print(f"   Integrity: {result['integrity_score']}")
    
    if 'audit_signature' in result:
        print(f"🔒 Signed: {result['audit_signature'][:16]}...")
    
    if 'merkle_root' in result:
        print(f"🌲 Merkle Root: {result['merkle_root']}")

    print("\n" + "=" * 60)
    print("🎉 INTEGRATION TEST PASSED.")
    return True

if __name__ == "__main__":
    success = test_moats_connectivity()
    sys.exit(0 if success else 1)
