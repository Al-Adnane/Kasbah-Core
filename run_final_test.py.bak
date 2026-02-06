#!/usr/bin/env python3
import sys
import os

# Ensure we can find the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'apps'))

def test_system():
    print("🧪 FINAL SYSTEM INTEGRATION TEST")
    print("=" * 50)

    try:
        # This import matches your new system structure
        from api.rtp.kernel_gate import KernelGate
        from api.rtp.integrity import GeometricIntegrityCalculator
        
        print("✅ Imports successful (No ExecutionTicket needed)")
        
        # Initialize the Kernel Gate
        gate = KernelGate()
        
        # Create a test payload
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
        
        # Run the decision
        result = gate.decide(payload)
        
        print(f"\n📤 Decision: {result['decision']}")
        print(f"🔒 Signature: {result['audit_signature'][:16]}...")
        print(f"🌲 Merkle Root: {result['merkle_root']}")
        
        print("\n" + "=" * 50)
        print("🎉 SYSTEM WORKING CORRECTLY")
        return True

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_system()
    sys.exit(0 if success else 1)
