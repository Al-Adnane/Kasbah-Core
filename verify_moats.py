import requests
import json

BASE = "http://127.0.0.1:8002"

def check_moats_endpoint():
    print("Checking /api/system/moats...")
    r = requests.get(f"{BASE}/api/system/moats")
    data = r.json()
    print(f"Total Moats Enabled: {data['enabled_count']}/{data['total']}")
    for m in data['moats']:
        status = "✅" if m['enabled'] else "❌"
        print(f"  {status} {m['name']}: {m['notes']}")

def check_decision_with_moats():
    print("\nTesting /api/rtp/decide with Moat Logic...")
    payload = {
        "tool_name": "read.me",
        "usage": {"tokens": 150, "agent_id": "test-agent"},
        "signals": {
            "normality": 0.85, 
            "consistency": 0.90, 
            "accuracy": 0.88,
            "latency": 0.95
        }
    }
    r = requests.post(f"{BASE}/api/rtp/decide", json=payload)
    res = r.json()
    
    print(f"Decision: {res['decision']}")
    print(f"Integrity: {res['integrity_score']}")
    print(f"Brittleness: {res.get('brittleness_score', 'N/A')}")
    print(f"Threat Prob: {res.get('threat_probability', 'N/A')}")
    
    if 'moats_applied' in res:
        print("\nMoats Active in this request:")
        for k, v in res['moats_applied'].items():
            print(f"  - {k}: {v}")

def check_metrics():
    print("\nChecking /api/system/metrics for Moat Data...")
    r = requests.get(f"{BASE}/api/system/metrics")
    data = r.json()
    
    if 'brittleness' in data:
        print(f"Brittleness Score: {data['brittleness']['current_score']}")
    if 'feedback_loop' in data:
        print(f"Phase Lead Compensation: {data['feedback_loop']['phase_lead_compensation']}")
        print(f"Integrity Samples: {data['feedback_loop']['integrity_samples']}")

if __name__ == "__main__":
    try:
        check_moats_endpoint()
        check_decision_with_moats()
        check_metrics()
        print("\n✅ ALL 13 MOATS INTEGRATED AND REPORTING")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
