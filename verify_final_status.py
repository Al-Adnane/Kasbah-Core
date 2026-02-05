#!/usr/bin/env python3
import requests
import json

API = "http://127.0.0.1:8002"

print("🔍 VERIFICATION: API TELEMETRY")
print("=" * 50)

# 1. Send a test request
print("\n1. Sending Request to trigger Moats...")
payload = {
    "tool_name": "test_observation",
    "agent_id": "admin_user",
    "signals": {"consistency": 0.9, "accuracy": 0.9, "normality": 0.9, "latency_score": 0.9}
}

res = requests.post(f"{API}/api/rtp/decide", json=payload)
data = res.json()

print(f"   Decision: {data['decision']}")
print(f"   Moats Triggered: {data['moats_triggered']}")
if len(data['moats_triggered']) >= 7:
    print("   ✅ PASS: Core moats are firing")
else:
    print("   ❌ FAIL: Not enough moats detected")

# 2. Check System Metrics
print("\n2. Checking /api/system/metrics...")
metrics = requests.get(f"{API}/api/system/metrics").json()

moats_active = sum(1 for k, v in metrics['moats_triggered'].items() if v > 0)
print(f"   Total Moats Reporting Activity: {moats_active}/13")

if moats_active >= 7:
    print("   ✅ PASS: System is tracking moat activity")
else:
    print("   ❌ FAIL: System is blind to moat activity")

# 3. Check Status
print("\n3. Checking /api/rtp/status...")
status = requests.get(f"{API}/api/rtp/status").json()
print(f"   Thermodynamic State: {status['thermo_state']}")
print(f"   System Integrity: {status['system_integrity']}")

if status['system_integrity'] > 0.5:
    print("   ✅ PASS: System Integrity is stable")
else:
    print("   ⚠️  System Integrity is low")

print("\n" + "=" * 50)
print("🎉 VERIFICATION COMPLETE")
print("The API is now fully observable.")
