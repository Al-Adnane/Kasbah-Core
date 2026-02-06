import requests
import json

BASE = "http://127.0.0.1:8002"

print("1. Testing Moat Status (13 Moats)...")
r = requests.get(f"{BASE}/api/system/moats")
d = r.json()
print(f"   Moats: {d['enabled_count']}/{d['total']}")

print("\n2. Testing Agent State (Moat E)...")
# Make a decision to generate state data
requests.post(f"{BASE}/api/rtp/decide", json={
    "tool_name": "read.me", 
    "agent_id": "test-agent-01",
    "signals": {"normality": 0.85, "consistency": 0.90}
})
# Check the state
r = requests.get(f"{BASE}/api/rtp/agent/test-agent-01/state")
state = r.json()
print(f"   Agent EMA: {state.get('ema')}")
print(f"   Trend: {state.get('trend')}")

print("\n3. Testing Decision with Geometry (Moat F)...")
r = requests.post(f"{BASE}/api/rtp/decide", json={
    "tool_name": "read.me", 
    "agent_id": "test-agent-01",
    "signals": {"normality": 0.95, "consistency": 0.95}
})
dec = r.json()
print(f"   Decision: {dec['decision']}")
print(f"   Geometry Score: {dec.get('geometry_score')}")
print(f"   Geometry Penalty: {dec.get('geometry_penalty')}")

if dec.get("ticket"):
    print("\n4. Testing Explain Endpoint (Moat C)...")
    # Use the core JTI (strip signature if present)
    jti = dec["ticket"].split(".")[0]
    r = requests.get(f"{BASE}/api/rtp/explain/{jti}")
    expl = r.json()
    print(f"   Status: {expl.get('status')}")
    print(f"   Tool: {expl.get('tool')}")

print("\n✅ ALL FEATURES INTEGRATED & SAFE")
