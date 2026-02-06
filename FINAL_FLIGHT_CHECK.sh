#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

API_URL="http://127.0.0.1:8002"
API_KEY="REPLACE_WITH_YOUR_OPENAI_KEY" 
TEMP_FILE="/tmp/kasbah_flight_check.json"

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🚀 KASBAH CORE - FINAL FLIGHT CHECK${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

if ! curl -s "$API_URL/health" > /dev/null; then
    echo -e "${RED}❌ SYSTEM DOWN. Cannot proceed.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ System is Online.${NC}"
echo -e "${BLUE}Testing Live Moat Integration via /decide endpoint...${NC}\n"

PAYLOAD='{
  "tool_name": "system.analyze",
  "usage": {"tokens": 500, "cost": 0.1, "agent_id": "launch-validator"},
  "signals": {
    "consistency": 0.92,
    "pred_accuracy": 0.95,
    "normality": 0.88,
    "entropy": 4.2,
    "latency_ms": 150
  }
}'

curl -s -X POST "$API_URL/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "$PAYLOAD" -o $TEMP_FILE

python3 << EOF
import json
import sys
import os

# Define colors INSIDE Python scope
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'

try:
    with open("$TEMP_FILE", "r") as f:
        data = json.load(f)
except Exception as e:
    print(f"❌ Error reading response: {e}")
    if os.path.exists("$TEMP_FILE"):
        with open("$TEMP_FILE", "r") as f:
            print("Raw Response:")
            print(f.read())
    sys.exit(1)

print(f"📊 ANALYSIS OF LIVE RESPONSE:")
print("-" * 60)

moats = {
    1: ("Bidirectional Feedback", "decision" in data and "threshold" in data),
    2: ("Geometric Integrity", "integrity_score" in data),
    3: ("QIFT (Transform)", "geometry_score" in data or "geometry_penalty" in data),
    4: ("Adversarial Training", False), 
    5: ("Crypto Command Binding", "ticket" in data and "sig" in data.get("ticket", {})),
    6: ("MoE Horizon Fusion", "pre_defense_state" in data),
    7: ("Merkle Audit Ledger", "merkle_root" in data or "audit_signature" in data),
    8: ("Self-Rewriting Kernel", False),
    9: ("Homomorphic State", False),
    10: ("Verifiable State Machine", False),
    11: ("Thermodynamic Defense", "defense_state" in data or "entropy" in data.get("signals", {})),
    12: ("Sovereign Reputation", "agent_state" in data and "ema" in data.get("agent_state", {})),
    13: ("Hyper-Graph Topology", False)
}

api_triggered = data.get("moats_triggered", [])
passed = 0
total = 13

for id, (name, detected) in moats.items():
    is_active = detected or (id in api_triggered)
    
    if is_active:
        print(f"{GREEN}✅ Moat {id:<2} {name:<30} [ACTIVE]{NC}")
        passed += 1
    else:
        print(f"{RED}❌ Moat {id:<2} {name:<30} [INACTIVE/NOT DETECTED]{NC}")

print("-" * 60)
print(f"SCORE: {passed}/{total} Moats Live ({int(passed/total*100)}%)")
print()

print(f"🛡️  CRITICAL LAUNCH CHECKS:")
print("-" * 60)

checks = {
    "Decision Logic": "decision" in data,
    "Ticket Generation": "ticket" in data,
    "Audit Trail": "merkle_root" in data,
    "System Integrity Calculated": "integrity_score" in data
}

all_good = True
for name, check in checks.items():
    if check:
        print(f"{GREEN}✅ {name}{NC}")
    else:
        print(f"{RED}❌ {name} - CRITICAL FAILURE${NC}")
        all_good = False

print()
if all_good and passed >= 10:
    print(f"{GREEN}================================================================================${NC}")
    print(f"{GREEN}  🎉 LAUNCH STATUS: GO FOR LAUNCH (System Healthy)${NC}")
    print(f"{GREEN}================================================================================${NC}")
elif passed >= 7:
    print(f"{YELLOW}================================================================================${NC}")
    print(f"{YELLOW}  ⚠️  LAUNCH STATUS: PROCEED WITH CAUTION (Some Moats Missing)${NC}")
    print(f"{YELLOW}================================================================================${NC}")
else:
    print(f"{RED}================================================================================${NC}")
    print(f"{RED}  🚨 LAUNCH STATUS: ABORT (Critical Moats Missing)${NC}")
    print(f"{RED}================================================================================${NC}")

if not all_good or passed < 10:
    print()
    print(f"DEBUG: Raw Response Snippet")
    print(json.dumps(data, indent=2))

os.remove("$TEMP_FILE")
EOF

