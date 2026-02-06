#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🔒 SYSTEM SAFETY CHECK & LIVE USER SIMULATION${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

# ==============================================================================
# STEP 1: SAFETY CHECK (Docker Logs)
# ==============================================================================
echo -e "${YELLOW}[STEP 1] Checking System Stability (Docker Logs)...${NC}"

# Check if container is running
if ! docker ps | grep -q "kasbah-core-api-1"; then
    echo -e "${RED}❌ Container is NOT running. Attempting restart...${NC}"
    docker-compose up -d
    echo -e "${YELLOW}Waiting for startup (15s)...${NC}"
    sleep 15
else
    echo -e "${GREEN}✅ Container is running.${NC}"
fi

# Check for Python Errors in recent logs
ERRORS=$(docker logs kasbah-core-api-1 2>&1 | grep -i "Traceback\|SyntaxError\|UnboundLocalError\|ImportError" | tail -5)

if [ ! -z "$ERRORS" ]; then
    echo -e "${RED}❌ CRITICAL: Errors found in logs! System is UNSTABLE.${NC}"
    echo -e "${YELLOW}--- LOGS ---${NC}"
    echo "$ERRORS"
    echo -e "${YELLOW}-------------${NC}"
    echo -e "${RED}Do not proceed with live test. Check the kernel_gate.py file for typos.${NC}"
    exit 1
else
    echo -e "${GREEN}✅ No Python errors in logs. System is STABLE.${NC}"
fi

# ==============================================================================
# STEP 2: LIVE USER SIMULATION
# ==============================================================================
echo -e "\n${YELLOW}[STEP 2] Sending Live Request as User 'live-test-user-01'...${NC}"

PAYLOAD='{
  "tool_name": "data.analyze",
  "usage": {
    "tokens": 500,
    "cost": 0.15,
    "agent_id": "live-test-user-01"
  },
  "signals": {
    "consistency": 0.92,
    "pred_accuracy": 0.95,
    "normality": 0.88,
    "entropy": 4.2,
    "latency_ms": 120
  }
}'

echo -e "${YELLOW}Sending to: http://127.0.0.1:8002/api/rtp/decide${NC}\n"

# Get Response and Pretty Print
RESPONSE=$(curl -s -X POST "http://127.0.0.1:8002/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: REPLACE_WITH_YOUR_OPENAI_KEY" \
  -d "$PAYLOAD")

# Pretty print JSON
echo "$RESPONSE" | python3 -m json.tool

# ==============================================================================
# STEP 3: VERIFICATION (Did the moats work?)
# ==============================================================================
echo -e "\n${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🛡️  INTEGRATION VERIFICATION${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

# Analyze Response
python3 << PYEOF
import json
import sys

try:
    data = json.loads("""$RESPONSE""")
except Exception as e:
    print(f"${RED}❌ Failed to parse response: {e}${NC}")
    sys.exit(1)

# 1. Check for specific keys from new moats
new_keys = {
    "Moat 4 (ATP)": "atp_status",
    "Moat 8 (SRK)": "kernel_health",
    "Moat 9 (HCS)": "hcs_sample",
    "Moat 10 (VSM)": "zk_state_proof",
    "Moat 13 (HGTA)": "topology_check"
}

all_found = True
print(f"{'MOAT':<15} | {'KEY':<20} | {'STATUS'}")
print("-" * 50)

for name, key in new_keys.items():
    if key in data:
        print(f"${GREEN}✅{NC} {name:<15} | {key:<20} | ${GREEN}FOUND${NC}")
    else:
        print(f"${RED}❌{NC} {name:<15} | {key:<20} | ${RED}MISSING${NC}")
        all_found = False

print("-" * 50)

# 2. Check the list of triggered moats
triggered = data.get('moats_triggered', [])
print(f"\n${CYAN}Triggered Moats List:{NC} {triggered}")

# Check if we have 13 unique moats
unique_count = len(set(triggered))
if unique_count == 13:
    print(f"${GREEN}✅ SUCCESS: All 13 Moats Active (${unique_count}/13)${NC}")
else:
    print(f"${RED}❌ PARTIAL: Only ${unique_count}/13 Moats Active.${NC}")
    all_found = False

# 3. Final Verdict
print("\n" + "="*50)
if all_found and data.get('decision'):
    print(f"${GREEN}🎉 LIVE TEST PASSED${NC}")
    print(f"   System is Safe, Stable, and Fully Integrated.")
    print(f"   User: {data.get('ticket', {}).get('agent_id', 'unknown')}")
    print(f"   Decision: {data.get('decision')}")
else:
    print(f"${RED}🚨 LIVE TEST FAILED${NC}")
    print(f"   Integration missing or logic error.")

PYEOF

