#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🏥 SURGICAL FIX: Move Hook to correct scope${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

MAIN_FILE="apps/api/rtp/kernel_gate.py"
BACKUP_FILE="apps/api/rtp/kernel_gate.py.surgical_backup"

# ==============================================================================
# STEP 1: BACKUP
# ==============================================================================
echo -e "${YELLOW}[Step 1/4] Creating Surgical Backup...${NC}"
cp $MAIN_FILE $BACKUP_FILE

# ==============================================================================
# STEP 2: REMOVE BROKEN HOOK (Clean up the mess)
# ==============================================================================
echo -e "${YELLOW}[Step 2/4] Removing broken hook insertion...${NC}"

# We use Python to do precise text removal
python3 << PYEOF
import re

filename = "$MAIN_FILE"
marker_start = "# --- MARKET READY PLUGIN ---"
marker_end = "return {"

with open(filename, 'r') as f:
    lines = f.readlines()

new_lines = []
skip = False
found_marker = False

# Logic: Keep lines unless we are inside the marker block
for i, line in enumerate(lines):
    if marker_start in line:
        skip = True
        found_marker = True
        continue # Skip the marker line itself
    
    if skip:
        # If we are skipping, check if we hit the return
        if marker_end in line:
            # We found the end of the bad block. 
            # We do NOT append the return here yet, we want to re-inject it safely later.
            # But we must stop skipping.
            skip = False
            # Note: We don't add the 'return' line yet to avoid duplicates if we re-inject
            # However, simpler logic: just remove the block lines, keep the return.
            # Let's actually just keep the return line.
            new_lines.append(line) 
            continue
        # Otherwise, skip the line (part of the broken block)
        continue
    
    new_lines.append(line)

if found_marker:
    with open(filename, 'w') as f:
        f.writelines(new_lines)
    print("   ✅ Removed broken hook block.")
else:
    print("   ⚠️  Marker not found, assuming file is already clean.")

PYEOF

# ==============================================================================
# STEP 3: RE-INJECT HOOK CORRECTLY (At the very end)
# ==============================================================================
echo -e "${YELLOW}[Step 3/4] Re-injecting Hook at Function End...${NC}"

python3 << PYEOF
import re

filename = "$MAIN_FILE"

with open(filename, 'r') as f:
    content = f.read()

# Define the Hook Code with correct indentation (4 spaces)
hook_code = """    # --- MARKET READY PLUGIN ---
    # Hook: Execute Market Ready Extensions (Moats 4,8,9,10,13)
    # Placed at end of function to ensure 'signals' and 'result' are defined.
    execute_extensions(payload, signals, agent_state, result)

"""

# Find the LAST "return {" in the file.
# We assume the last return is the one we want.
# We insert the hook immediately before it.

parts = content.rsplit("return {", 1)

if len(parts) == 2:
    # Reconstruct: Part 1 (everything before return) + Hook + "return {" + Part 2
    new_content = parts[0] + hook_code + "return {" + parts[1]
    
    with open(filename, 'w') as f:
        f.write(new_content)
    
    print("   ✅ Hook injected before final return.")
else:
    print("   ❌ Could not find 'return {' to inject hook.")

PYEOF

# ==============================================================================
# STEP 4: RESTART
# ==============================================================================
echo -e "${YELLOW}[Step 4/4] Restarting System...${NC}"
docker-compose restart

echo -e "${YELLOW}Waiting for restart (10s)...${NC}"
sleep 10

# ==============================================================================
# VERIFY
# ==============================================================================
echo -e "\n${CYAN}================================================================================${NC}"
echo -e "${CYAN}  POST-SURGERY CHECK${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

curl -s http://127.0.0.1:8002/health

# Run a quick decide test to see if it crashes
echo -e "\n${YELLOW}Sending Test Request...${NC}"
TEST_RESPONSE=$(curl -s -X POST "http://127.0.0.1:8002/api/rtp/decide" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: REPLACE_WITH_YOUR_OPENAI_KEY" \
  -d '{"tool_name":"test","usage":{"tokens":10},"signals":{"consistency":0.9}}')

if echo "$TEST_RESPONSE" | grep -q "decision"; then
    echo -e "${GREEN}✅ SUCCESS: Request processed without crash.${NC}"
    # Check for keys
    if echo "$TEST_RESPONSE" | grep -q "atp_status"; then
        echo -e "${GREEN}✅ INTEGRATION CONFIRMED: New Moat keys found in response.${NC}"
    else
        echo -e "${RED}❌ DATA MISSING: Request processed but moats didn't run.${NC}"
    fi
else
    echo -e "${RED}❌ FAILED: Server returned error or crashed.${NC}"
fi

