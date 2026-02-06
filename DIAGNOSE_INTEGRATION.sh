#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🔬 FORENSIC DIAGNOSTIC: Why are Moats missing?${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

MAIN_FILE="apps/api/rtp/kernel_gate.py"

# ==============================================================================
# CHECK 1: DOES THE IMPORT EXIST?
# ==============================================================================
echo -e "${YELLOW}[CHECK 1] Looking for Import Statement...${NC}"

if grep -q "from .market_ready_extensions import execute_extensions" $MAIN_FILE; then
    echo -e "${GREEN}✅ FOUND: Import statement exists.${NC}"
    echo -e "   Line: $(grep -n "from .market_ready_extensions" $MAIN_FILE)"
else
    echo -e "${RED}❌ MISSING: Import statement NOT found.${NC}"
    echo -e "   The plugin file exists, but kernel_gate.py doesn't know about it."
fi

# ==============================================================================
# CHECK 2: DOES THE HOOK EXIST?
# ==============================================================================
echo -e "\n${YELLOW}[CHECK 2] Looking for Function Call (Hook)...${NC}"

if grep -q "execute_extensions(" $MAIN_FILE; then
    echo -e "${GREEN}✅ FOUND: Function call exists.${NC}"
    echo -e "   Line(s): $(grep -n "execute_extensions(" $MAIN_FILE)"
else
    echo -e "${RED}❌ MISSING: Function call NOT found.${NC}"
    echo -e "   The code is imported, but never executed."
fi

# ==============================================================================
# CHECK 3: IS IT IN THE RIGHT PLACE? (Context Check)
# ==============================================================================
echo -e "\n${YELLOW}[CHECK 3] Checking Context (Where is the hook?)${NC}"

# We extract 5 lines before and after the hook to show context
echo -e "   Snippet from $MAIN_FILE:"
echo -e "   -----------------------------------------"
grep -B 5 -A 5 "execute_extensions(" $MAIN_FILE || echo "   (No hook found)"
echo -e "   -----------------------------------------"

# ==============================================================================
# CHECK 4: DOES THE PLUGIN FILE EXIST?
# ==============================================================================
echo -e "\n${YELLOW}[CHECK 4] Verifying Plugin File Integrity...${NC}"

if [ -f "apps/api/rtp/market_ready_extensions.py" ]; then
    echo -e "${GREEN}✅ File exists.${NC}"
    # Quick syntax check
    if python3 -m py_compile "apps/api/rtp/market_ready_extensions.py" 2>/dev/null; then
        echo -e "${GREEN}   ✅ Syntax is valid.${NC}"
    else
        echo -e "${RED}   ❌ Syntax error in plugin file.${NC}"
    fi
else
    echo -e "${RED}❌ File does not exist.${NC}"
fi

# ==============================================================================
# CHECK 5: DOCKER LOGS (Did it crash?)
# ==============================================================================
echo -e "\n${YELLOW}[CHECK 5] Checking Docker Logs for Crashes...${NC}"

if docker logs kasbah-core-api-1 2>&1 | grep -i "import\|error\|traceback" | tail -5; then
    echo -e "${YELLOW}   ⚠️  Recent errors found in logs (shown above).${NC}"
else
    echo -e "${GREEN}   ✅ No obvious import errors in recent logs.${NC}"
fi

# ==============================================================================
# VERDICT
# ==============================================================================
echo -e "\n${CYAN}================================================================================${NC}"
echo -e "${CYAN}  DIAGNOSTIC VERDICT${NC}"
echo -e "${CYAN}================================================================================${NC}"

IMPORT_FOUND=$(grep -c "from .market_ready_extensions import execute_extensions" $MAIN_FILE || echo 0)
HOOK_FOUND=$(grep -c "execute_extensions(" $MAIN_FILE || echo 0)

if [ "$IMPORT_FOUND" -eq 0 ]; then
    echo -e "${RED}❌ ISSUE: The Import is missing. The script failed to inject it.${NC}"
    echo -e "${YELLOW}   NEXT STEP: Manually add 'from .market_ready_extensions import execute_extensions' to the top of kernel_gate.py${NC}"
elif [ "$HOOK_FOUND" -eq 0 ]; then
    echo -e "${RED}❌ ISSUE: The Hook is missing. The script failed to inject it.${NC}"
    echo -e "${YELLOW}   NEXT STEP: Manually add 'execute_extensions(payload, signals, agent_state, result)' before the return statement in decide().${NC}"
else
    echo -e "${RED}❌ ISSUE: Both Import and Hook exist, but Moats are still missing.${NC}"
    echo -e "${YELLOW}   LIKELY CAUSE: Indentation error (wrong number of spaces) or Hook is placed after 'return'.${NC}"
    echo -e "${YELLOW}   NEXT STEP: Check the 'Snippet' above. Ensure 'execute_extensions' is called BEFORE the final 'return {' and is indented exactly 4 spaces.${NC}"
fi

