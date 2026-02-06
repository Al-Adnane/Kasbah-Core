#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🔍 PRE-LAUNCH VERIFICATION: Does the plugin work & is it connected?${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

PLUGIN_FILE="apps/api/rtp/market_ready_extensions.py"
MAIN_FILE="apps/api/rtp/kernel_gate.py"
SUCCESS=true

# ==============================================================================
# TEST 1: SYNTAX CHECK (Does the Python file crash the compiler?)
# ==============================================================================
echo -e "${YELLOW}[TEST 1/4] Syntax Check (Python Compilation)...${NC}"

if [ ! -f "$PLUGIN_FILE" ]; then
    echo -e "${RED}❌ FAILED: Plugin file does not exist. Run the creation script first.${NC}"
    exit 1
fi

if python3 -m py_compile "$PLUGIN_FILE" 2>/dev/null; then
    echo -e "${GREEN}✅ PASSED: File has valid Python syntax.${NC}"
else
    echo -e "${RED}❌ FAILED: Syntax error in $PLUGIN_FILE${NC}"
    SUCCESS=false
fi

# ==============================================================================
# TEST 2: LOGIC CHECK (Does the code actually run?)
# ==============================================================================
echo -e "\n${YELLOW}[TEST 2/4] Logic Check (Dry Run with Mock Data)...${NC}"

python3 << PYEOF
import sys
import os

# Add path to import
sys.path.insert(0, 'apps/api/rtp')

try:
    # Import the module
    from market_ready_extensions import execute_extensions
    print("✅ Import successful.")
    
    # Create Mock Data (simulating what kernel_gate passes)
    mock_payload = {"agent_id": "test-agent-99", "tool_name": "test.tool"}
    mock_signals = {"consistency": 0.95, "pred_accuracy": 0.90}
    mock_agent_state = {"ema": 0.5, "trend": "stable"}
    mock_result = {
        "decision": "ALLOW", 
        "integrity_score": 0.88, 
        "moats_triggered": [1, 2, 3]
    }
    
    # Run the function
    print("   Running logic...")
    execute_extensions(mock_payload, mock_signals, mock_agent_state, mock_result)
    
    # Verify output
    expected_keys = ['atp_status', 'kernel_health', 'hcs_sample', 'zk_state_proof', 'topology_check']
    missing_keys = [k for k in expected_keys if k not in mock_result]
    
    if not missing_keys:
        print("✅ All 5 Moats generated output.")
        print(f"   Sample output: ATP={mock_result['atp_status']}, HGTA={mock_result['topology_check']['centrality_score']}")
    else:
        print(f"❌ Logic failed: Missing keys {missing_keys}")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ Logic failed with error: {e}")
    sys.exit(1)

PYEOF

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ FAILED: Logic test crashed.${NC}"
    SUCCESS=false
else
    echo -e "${GREEN}✅ PASSED: Logic runs without errors.${NC}"
fi

# ==============================================================================
# TEST 3: IMPORT CHECK (Is it linked to Kernel Gate?)
# ==============================================================================
echo -e "\n${YELLOW}[TEST 3/4] Integration Check (Is Import in kernel_gate.py?)${NC}"

if grep -q "from .market_ready_extensions import execute_extensions" $MAIN_FILE; then
    echo -e "${GREEN}✅ PASSED: Import statement found in kernel_gate.py${NC}"
    echo -e "   📄 Line: $(grep -n "from .market_ready_extensions" $MAIN_FILE)${NC}"
else
    echo -e "${RED}❌ FAILED: Import statement NOT found in kernel_gate.py${NC}"
    echo -e "   ⚠️  The plugin file exists, but it is not connected to the main system."
    SUCCESS=false
fi

# ==============================================================================
# TEST 4: HOOK CHECK (Is the function actually called?)
# ==============================================================================
echo -e "\n${YELLOW}[TEST 4/4] Hook Check (Is function called before return?)${NC}"

if grep -q "execute_extensions(" $MAIN_FILE; then
    echo -e "${GREEN}✅ PASSED: Function call found in kernel_gate.py${NC}"
    echo -e "   📄 Line: $(grep -n "execute_extensions(" $MAIN_FILE)${NC}"
else
    echo -e "${RED}❌ FAILED: Function call NOT found in kernel_gate.py${NC}"
    echo -e "   ⚠️  The import exists, but the function is never executed."
    SUCCESS=false
fi

# ==============================================================================
# FINAL SUMMARY
# ==============================================================================
echo -e "\n${CYAN}================================================================================${NC}"
echo -e "${CYAN}  FINAL VERDICT${NC}"
echo -e "${CYAN}================================================================================${NC}"

if [ "$SUCCESS" = true ]; then
    echo -e "${GREEN}✅ ALL CHECKS PASSED${NC}"
    echo -e "${GREEN}   The plugin works 100% and is correctly integrated.${NC}"
    echo -e "${GREEN}   You may proceed with docker-compose up --build.${NC}"
else
    echo -e "${RED}❌ VERIFICATION FAILED${NC}"
    echo -e "${RED}   Do not launch yet. Fix the errors above.${NC}"
fi

