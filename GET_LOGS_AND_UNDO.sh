#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  🚑 EMERGENCY DIAGNOSTIC: Check Logs & Undo if Broken${NC}"
echo -e "${CYAN}================================================================================${NC}\n"

# ==============================================================================
# STEP 1: GET LOGS
# ==============================================================================
echo -e "${YELLOW}[Step 1] Fetching latest Error Logs...${NC}"
echo -e "   ----------------------------------------"
docker logs kasbah-core-api-1 2>&1 | grep -A 10 "Traceback\|Error\|Exception" | tail -20
echo -e "   ----------------------------------------"

# ==============================================================================
# STEP 2: CHECK END OF FILE (Visual Inspection)
# ==============================================================================
echo -e "\n${YELLOW}[Step 2] Showing last 10 lines of kernel_gate.py...${NC}"
echo -e "   (Check if the hook looks broken here)"
echo -e "   ----------------------------------------"
tail -10 apps/api/rtp/kernel_gate.py
echo -e "   ----------------------------------------"

# ==============================================================================
# STEP 3: UNDO OPTION
# ==============================================================================
echo -e "\n${RED}The system seems unstable. Do you want to restore the backup?${NC}"
echo -e "${YELLOW}This will revert kernel_gate.py to the state before the last modification.${NC}"
read -p "Type 'yes' to restore backup: " CONFIRM

if [ "$CONFIRM" = "yes" ]; then
    if [ -f "apps/api/rtp/kernel_gate.py.surgical_backup" ]; then
        echo -e "${YELLOW}Restoring backup...${NC}"
        cp apps/api/rtp/kernel_gate.py.surgical_backup apps/api/rtp/kernel_gate.py
        
        echo -e "${YELLOW}Removing the plugin hook logic from file...${NC}"
        # Remove the import line
        sed -i.tmp '/from .market_ready_extensions import execute_extensions/d' apps/api/rtp/kernel_gate.py
        rm apps/api/rtp/kernel_gate.py.tmp
        
        echo -e "${YELLOW}Restarting...${NC}"
        docker-compose restart
        sleep 5
        
        echo -e "${GREEN}✅ System restored to previous working state.${NC}"
        curl -s http://127.0.0.1:8002/health
    else
        echo -e "${RED}❌ Backup file not found!${NC}"
    fi
else
    echo -e "${YELLOW}No changes made. Please investigate the logs above manually.${NC}"
fi

