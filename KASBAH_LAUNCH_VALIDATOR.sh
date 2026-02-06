#!/bin/bash

# ==============================================================================
# 🏰 KASBAH CORE - PRODUCT LAUNCH VALIDATOR
# "The Mother of All Tests"
# Tests 13 Moats, API Integration, and Code Completeness
# ==============================================================================

set -e # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "\n${CYAN}================================================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}================================================================================${NC}\n"
}

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_fail() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

# ==============================================================================
# PHASE 1: ENVIRONMENT BOOTSTRAP
# ==============================================================================
print_header "PHASE 1: ENVIRONMENT & DEPENDENCY CHECK"

# Check Python
if ! command -v python3 &> /dev/null; then
    print_fail "Python 3 is not installed. Aborting."
    exit 1
else
    print_success "Python 3 found: $(python3 --version)"
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    print_fail "Docker is not installed. Aborting."
    exit 1
else
    print_success "Docker found."
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_fail "Docker Compose is not installed. Aborting."
    exit 1
else
    print_success "Docker Compose found."
fi

# Install Python dependencies if missing
print_info "Checking Python dependencies (requests, pyyaml)..."
if ! python3 -c "import requests, yaml" 2>/dev/null; then
    print_warning "Missing Python libs. Installing via pip..."
    pip3 install requests pyyaml 2>/dev/null || pip install requests pyyaml
fi

# ==============================================================================
# PHASE 2: SYSTEM STARTUP
# ==============================================================================
print_header "PHASE 2: BOOTING KASBAH CORE SYSTEM"

if [ -f "docker-compose.yml" ]; then
    print_info "Stopping old containers..."
    docker-compose down 2>/dev/null || true
    
    print_info "Building and starting Kasbah Core..."
    docker-compose up -d --build
    
    print_info "Waiting for API to initialize (20s)..."
    sleep 20
    
    # Health Check
    if curl -s http://127.0.0.1:8002/health > /dev/null 2>&1; then
        print_success "System is ONLINE and Healthy."
    else
        print_fail "System failed to start or not healthy. Check logs: docker-compose logs"
        exit 1
    fi
else
    print_fail "docker-compose.yml not found in current directory."
    exit 1
fi

# ==============================================================================
# PHASE 3: DEEP CODE AUDIT (STATIC ANALYSIS)
# ==============================================================================
print_header "PHASE 3: STATIC CODE AUDIT (13 MOATS)"

python3 << 'PYTHON_SCRIPT'
import os
import ast
import re
import sys

class MoatAuditor:
    def __init__(self, base_path="apps/api/rtp"):
        self.base_path = base_path
        self.results = []
        
        # Define the 13 Moats with specific detection rules
        self.moats = [
            {
                "id": 1, "name": "Bidirectional Feedback", 
                "files": ["kernel_gate.py"], 
                "keywords": ["I(t)", "integrity_index", "threshold", "feedback"],
                "logic": "Check for dynamic threshold adjustment based on integrity"
            },
            {
                "id": 2, "name": "Geometric Mean Integrity",
                "files": ["integrity.py", "kernel_gate.py"],
                "keywords": ["geometric_mean", "geometric_integrity", "weighted"],
                "logic": "Check geometric mean calculation"
            },
            {
                "id": 3, "name": "QIFT (Anticipatory Transform)",
                "files": ["signals.py", "transform.py", "kernel_gate.py"],
                "keywords": ["orthogonal", "rotation", "QIFT", "transform"],
                "logic": "Check for feature rotation logic"
            },
            {
                "id": 4, "name": "Adversarial Training (ATP)",
                "files": ["*.py"], # Search everywhere
                "keywords": ["adversarial", "FGSM", "PGD", "perturbation"],
                "logic": "Search for adversarial example generation"
            },
            {
                "id": 5, "name": "Crypto Command Binding (CCB)",
                "files": ["kernel_gate.py", "crypto.py"],
                "keywords": ["sign", "ed25519", "signature", "verify"],
                "logic": "Check for signing of commands"
            },
            {
                "id": 6, "name": "MoE Horizon Fusion",
                "files": ["*.py"],
                "keywords": ["mixture", "expert", "LSTM", "Transformer", "fusion"],
                "logic": "Check for ML model ensemble logic"
            },
            {
                "id": 7, "name": "Merkle Integrity Ledger",
                "files": ["audit.py"],
                "keywords": ["merkle", "tree", "root_hash", "incremental"],
                "logic": "Check for Merkle tree in audit"
            },
            {
                "id": 8, "name": "Self-Rewriting Kernel",
                "files": ["*.py"],
                "keywords": ["genetic", "rewrite", "evolve", "patch"],
                "logic": "Search for self-modifying code logic"
            },
            {
                "id": 9, "name": "Homomorphic State",
                "files": ["*.py"],
                "keywords": ["homomorphic", "paillier", "encrypted_computation"],
                "logic": "Search for privacy-preserving crypto"
            },
            {
                "id": 10, "name": "Verifiable State Machine",
                "files": ["*.py"],
                "keywords": ["zk-snark", "zero_knowledge", "verifiable", "proof"],
                "logic": "Search for ZK proof verification"
            },
            {
                "id": 11, "name": "Thermodynamic Defense",
                "files": ["*.py"],
                "keywords": ["entropy", "power", "thermodynamic", "scaling"],
                "logic": "Search for entropy-based resource management"
            },
            {
                "id": 12, "name": "Sovereign Reputation",
                "files": ["*.py"],
                "keywords": ["reputation", "sovereign", "identity", "ledger"],
                "logic": "Search for reputation scoring"
            },
            {
                "id": 13, "name": "Hyper-Graph Topology",
                "files": ["*.py"],
                "keywords": ["hypergraph", "topology", "networkx", "graph"],
                "logic": "Search for network topology analysis"
            }
        ]

    def check_file(self, filepath):
        if not os.path.exists(filepath):
            return None
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()

    def check_keywords(self, content, keywords):
        if not content: return []
        found = []
        content_lower = content.lower()
        for kw in keywords:
            if kw.lower() in content_lower:
                found.append(kw)
        return found

    def audit(self):
        print(f"{'ID':<3} | {'Moat Name':<30} | {'Status':<10} | {'Details'}")
        print("-" * 80)
        
        for moat in self.moats:
            status = "NOT FOUND"
            details = "No code detected"
            files_checked = []
            
            # Check specific files
            files_to_check = moat['files']
            
            if "*.py" in files_to_check:
                # Search all files in rtp
                for root, dirs, files in os.walk(self.base_path):
                    for file in files:
                        if file.endswith(".py"):
                            files_to_check.append(os.path.join(root, file))

            # Remove duplicates and wildcards
            files_to_check = list(set([f for f in files_to_check if "*" not in f]))

            for fpath in files_to_check:
                # Handle relative paths
                full_path = fpath if os.path.isabs(fpath) else os.path.join(self.base_path, fpath)
                if not os.path.exists(full_path):
                    # Try finding it by name if path fails
                    if os.path.exists(os.path.join("apps/api/rtp", os.path.basename(fpath))):
                        full_path = os.path.join("apps/api/rtp", os.path.basename(fpath))
                    else:
                        continue
                
                content = self.check_file(full_path)
                if content:
                    found_kws = self.check_keywords(content, moat['keywords'])
                    if found_kws:
                        status = "PRESENT"
                        details = f"Found: {', '.join(found_kws[:3])}"
                        files_checked.append(os.path.basename(fpath))
                        break # Found in one file is enough
            
            # Special check for integration (is it used in kernel_gate?)
            if status == "PRESENT":
                kg_content = self.check_file(os.path.join(self.base_path, "kernel_gate.py"))
                if kg_content:
                    # Simple heuristic: check if a keyword appears in kernel_gate
                    if any(k.lower() in kg_content.lower() for k in moat['keywords'][:2]):
                        status = "INTEGRATED"
                    else:
                        status = "ISOLATED"
                        details += " (Not in KernelGate)"

            color_code = "\033[92m" if status == "INTEGRATED" else "\033[93m" if status == "PRESENT" else "\033[91m"
            reset_code = "\033[0m"
            
            print(f"{moat['id']:<3} | {moat['name']:<30} | {color_code}{status:<10}{reset_code} | {details}")
            self.results.append({"moat": moat['name'], "status": status})

auditor = MoatAuditor()
auditor.audit()
PYTHON_SCRIPT

# ==============================================================================
# PHASE 4: DYNAMIC INTEGRATION TEST
# ==============================================================================
print_header "PHASE 4: DYNAMIC API INTEGRATION TEST"

# Test 1: Health Endpoint
print_info "Test 1: GET /health"
HEALTH_RESPONSE=$(curl -s http://127.0.0.1:8002/health)
if echo "$HEALTH_RESPONSE" | grep -q "ok\|status"; then
    print_success "Health endpoint responding."
    echo "   Response: $HEALTH_RESPONSE"
else
    print_fail "Health endpoint failed."
    echo "   Response: $HEALTH_RESPONSE"
fi

echo ""

# Test 2: Decide Endpoint (The Core Logic)
print_info "Test 2: POST /api/rtp/decide"
PAYLOAD='{
  "tool_name": "read.file",
  "usage": {"tokens": 150, "cost": 0.05, "agent_id": "test-agent-01"},
  "signals": {
    "consistency": 0.85,
    "pred_accuracy": 0.90,
    "normality": 0.80
  }
}'

DECIDE_RESPONSE=$(curl -s -X POST http://127.0.0.1:8002/api/rtp/decide \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "   Payload: Tool=read.file, Integrity=0.85"
echo "   Response: $DECIDE_RESPONSE"

# Validate Response
if echo "$DECIDE_RESPONSE" | grep -q "decision"; then
    print_success "Decision endpoint working."
    
    # Check for Ticket Generation (Moat 5)
    if echo "$DECIDE_RESPONSE" | grep -q "ticket"; then
        print_success "   -> Ticket Generated (Moat 5 Active)"
    else
        print_warning "   -> No Ticket found (Moat 5 Inactive)"
    fi

    # Check for Audit ID
    if echo "$DECIDE_RESPONSE" | grep -q "audit_id\|log_id"; then
        print_success "   -> Audit Linked (Moat 7 Active)"
    else
        print_warning "   -> No Audit Link found (Moat 7 Inactive)"
    fi
else
    print_fail "Decision endpoint failed to return decision."
fi

echo ""

# Test 3: Audit Retrieval
print_info "Test 3: GET /api/rtp/audit (Verify Ledger)"
AUDIT_RESPONSE=$(curl -s "http://127.0.0.1:8002/api/rtp/audit?limit=1")

if echo "$AUDIT_RESPONSE" | grep -q "log\|entry"; then
    print_success "Audit Ledger is accessible."
    # Check for Merkle Root in audit (Moat 7)
    if echo "$AUDIT_RESPONSE" | grep -qi "merkle\|hash\|root"; then
        print_success "   -> Merkle/Hash fields present (Moat 7 Structure)"
    else
        print_warning "   -> Basic Audit, Merkle structure unclear."
    fi
else
    print_fail "Audit Ledger is inaccessible."
fi

# ==============================================================================
# PHASE 5: FINAL LAUNCH VERDICT
# ==============================================================================
print_header "FINAL LAUNCH VERDICT"

echo "Please review the outputs above carefully."
echo ""
echo "CRITICAL CHECKLIST FOR LAUNCH:"
echo "1. Are all 13 Moats marked 'INTEGRATED' or at least 'PRESENT'?"
echo "2. Did the /api/rtp/decide test return a 'decision'?"
echo "3. Was a 'ticket' generated in the response?"
echo "4. Is the Audit Ledger returning data?"
echo ""
echo "If any of the above are RED, DO NOT LAUNCH."
echo "Fix the specific Moat or API issue and re-run this script."

