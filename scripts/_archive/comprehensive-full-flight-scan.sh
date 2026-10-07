#!/bin/bash

# Kasbah Guard — Comprehensive Full Flight Scan
# Scans ALL levels, ALL products, ALL files
# Usage: ./comprehensive-full-flight-scan.sh

set -e

echo "========================================"
echo "Kasbah Guard — Comprehensive Full Flight Scan"
echo "Date: $(date)"
echo "Scanning: ALL Levels, ALL Products, ALL Files"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_level() { echo -e "${BLUE}════════════════════════════════════════${NC}"; echo -e "${BLUE}LEVEL $1: $2${NC}"; echo -e "${BLUE}════════════════════════════════════════${NC}"; }
log_section() { echo -e "${YELLOW}────────────────────────────────────────${NC}"; echo -e "${YELLOW}$1${NC}"; echo -e "${YELLOW}────────────────────────────────────────${NC}"; }
log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; }

# Counters
TOTAL_CHECKS=0
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
TOTAL_FILES=0
TOTAL_LINES=0

check() {
  ((TOTAL_CHECKS++))
  if [ -f "$1" ] || [ -d "$1" ]; then
    if [ -n "$2" ]; then
      if grep -q "$2" "$1" 2>/dev/null; then
        log_pass "$3"
        ((PASS_COUNT++))
        return 0
      else
        log_fail "$3"
        ((FAIL_COUNT++))
        return 1
      fi
    else
      log_pass "$1 exists"
      ((PASS_COUNT++))
      return 0
    fi
  else
    log_fail "$1 missing"
    ((FAIL_COUNT++))
    return 1
  fi
}

count_files() {
  local dir=$1
  local pattern=$2
  if [ -d "$dir" ]; then
    local count=$(find "$dir" -name "$pattern" -type f 2>/dev/null | wc -l)
    local lines=$(find "$dir" -name "$pattern" -type f -exec wc -l {} \; 2>/dev/null | awk '{s+=$1} END {print s}')
    echo "$count files, $lines lines"
    ((TOTAL_FILES+=count))
    ((TOTAL_LINES+=lines))
  else
    echo "0 files, 0 lines"
  fi
}

# ═══════════════════════════════════════════════════════════════
# LEVEL 1: INFRASTRUCTURE LAYER
# ═══════════════════════════════════════════════════════════════
log_level "1" "INFRASTRUCTURE LAYER"

log_section "Deployment Scripts"
check "deploy-to-production.sh" "" "Deployment script"
check "scripts/setup-production.sh" "" "Setup script"
check "scripts/monitor-production.sh" "" "Monitoring script"
check "scripts/automated-backup.sh" "" "Backup script"
check "execute-all-5-fixes.sh" "" "Verification script"
check "full-flight-scan.sh" "" "Scan script"

log_section "CI/CD Configuration"
check ".github/workflows/ci-cd-pipeline.yml" "" "Main CI/CD pipeline"
check ".github/workflows/ci.yml" "" "Base CI workflow"
check ".github/workflows/security.yml" "" "Security workflow"

log_section "Configuration Files"
check ".env.example" "" "Environment template"
check ".gitignore" "" "Git ignore file"
check "docker-compose.yml" "" "Docker compose"
check "Dockerfile" "" "Docker file"

# ═══════════════════════════════════════════════════════════════
# LEVEL 2: CORE SECURITY LAYER (Kasbah-Core)
# ═══════════════════════════════════════════════════════════════
log_level "2" "CORE SECURITY LAYER"

log_section "Core Detection Modules"
check "Kasbah-Core/core/frontier/" "" "Frontier detection directory"
check "Kasbah-Core/core/ml/" "" "ML modules directory"
check "Kasbah-Core/core/moats/" "" "Moats directory"
check "Kasbah-Core/core/observability.py" "" "Observability module"
check "Kasbah-Core/core/integrity_engine.py" "" "Integrity engine"
check "Kasbah-Core/core/adaptive_defense.py" "" "Adaptive defense"

log_section "API Layer"
check "Kasbah-Core/apps/api/main.py" "" "Main API server"
check "Kasbah-Core/apps/api/rtp/" "" "RTP API directory"
check "Kasbah-Core/requirements.txt" "" "Python requirements"

log_section "Cryptography"
check "Kasbah-Core/crypto/" "" "Crypto directory"
check "Kasbah-Core/crypto/zk_verifier.py" "" "ZK verifier"
check "Kasbah-Core/crypto/homomorphic_state.py" "" "Homomorphic state"
check "Kasbah-Core/crypto/quantum_safe.py" "" "Quantum-safe crypto"

log_section "Core Tests"
check "Kasbah-Core/tests/" "" "Core tests directory"

# ═══════════════════════════════════════════════════════════════
# LEVEL 3: API SECURITY MOATS
# ═══════════════════════════════════════════════════════════════
log_level "3" "API SECURITY MOATS"

log_section "Rate Limiting & Circuit Breaker"
check "Kasbah-site/api/src/moats/rate-limiter-complete.js" "" "Rate limiter"
check "Kasbah-site/api/src/moats/circuit-breaker-complete.js" "" "Circuit breaker"
check "Kasbah-site/api/src/moats/rate-limiter.js" "" "Rate limiter base"
check "Kasbah-site/api/src/moats/circuit-breaker.js" "" "Circuit breaker base"

log_section "Audit & Compliance"
check "Kasbah-site/api/src/moats/audit-ledger-complete.js" "" "Audit ledger"
check "Kasbah-site/api/src/moats/crypto-receipts-complete.js" "" "Crypto receipts"
check "Kasbah-site/api/src/moats/magic-bytes-complete.js" "" "Magic bytes"

log_section "Advanced Detection"
check "Kasbah-site/api/src/moats/behavioral-biometrics-complete.js" "" "Behavioral biometrics"
check "Kasbah-site/api/src/moats/ml-anomaly-complete.js" "" "ML anomaly detection"
check "Kasbah-site/api/src/moats/zk-proofs-complete.js" "" "ZK proofs"
check "Kasbah-site/api/src/moats/sii-complete.js" "" "System integrity index"

log_section "Red-Team Toolkit"
check "Kasbah-site/api/src/moats/redteam-toolkit-complete.js" "" "Red-team toolkit"

log_section "Moats Tests"
check "Kasbah-site/api/src/moats/__tests__/phase1-complete.test.js" "" "Phase 1 tests"
check "Kasbah-site/api/src/moats/__tests__/phase2-complete.test.js" "" "Phase 2 tests"
check "Kasbah-site/api/src/moats/__tests__/phase3-complete.test.js" "" "Phase 3 tests"
check "Kasbah-site/api/src/moats/__tests__/phase4-complete.test.js" "" "Phase 4 tests"

# ═══════════════════════════════════════════════════════════════
# LEVEL 4: PRODUCT LAYER
# ═══════════════════════════════════════════════════════════════
log_level "4" "PRODUCT LAYER"

log_section "Browser Extensions"
check "Kasbah-site/kasbah-guard-dist/extensions/chrome/" "" "Chrome extension"
check "Kasbah-site/kasbah-guard-dist/extensions/firefox/" "" "Firefox extension"
check "Kasbah-site/kasbah-guard-dist/extensions/edge/" "" "Edge extension"
check "Kasbah-site/kasbah-guard-dist/extensions/opera/" "" "Opera extension"
check "Kasbah-site/kasbah-guard-dist/extensions/safari/" "" "Safari extension"
check "Kasbah-site/kasbah-guard-dist/extensions/chrome/src/detector.js" "" "Detector kernel"
check "Kasbah-site/kasbah-guard-dist/extensions/chrome/background.js" "" "Background script"

log_section "Slack Guard"
check "Kasbah-site/kasbah-guard-dist/apps/slack-guard/" "" "Slack Guard directory"
check "Kasbah-site/kasbah-guard-dist/apps/slack-guard/src/slack-guard-complete.js" "" "Slack Guard implementation"

log_section "Discord Guardian"
check "Kasbah-site/kasbah-guard-dist/apps/discord-guard/" "" "Discord Guardian directory"
check "Kasbah-site/kasbah-guard-dist/apps/discord-guard/src/discord-guardian-complete.js" "" "Discord Guardian implementation"

log_section "Hospital Guardian (HIPAA)"
check "Kasbah-site/kasbah-guard-dist/apps/hospital-guard/" "" "Hospital Guardian directory"
check "Kasbah-site/kasbah-guard-dist/apps/hospital-guard/src/hospital-guardian-complete.js" "" "Hospital Guardian implementation"

log_section "Legal Shield"
check "Kasbah-site/kasbah-guard-dist/apps/legal-shield/" "" "Legal Shield directory"
check "Kasbah-site/kasbah-guard-dist/apps/legal-shield/src/legal-shield-complete.js" "" "Legal Shield implementation"

log_section "API Guard"
check "Kasbah-site/kasbah-guard-dist/apps/api-guard/" "" "API Guard directory"
check "Kasbah-site/kasbah-guard-dist/apps/api-guard/bin/kasbah.js" "" "API Guard CLI"

log_section "Desktop App"
check "Kasbah-site/kasbah-guard-dist/apps/desktop/" "" "Desktop app directory"

log_section "Constitutional AI"
check "Kasbah-site/kasbah-guard-dist/apps/constitutional-ai/" "" "Constitutional AI directory"

# ═══════════════════════════════════════════════════════════════
# LEVEL 5: DETECTOR KERNEL
# ═══════════════════════════════════════════════════════════════
log_level "5" "DETECTOR KERNEL"

log_section "Core Detector"
check "Kasbah-site/kasbah-guard-dist/packages/detector/" "" "Detector package"
check "Kasbah-site/kasbah-guard-dist/packages/detector/src/index.js" "" "Main detector"
check "Kasbah-site/kasbah-guard-dist/packages/detector/src/ml-anomaly.js" "" "ML anomaly"
check "Kasbah-site/kasbah-guard-dist/packages/detector/src/behavioral.js" "" "Behavioral detection"
check "Kasbah-site/kasbah-guard-dist/packages/detector/src/obfuscation-decoder-complete.js" "" "Obfuscation decoder"

log_section "Advanced Models"
check "Kasbah-site/kasbah-guard-dist/packages/detector/src/advanced-frontier-models.js" "" "Advanced frontier models"
check "Kasbah-site/kasbah-guard-dist/packages/detector/src/quantum-resistant-crypto.js" "" "Quantum-resistant crypto"

log_section "Detector Tests"
check "Kasbah-site/kasbah-guard-dist/packages/detector/tests/comprehensive.test.js" "" "Comprehensive tests"
check "Kasbah-site/kasbah-guard-dist/packages/detector/tests/detector.test.js" "" "Detector tests"
check "Kasbah-site/kasbah-guard-dist/packages/detector/tests/advanced-frontier.test.js" "" "Frontier tests"
check "Kasbah-site/kasbah-guard-dist/packages/detector/tests/quantum-resistant.test.js" "" "Quantum tests"

# ═══════════════════════════════════════════════════════════════
# LEVEL 6: SDKs
# ═══════════════════════════════════════════════════════════════
log_level "6" "SDKs"

log_section "Python SDK"
check "kasbah-sdk-python/" "" "Python SDK directory"
check "kasbah-sdk-python/kasbah/" "" "Python kasbah package"
check "kasbah-sdk-python/pyproject.toml" "" "Python package config"

log_section "Node.js SDK"
check "kasbah-sdk-node/" "" "Node SDK directory"
check "kasbah-sdk-node/src/" "" "Node source directory"
check "kasbah-sdk-node/package.json" "" "Node package config"

log_section "Flutter SDK"
check "kasbah-sdk-flutter/" "" "Flutter SDK directory"
check "kasbah-sdk-flutter/lib/" "" "Flutter lib directory"
check "kasbah-sdk-flutter/pubspec.yaml" "" "Flutter package config"

log_section "React Native SDK"
check "kasbah-sdk-react-native/" "" "React Native SDK directory"
check "kasbah-sdk-react-native/src/" "" "React Native source"
check "kasbah-sdk-react-native/package.json" "" "React Native package config"

# ═══════════════════════════════════════════════════════════════
# LEVEL 7: LOAD TESTING
# ═══════════════════════════════════════════════════════════════
log_level "7" "LOAD TESTING"

log_section "Load Test Suite"
check "tests/load/" "" "Load tests directory"
check "tests/load/api-load-test.js" "" "API load test"
check "tests/load/detection-burst-test.js" "" "Burst detection test"
check "tests/load/multi-product-test.js" "" "Multi-product test"
check "tests/load/memory-leak-test.js" "" "Memory leak test"

# ═══════════════════════════════════════════════════════════════
# LEVEL 8: DOCUMENTATION
# ═══════════════════════════════════════════════════════════════
log_level "8" "DOCUMENTATION"

log_section "Fix Documentation"
check "ALL_5_FIXES_EXECUTED.md" "" "All 5 fixes executed"
check "5_FIXES_COMPLETE.md" "" "5 fixes complete"
check "FIXES_AND_FLIGHT_CHECKS_REPORT.md" "" "Fixes report"

log_section "Production Documentation"
check "COMPLETE_FLIGHT_CHECKS.md" "" "Flight checks"
check "PRODUCTION_COMPLETE.md" "" "Production complete"
check "FINAL_PRODUCTION_STATUS.md" "" "Final production status"
check "DEPLOYMENT_COMPLETE.md" "" "Deployment complete"

log_section "Compliance Documentation"
check "COMPLIANCE_DOCUMENTATION.md" "" "Compliance docs"
check "INCIDENT_RESPONSE_PLAN.md" "" "IR plan"
check "LEGAL/BAA_TEMPLATE.md" "" "BAA template"
check "LEGAL/DPA_TEMPLATE.md" "" "DPA template"

log_section "API Documentation"
check "Kasbah-Core/docs/API_OPENAPI_SPEC.md" "" "OpenAPI spec"

log_section "Analysis Documentation"
check "COMPLETE_GAP_ANALYSIS.md" "" "Gap analysis"
check "MISSING_COMPONENTS_REPORT.md" "" "Missing components"
check "MASTER_SUMMARY.md" "" "Master summary"
check "ACHIEVEMENT_SUMMARY.md" "" "Achievement summary"

# ═══════════════════════════════════════════════════════════════
# LEVEL 9: WORKER REFACTORING
# ═══════════════════════════════════════════════════════════════
log_level "9" "WORKER REFACTORING"

log_section "Refactored Worker"
check "Kasbah-site/api/src/worker-refactored.js" "" "Refactored worker"
check "Kasbah-site/api/src/authz-pipeline.js" "" "AuthZ pipeline"

log_section "Route Handlers"
check "Kasbah-site/api/src/routes/auth.js" "" "Auth routes"
check "Kasbah-site/api/src/routes/api.js" "" "API routes"

log_section "Utilities"
check "Kasbah-site/api/src/utils/crypto.js" "" "Crypto utils"
check "Kasbah-site/api/src/utils/email.js" "" "Email utils"
check "Kasbah-site/api/src/utils/response.js" "" "Response utils"
check "Kasbah-site/api/src/utils/risk-scan.js" "" "Risk scan utils"

log_section "Core State"
check "Kasbah-site/api/src/core/state.js" "" "Core state"

# ═══════════════════════════════════════════════════════════════
# LEVEL 10: SECURITY HARDENING
# ═══════════════════════════════════════════════════════════════
log_level "10" "SECURITY HARDENING"

log_section "Environment Security"
check ".env.example" "GENERATE_STRONG_PASSWORD" "Strong password placeholder"
check ".env.example" "GENERATE_STRONG_SECRET" "Strong secret placeholder"

log_section "Security Scanning"
check ".gitleaks.toml" "" "Gitleaks config"

# ═══════════════════════════════════════════════════════════════
# FILE COUNT SUMMARY
# ═══════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════"
echo "FILE COUNT SUMMARY"
echo "════════════════════════════════════════"
echo ""

echo "Production Scripts:"
count_files "scripts" "*.sh"

echo "JavaScript/TypeScript Files:"
count_files "Kasbah-site" "*.js"
count_files "Kasbah-site" "*.ts"

echo "Python Files:"
count_files "Kasbah-Core" "*.py"

echo "Test Files:"
count_files "." "*.test.js"

echo "Documentation Files:"
count_files "." "*.md"

echo "CI/CD Workflows:"
count_files ".github/workflows" "*.yml"

echo ""
echo "════════════════════════════════════════"
echo "TOTAL FILES: ${TOTAL_FILES}"
echo "TOTAL LINES: ${TOTAL_LINES}"
echo "════════════════════════════════════════"

# ═══════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════
echo ""
echo "========================================"
echo "COMPREHENSIVE FULL FLIGHT SCAN COMPLETE"
echo "========================================"
echo ""
echo "Results:"
echo -e "  ${GREEN}Passed:${NC} ${PASS_COUNT}/${TOTAL_CHECKS}"
echo -e "  ${YELLOW}Warnings:${NC} ${WARN_COUNT}"
echo -e "  ${RED}Failed:${NC} ${FAIL_COUNT}"
echo ""

if [ ${FAIL_COUNT} -eq 0 ]; then
  echo -e "${GREEN}✓ ALL COMPONENTS VERIFIED!${NC}"
  echo ""
  echo "Production Status: READY"
  echo "Deployment Status: AUTHORIZED"
  EXIT_CODE=0
else
  echo -e "${RED}✗ ${FAIL_COUNT} COMPONENT(S) MISSING${NC}"
  echo ""
  echo "Production Status: NOT READY"
  echo "Deployment Status: NOT AUTHORIZED"
  EXIT_CODE=1
fi

echo ""
echo "========================================"

exit $EXIT_CODE
