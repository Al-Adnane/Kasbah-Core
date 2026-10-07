#!/bin/bash

# Kasbah Guard — Full Flight-Wide Scan
# Comprehensive scan for missing components
# Usage: ./full-flight-scan.sh

set -e

echo "========================================"
echo "Kasbah Guard — Full Flight-Wide Scan"
echo "Date: $(date)"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_check() { echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; }

MISSING_COMPONENTS=()
WARNING_COMPONENTS=()
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

check_file() {
  if [ -f "$1" ]; then
    log_pass "Found: $1"
    ((PASS_COUNT++))
  else
    log_fail "Missing: $1"
    MISSING_COMPONENTS+=("$1")
    ((FAIL_COUNT++))
  fi
}

check_dir() {
  if [ -d "$1" ]; then
    log_pass "Found: $1"
    ((PASS_COUNT++))
  else
    log_fail "Missing: $1"
    MISSING_COMPONENTS+=("$1")
    ((FAIL_COUNT++))
  fi
}

check_executable() {
  if [ -x "$1" ]; then
    log_pass "Executable: $1"
    ((PASS_COUNT++))
  else
    log_warn "Not executable: $1"
    WARNING_COMPONENTS+=("$1 (not executable)")
    ((WARN_COUNT++))
  fi
}

check_content() {
  if grep -q "$2" "$1" 2>/dev/null; then
    log_pass "$1 contains: $2"
    ((PASS_COUNT++))
  else
    log_fail "$1 missing: $2"
    MISSING_COMPONENTS+=("$1: $2")
    ((FAIL_COUNT++))
  fi
}

# Scan 1: Core Production Files
log_check "Scan 1: Core Production Files"

check_file "deploy-to-production.sh"
check_file "scripts/setup-production.sh"
check_file "scripts/monitor-production.sh"
check_file "scripts/automated-backup.sh"
check_executable "deploy-to-production.sh"
check_executable "scripts/setup-production.sh"
check_executable "scripts/monitor-production.sh"
check_executable "scripts/automated-backup.sh"

# Scan 2: CI/CD Pipeline
log_check "Scan 2: CI/CD Pipeline"

check_file ".github/workflows/ci-cd-pipeline.yml"
check_content ".github/workflows/ci-cd-pipeline.yml" "name: Kasbah Guard"
check_content ".github/workflows/ci-cd-pipeline.yml" "test-unit"
check_content ".github/workflows/ci-cd-pipeline.yml" "deploy-production"

# Scan 3: Load Tests
log_check "Scan 3: Load Testing Suite"

check_dir "tests/load"
check_file "tests/load/api-load-test.js"
check_file "tests/load/detection-burst-test.js"
check_file "tests/load/multi-product-test.js"
check_file "tests/load/memory-leak-test.js"

# Scan 4: Documentation
log_check "Scan 4: Documentation"

check_file "ALL_5_FIXES_EXECUTED.md"
check_file "5_FIXES_COMPLETE.md"
check_file "COMPLETE_FLIGHT_CHECKS.md"
check_file "COMPLIANCE_DOCUMENTATION.md"
check_file "API_OPENAPI_SPEC.md"
check_file "INCIDENT_RESPONSE_PLAN.md"
check_file "PRODUCTION_COMPLETE.md"

# Scan 5: API Security Layer
log_check "Scan 5: API Security Layer"

check_file "Kasbah-site/api/src/moats/rate-limiter-complete.js"
check_file "Kasbah-site/api/src/moats/circuit-breaker-complete.js"
check_file "Kasbah-site/api/src/moats/magic-bytes-complete.js"
check_file "Kasbah-site/api/src/moats/audit-ledger-complete.js"
check_file "Kasbah-site/api/src/moats/crypto-receipts-complete.js"
check_file "Kasbah-site/api/src/moats/redteam-toolkit-complete.js"
check_file "Kasbah-site/api/src/moats/sii-complete.js"

# Scan 6: Advanced Detection
log_check "Scan 6: Advanced Detection"

check_file "Kasbah-site/api/src/moats/behavioral-biometrics-complete.js"
check_file "Kasbah-site/api/src/moats/ml-anomaly-complete.js"
check_file "Kasbah-site/api/src/moats/zk-proofs-complete.js"
check_file "Kasbah-site/kasbah-guard-dist/packages/detector/src/advanced-frontier-models.js"
check_file "Kasbah-site/kasbah-guard-dist/packages/detector/src/quantum-resistant-crypto.js"

# Scan 7: Product Implementations
log_check "Scan 7: Product Implementations"

check_file "Kasbah-site/kasbah-guard-dist/apps/slack-guard/src/slack-guard-complete.js"
check_file "Kasbah-site/kasbah-guard-dist/apps/discord-guard/src/discord-guardian-complete.js"
check_file "Kasbah-site/kasbah-guard-dist/apps/hospital-guard/src/hospital-guardian-complete.js"
check_file "Kasbah-site/kasbah-guard-dist/apps/legal-shield/src/legal-shield-complete.js"

# Scan 8: Test Suite
log_check "Scan 8: Test Suite"

check_file "Kasbah-site/api/src/moats/__tests__/phase1-complete.test.js"
check_file "Kasbah-site/api/src/moats/__tests__/phase2-complete.test.js"
check_file "Kasbah-site/api/src/moats/__tests__/phase3-complete.test.js"
check_file "Kasbah-site/api/src/moats/__tests__/phase4-complete.test.js"
check_file "Kasbah-site/kasbah-guard-dist/apps/__tests__/phase5-products.test.js"
check_file "Kasbah-site/kasbah-guard-dist/packages/detector/tests/advanced-frontier.test.js"
check_file "Kasbah-site/kasbah-guard-dist/packages/detector/tests/quantum-resistant.test.js"

# Scan 9: Worker Refactoring
log_check "Scan 9: Worker Refactoring"

check_file "Kasbah-site/api/src/worker-refactored.js"
check_file "Kasbah-site/api/src/routes/auth.js"
check_file "Kasbah-site/api/src/routes/api.js"
check_file "Kasbah-site/api/src/utils/crypto.js"
check_file "Kasbah-site/api/src/utils/email.js"
check_file "Kasbah-site/api/src/utils/response.js"
check_file "Kasbah-site/api/src/authz-pipeline.js"

# Scan 10: Security Hardening
log_check "Scan 10: Security Hardening"

check_file ".env.example"
check_content ".env.example" "GENERATE_STRONG_PASSWORD"
check_content ".env.example" "GENERATE_STRONG_SECRET"

# Scan 11: Observability
log_check "Scan 11: Observability Stack"

check_file "Kasbah-Core/core/observability.py"
check_content "Kasbah-Core/core/observability.py" "MetricsCollector"
check_content "Kasbah-Core/core/observability.py" "Tracer"
check_content "Kasbah-Core/core/observability.py" "AlertManager"

# Scan 12: Browser Extensions
log_check "Scan 12: Browser Extensions"

check_dir "Kasbah-site/kasbah-guard-dist/extensions/chrome"
check_dir "Kasbah-site/kasbah-guard-dist/extensions/firefox"
check_dir "Kasbah-site/kasbah-guard-dist/extensions/edge"
check_file "Kasbah-site/kasbah-guard-dist/extensions/chrome/src/detector.js"
check_file "Kasbah-site/kasbah-guard-dist/extensions/chrome/background.js"

# Scan 13: SDKs
log_check "Scan 13: SDKs"

check_dir "kasbah-sdk-python"
check_dir "kasbah-sdk-node"
check_dir "kasbah-sdk-flutter"
check_dir "kasbah-sdk-react-native"

# Scan 14: Kasbah-Core
log_check "Scan 14: Kasbah-Core Backend"

check_dir "Kasbah-Core/core"
check_dir "Kasbah-Core/apps/api"
check_file "Kasbah-Core/apps/api/main.py"
check_file "Kasbah-Core/requirements.txt"

# Scan 15: Compliance
log_check "Scan 15: Compliance"

check_file "LEGAL/BAA_TEMPLATE.md"
check_file "LEGAL/DPA_TEMPLATE.md"

# Summary
echo ""
echo "========================================"
echo "Full Flight-Wide Scan Complete"
echo "========================================"
echo ""
echo "Results:"
echo -e "  ${GREEN}Passed:${NC} ${PASS_COUNT}"
echo -e "  ${YELLOW}Warnings:${NC} ${WARN_COUNT}"
echo -e "  ${RED}Failed:${NC} ${FAIL_COUNT}"
echo ""

if [ ${FAIL_COUNT} -eq 0 ]; then
  echo -e "${GREEN}✓ All critical components present!${NC}"
  EXIT_CODE=0
else
  echo -e "${RED}✗ Missing ${FAIL_COUNT} critical component(s)${NC}"
  echo ""
  echo "Missing Components:"
  for component in "${MISSING_COMPONENTS[@]}"; do
    echo -e "  ${RED}✗${NC} ${component}"
  done
  EXIT_CODE=1
fi

if [ ${WARN_COUNT} -gt 0 ]; then
  echo ""
  echo "Warnings:"
  for warning in "${WARNING_COMPONENTS[@]}"; do
    echo -e "  ${YELLOW}⚠${NC} ${warning}"
  done
fi

echo ""
echo "========================================"

exit $EXIT_CODE
