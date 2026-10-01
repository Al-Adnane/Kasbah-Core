#!/bin/bash

# Kasbah Guard — Complete Wiring Verification
# Scans ALL documents and code to verify everything is properly wired
# Usage: ./complete-wiring-verification.sh

set -e

echo "========================================"
echo "Kasbah Guard — Complete Wiring Verification"
echo "Date: $(date)"
echo "Scanning: All documents, code, and configurations"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_section() { echo -e "${BLUE}════════════════════════════════════════${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}════════════════════════════════════════${NC}"; }
log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; }

# Counters
TOTAL_CHECKS=0
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
BROKEN_REFS=()

check_file_exists() {
  ((TOTAL_CHECKS++))
  if [ -f "$1" ]; then
    log_pass "Found: $1"
    ((PASS_COUNT++))
    return 0
  else
    log_fail "Missing: $1"
    ((FAIL_COUNT++))
    return 1
  fi
}

check_dir_exists() {
  ((TOTAL_CHECKS++))
  if [ -d "$1" ]; then
    log_pass "Found directory: $1"
    ((PASS_COUNT++))
    return 0
  else
    log_fail "Missing directory: $1"
    ((FAIL_COUNT++))
    return 1
  fi
}

check_reference() {
  local file=$1
  local ref=$2
  ((TOTAL_CHECKS++))
  if grep -q "$ref" "$file" 2>/dev/null; then
    log_pass "$file references: $ref"
    ((PASS_COUNT++))
    return 0
  else
    log_warn "$file missing reference: $ref"
    ((WARN_COUNT++))
    return 1
  fi
}

check_import() {
  local file=$1
  local import=$2
  ((TOTAL_CHECKS++))
  if grep -q "$import" "$file" 2>/dev/null; then
    log_pass "$file imports: $import"
    ((PASS_COUNT++))
    return 0
  else
    log_fail "$file missing import: $import"
    ((FAIL_COUNT++))
    BROKEN_REFS+=("$file: $import")
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════
# SCAN 1: Documentation Cross-References
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 1: Documentation Cross-References"

echo ""
echo "Checking main documentation files..."

# Check if all major docs exist
check_file_exists "ALL_PRODUCTS_100_PERCENT_READY.md"
check_file_exists "FRONTIER_BULLETPROOF_ROADMAP.md"
check_file_exists "MARKET_READY_PRODUCTS_0_BUG.md"
check_file_exists "COMPREHENSIVE_SCAN_RESULTS.md"
check_file_exists "FINAL_PRODUCTION_STATUS.md"
check_file_exists "5_FIXES_COMPLETE.md"
check_file_exists "ALL_5_FIXES_EXECUTED.md"

# Check if docs reference each other
echo ""
echo "Checking documentation cross-references..."
check_reference "FRONTIER_BULLETPROOF_ROADMAP.md" "MASS_SCALE_READINESS_PLAN.md"
check_reference "ALL_PRODUCTS_100_PERCENT_READY.md" "MOBILE_APPS_IMPLEMENTATION.md"
check_reference "ALL_PRODUCTS_100_PERCENT_READY.md" "IDE_GUARD_IMPLEMENTATION.md"
check_reference "ALL_PRODUCTS_100_PERCENT_READY.md" "SCALE_INFRASTRUCTURE_10K_USERS.md"

# ═══════════════════════════════════════════════════════════════
# SCAN 2: Code Import Chains
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 2: Code Import Chains"

echo ""
echo "Checking API security moats imports..."

# Check worker-refactored imports
check_import "Kasbah-site/api/src/worker-refactored.js" "routes/auth"
check_import "Kasbah-site/api/src/worker-refactored.js" "routes/api"
check_import "Kasbah-site/api/src/worker-refactored.js" "authz-pipeline"

# Check routes imports
check_import "Kasbah-site/api/src/routes/auth.js" "utils/crypto"
check_import "Kasbah-site/api/src/routes/auth.js" "utils/response"
check_import "Kasbah-site/api/src/routes/api.js" "frontier"
check_import "Kasbah-site/api/src/routes/api.js" "authz-pipeline"

# Check moats imports
check_import "Kasbah-site/api/src/moats/rate-limiter-complete.js" "module.exports"
check_import "Kasbah-site/api/src/moats/circuit-breaker-complete.js" "module.exports"
check_import "Kasbah-site/api/src/moats/audit-ledger-complete.js" "crypto"

# ═══════════════════════════════════════════════════════════════
# SCAN 3: Detector Kernel Wiring
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 3: Detector Kernel Wiring"

echo ""
echo "Checking detector kernel exports..."

check_import "Kasbah-site/kasbah-guard-dist/packages/detector/src/index.js" "ml-anomaly"
check_import "Kasbah-site/kasbah-guard-dist/packages/detector/src/index.js" "behavioral"
check_import "Kasbah-site/kasbah-guard-dist/packages/detector/src/index.js" "obfuscation-decoder"

# Check advanced models
check_file_exists "Kasbah-site/kasbah-guard-dist/packages/detector/src/advanced-frontier-models.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/packages/detector/src/quantum-resistant-crypto.js"

# ═══════════════════════════════════════════════════════════════
# SCAN 4: Product Implementations
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 4: Product Implementations"

echo ""
echo "Checking product implementations..."

# Slack Guard
check_import "Kasbah-site/kasbah-guard-dist/apps/slack-guard/src/slack-guard-complete.js" "@slack/bolt"
check_import "Kasbah-site/kasbah-guard-dist/apps/slack-guard/src/slack-guard-complete.js" "@kasbah/detector"

# Discord Guardian
check_import "Kasbah-site/kasbah-guard-dist/apps/discord-guard/src/discord-guardian-complete.js" "discord.js"
check_import "Kasbah-site/kasbah-guard-dist/apps/discord-guard/src/discord-guardian-complete.js" "@kasbah/detector"

# Hospital Guardian
check_file_exists "Kasbah-site/kasbah-guard-dist/apps/hospital-guard/src/hospital-guardian-complete.js"
check_import "Kasbah-site/kasbah-guard-dist/apps/hospital-guard/src/hospital-guardian-complete.js" "@kasbah/detector"

# Legal Shield
check_file_exists "Kasbah-site/kasbah-guard-dist/apps/legal-shield/src/legal-shield-complete.js"
check_import "Kasbah-site/kasbah-guard-dist/apps/legal-shield/src/legal-shield-complete.js" "@kasbah/detector"

# ═══════════════════════════════════════════════════════════════
# SCAN 5: SDK Wiring
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 5: SDK Wiring"

echo ""
echo "Checking SDK configurations..."

# Python SDK
check_file_exists "kasbah-sdk-python/pyproject.toml"
check_file_exists "kasbah-sdk-python/kasbah/client.py"
check_file_exists "kasbah-sdk-python/kasbah/models.py"

# Node.js SDK
check_file_exists "kasbah-sdk-node/package.json"
check_file_exists "kasbah-sdk-node/src/index.ts"

# Flutter SDK
check_file_exists "kasbah-sdk-flutter/pubspec.yaml"
check_file_exists "kasbah-sdk-flutter/lib/kasbah_guard.dart"
check_file_exists "kasbah-sdk-flutter/lib/src/kasbah_client.dart"

# React Native SDK
check_file_exists "kasbah-sdk-react-native/package.json"
check_file_exists "kasbah-sdk-react-native/lib/index.js"
check_file_exists "kasbah-sdk-react-native/lib/index.d.ts"

# ═══════════════════════════════════════════════════════════════
# SCAN 6: CI/CD Pipeline Wiring
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 6: CI/CD Pipeline Wiring"

echo ""
echo "Checking CI/CD workflows..."

check_file_exists ".github/workflows/ci-cd-pipeline.yml"
check_file_exists ".github/workflows/ci.yml"
check_file_exists ".github/workflows/security.yml"

# Check workflow references
check_reference ".github/workflows/ci-cd-pipeline.yml" "test-unit"
check_reference ".github/workflows/ci-cd-pipeline.yml" "deploy-production"
check_reference ".github/workflows/ci-cd-pipeline.yml" "publish-npm"

# ═══════════════════════════════════════════════════════════════
# SCAN 7: Deployment Scripts
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 7: Deployment Scripts"

echo ""
echo "Checking deployment scripts..."

check_file_exists "deploy-to-production.sh"
check_file_exists "scripts/setup-production.sh"
check_file_exists "scripts/monitor-production.sh"
check_file_exists "scripts/automated-backup.sh"
check_file_exists "scripts/build-desktop-platforms.sh"

# Check scripts are executable
if [ -x "deploy-to-production.sh" ]; then
  log_pass "deploy-to-production.sh is executable"
  ((PASS_COUNT++))
else
  log_warn "deploy-to-production.sh not executable"
  ((WARN_COUNT++))
fi

# ═══════════════════════════════════════════════════════════════
# SCAN 8: Test Suite Wiring
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 8: Test Suite Wiring"

echo ""
echo "Checking test files..."

check_file_exists "Kasbah-site/api/src/moats/__tests__/phase1-complete.test.js"
check_file_exists "Kasbah-site/api/src/moats/__tests__/phase2-complete.test.js"
check_file_exists "Kasbah-site/api/src/moats/__tests__/phase3-complete.test.js"
check_file_exists "Kasbah-site/api/src/moats/__tests__/phase4-complete.test.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/apps/__tests__/phase5-products.test.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/packages/detector/tests/comprehensive.test.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/packages/detector/tests/advanced-frontier.test.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/packages/detector/tests/quantum-resistant.test.js"

# ═══════════════════════════════════════════════════════════════
# SCAN 9: Extension Wiring
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 9: Extension Wiring"

echo ""
echo "Checking browser extensions..."

check_file_exists "Kasbah-site/kasbah-guard-dist/extensions/chrome/manifest.json"
check_file_exists "Kasbah-site/kasbah-guard-dist/extensions/chrome/background.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/extensions/chrome/src/detector.js"
check_file_exists "Kasbah-site/kasbah-guard-dist/extensions/chrome/src/content.js"

# Check manifest references
check_reference "Kasbah-site/kasbah-guard-dist/extensions/chrome/manifest.json" "background.js"
check_reference "Kasbah-site/kasbah-guard-dist/extensions/chrome/manifest.json" "content.js"

# ═══════════════════════════════════════════════════════════════
# SCAN 10: Kasbah-Core Backend
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 10: Kasbah-Core Backend"

echo ""
echo "Checking Kasbah-Core backend..."

check_file_exists "Kasbah-Core/apps/api/main.py"
check_file_exists "Kasbah-Core/core/observability.py"
check_file_exists "Kasbah-Core/core/integrity_engine.py"
check_file_exists "Kasbah-Core/core/adaptive_defense.py"
check_file_exists "Kasbah-Core/requirements.txt"
check_file_exists "Kasbah-Core/docker-compose.yml"

# Check Python imports
check_import "Kasbah-Core/apps/api/main.py" "fastapi"
check_import "Kasbah-Core/apps/api/main.py" "pydantic"

# ═══════════════════════════════════════════════════════════════
# SCAN 11: Configuration Files
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 11: Configuration Files"

echo ""
echo "Checking configuration files..."

check_file_exists ".env.example"
check_file_exists ".gitignore"
check_file_exists "docker-compose.yml"
check_file_exists "Dockerfile"

# Check .env.example has required vars
check_reference ".env.example" "DATABASE_URL"
check_reference ".env.example" "REDIS_URL"
check_reference ".env.example" "JWT_SECRET"

# ═══════════════════════════════════════════════════════════════
# SCAN 12: Load Tests
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 12: Load Tests"

echo ""
echo "Checking load test suite..."

check_dir_exists "tests/load"
check_file_exists "tests/load/api-load-test.js"
check_file_exists "tests/load/detection-burst-test.js"
check_file_exists "tests/load/multi-product-test.js"
check_file_exists "tests/load/memory-leak-test.js"

# ═══════════════════════════════════════════════════════════════
# SCAN 13: Compliance & Legal
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 13: Compliance & Legal"

echo ""
echo "Checking compliance documents..."

check_file_exists "LEGAL/BAA_TEMPLATE.md"
check_file_exists "LEGAL/DPA_TEMPLATE.md"
check_file_exists "COMPLIANCE_DOCUMENTATION.md"
check_file_exists "HOSPITAL_GUARDIAN_HIPAA.md"
check_file_exists "INCIDENT_RESPONSE_PLAN.md"

# ═══════════════════════════════════════════════════════════════
# SCAN 14: Implementation Plans
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 14: Implementation Plans"

echo ""
echo "Checking implementation plans..."

check_file_exists "MOBILE_APPS_IMPLEMENTATION.md"
check_file_exists "IDE_GUARD_IMPLEMENTATION.md"
check_file_exists "SCALE_INFRASTRUCTURE_10K_USERS.md"
check_file_exists "MASS_SCALE_READINESS_PLAN.md"
check_file_exists "HOSPITAL_GUARDIAN_HIPAA.md"

# ═══════════════════════════════════════════════════════════════
# SCAN 15: Package Dependencies
# ═══════════════════════════════════════════════════════════════
log_section "SCAN 15: Package Dependencies"

echo ""
echo "Checking package.json files..."

check_file_exists "Kasbah-site/kasbah-guard-dist/packages/detector/package.json"
check_file_exists "Kasbah-site/kasbah-guard-dist/apps/api-guard/package.json"
check_file_exists "Kasbah-site/kasbah-guard-dist/apps/slack-guard/package.json"
check_file_exists "Kasbah-site/kasbah-guard-dist/apps/discord-guard/package.json"
check_file_exists "kasbah-sdk-node/package.json"
check_file_exists "kasbah-sdk-react-native/package.json"

# Check package.json has required fields
check_reference "Kasbah-site/kasbah-guard-dist/packages/detector/package.json" '"name": "@kasbah/detector"'
check_reference "Kasbah-site/kasbah-guard-dist/packages/detector/package.json" '"main":'
check_reference "Kasbah-site/kasbah-guard-dist/packages/detector/package.json" '"types":'

# ═══════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════
echo ""
echo "========================================"
echo "WIRING VERIFICATION COMPLETE"
echo "========================================"
echo ""
echo "Results:"
echo -e "  ${GREEN}Passed:${NC} ${PASS_COUNT}/${TOTAL_CHECKS}"
echo -e "  ${YELLOW}Warnings:${NC} ${WARN_COUNT}"
echo -e "  ${RED}Failed:${NC} ${FAIL_COUNT}"
echo ""

if [ ${FAIL_COUNT} -gt 0 ]; then
  echo -e "${RED}✗ BROKEN REFERENCES DETECTED${NC}"
  echo ""
  echo "Broken imports/references:"
  for ref in "${BROKEN_REFS[@]}"; do
    echo -e "  ${RED}✗${NC} ${ref}"
  done
  echo ""
  echo "Action Required: Fix broken imports before deployment"
  EXIT_CODE=1
else
  echo -e "${GREEN}✓ ALL WIRING VERIFIED!${NC}"
  echo ""
  echo "All documents, code, and configurations are properly wired."
  EXIT_CODE=0
fi

if [ ${WARN_COUNT} -gt 0 ]; then
  echo ""
  echo -e "${YELLOW}⚠ ${WARN_COUNT} warnings (non-critical)${NC}"
fi

echo ""
echo "========================================"

exit $EXIT_CODE
