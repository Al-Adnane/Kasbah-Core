#!/bin/bash
# Kasbah Guard - Full Test Suite Runner
# Runs all tests across the platform

set -e

echo "========================================"
echo "  Kasbah Guard - Full Test Suite"
echo "========================================"
echo ""

PASSED=0
FAILED=0
TOTAL=0

run_test() {
  local name=$1
  local cmd=$2
  
  echo "Running: $name"
  if eval "$cmd"; then
    echo "✓ PASSED: $name"
    ((PASSED++))
  else
    echo "✗ FAILED: $name"
    ((FAILED++))
  fi
  ((TOTAL++))
  echo ""
}

# Detector tests
run_test "Detector Tests" "cd Kasbah-site/kasbah-guard-dist/packages/detector && npm test"

# Discord Guardian tests
run_test "Discord Guardian Tests" "cd Kasbah-site/kasbah-guard-dist/apps/discord-guard && npm test"

# Slack Guardian tests
run_test "Slack Guardian Tests" "cd Kasbah-site/kasbah-guard-dist/apps/slack-guard && npm test"

# API Guard tests
run_test "API Guard Tests" "cd Kasbah-site/kasbah-guard-dist/apps/api-guard && npm test"

# Node.js SDK tests
run_test "Node.js SDK Tests" "cd kasbah-sdk-node && npm test"

# Python SDK tests
run_test "Python SDK Tests" "cd kasbah-sdk-python && python -m pytest tests/"

# Kasbah-Core tests
run_test "Kasbah-Core Tests" "cd Kasbah-Core && python -m pytest tests/"

# VS Code Extension tests
run_test "VS Code Extension Tests" "cd Kasbah-site/kasbah-guard-dist/apps/vscode && npm test"

# Summary
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo "Total:  $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
  echo "✓ All tests passed!"
  exit 0
else
  echo "✗ $FAILED test(s) failed"
  exit 1
fi
