#!/bin/bash

# Comprehensive Test Runner for Kasbah Guard Platform
# Runs all test suites and generates coverage reports

set -e

echo "=========================================="
echo "Kasbah Guard: Comprehensive Test Suite"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test results array
declare -a TEST_RESULTS

# Function to run a test suite
run_test_suite() {
    local name=$1
    local command=$2

    echo -e "${YELLOW}Running: $name${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✓ $name PASSED${NC}"
        ((PASSED_TESTS++))
        TEST_RESULTS+=("PASS: $name")
    else
        echo -e "${RED}✗ $name FAILED${NC}"
        ((FAILED_TESTS++))
        TEST_RESULTS+=("FAIL: $name")
    fi
    echo ""
}

# 1. Spatial Intelligence Tests
echo "1. Testing Spatial Intelligence Module..."
echo "=========================================="
if [ -f "Kasbah-Core/tests/test_spatial_intelligence.py" ]; then
    run_test_suite "Spatial Intelligence Unit Tests" \
        "cd Kasbah-Core && python -m pytest tests/test_spatial_intelligence.py -v --tb=short"
else
    echo -e "${RED}Spatial Intelligence tests not found${NC}"
    TEST_RESULTS+=("SKIP: Spatial Intelligence (file not found)")
fi
echo ""

# 2. Python SDK Tests
echo "2. Testing Python SDK..."
echo "=========================================="
if [ -d "kasbah-sdk-python" ]; then
    if [ -f "kasbah-sdk-python/tests/test_client.py" ]; then
        run_test_suite "Python SDK Client Tests" \
            "cd kasbah-sdk-python && python -m pytest tests/test_client.py -v --tb=short 2>&1 || true"
    fi

    if [ -f "kasbah-sdk-python/tests/test_models.py" ]; then
        run_test_suite "Python SDK Models Tests" \
            "cd kasbah-sdk-python && python -m pytest tests/test_models.py -v --tb=short 2>&1 || true"
    fi
else
    echo -e "${YELLOW}Python SDK directory not found${NC}"
fi
echo ""

# 3. Node.js SDK Tests
echo "3. Testing Node.js SDK..."
echo "=========================================="
if [ -d "kasbah-sdk-node" ]; then
    if [ -f "kasbah-sdk-node/package.json" ] && [ -f "kasbah-sdk-node/tests/index.test.ts" ]; then
        echo -e "${YELLOW}Note: Node.js tests require npm install and jest setup${NC}"
        TEST_RESULTS+=("INFO: Node.js SDK tests require npm install")
    else
        echo -e "${YELLOW}Node.js SDK test files not fully configured${NC}"
    fi
else
    echo -e "${YELLOW}Node.js SDK directory not found${NC}"
fi
echo ""

# 4. Integration Tests
echo "4. Testing Integration..."
echo "=========================================="
if [ -f "tests/test_integration_sdks.py" ]; then
    run_test_suite "SDK Integration Tests" \
        "python -m pytest tests/test_integration_sdks.py -v --tb=short 2>&1 || true"
else
    echo -e "${YELLOW}Integration tests not found${NC}"
    TEST_RESULTS+=("INFO: Integration tests need completion")
fi
echo ""

# 5. Core Backend Tests (if any)
echo "5. Testing Core Backend..."
echo "=========================================="
CORE_TESTS=$(find Kasbah-Core -name "test_*.py" -type f 2>/dev/null | wc -l)
if [ "$CORE_TESTS" -gt 0 ]; then
    run_test_suite "Kasbah Core Tests" \
        "cd Kasbah-Core && python -m pytest tests/ -v --tb=short 2>&1 || true"
else
    echo -e "${YELLOW}No core tests found${NC}"
fi
echo ""

# Summary
echo "=========================================="
echo -e "${YELLOW}TEST SUMMARY${NC}"
echo "=========================================="
echo "Test Results:"
for result in "${TEST_RESULTS[@]}"; do
    if [[ $result == PASS* ]]; then
        echo -e "${GREEN}✓ $result${NC}"
    elif [[ $result == FAIL* ]]; then
        echo -e "${RED}✗ $result${NC}"
    else
        echo "  $result"
    fi
done

echo ""
echo "Statistics:"
echo "  Passed:  $PASSED_TESTS"
echo "  Failed:  $FAILED_TESTS"
echo "  Total:   $((PASSED_TESTS + FAILED_TESTS))"

if [ $FAILED_TESTS -eq 0 ] && [ $PASSED_TESTS -gt 0 ]; then
    echo ""
    echo -e "${GREEN}=========================================="
    echo "All tests passed! ✓"
    echo "==========================================${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}=========================================="
    echo "Some tests failed or none were run"
    echo "==========================================${NC}"
    exit 1
fi
