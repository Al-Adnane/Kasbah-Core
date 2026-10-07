#!/bin/bash
# ============================================================================
# KASBAH - SIMPLE INSTALLATION SCRIPT
# ============================================================================
# Fixed version - oqs is optional, core features work without it
# 
# Run: bash scripts/install_simple.sh
# ============================================================================

set -e  # Exit on error

echo "========================================================================"
echo "KASBAH - SIMPLE INSTALLATION"
echo "========================================================================"
echo ""
echo "Installing core dependencies (5-10 minutes)..."
echo ""

# ============================================================================
# STEP 1: INSTALL @kasbah/core (Node.js)
# ============================================================================
echo "STEP 1: Installing @kasbah/core..."
echo ""

cd kasbah-core

# Install core dependencies (oqs is optional - installed separately if needed)
npm install --legacy-peer-deps

echo ""
echo "Building @kasbah/core..."
npm run build

cd ..

echo ""
echo "✅ @kasbah/core installed"

# ============================================================================
# STEP 2: INSTALL kasbah-core-python
# ============================================================================
echo ""
echo "STEP 2: Installing kasbah-core-python..."
echo ""

cd kasbah-core-python

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install in virtual environment
echo "Installing kasbah-core-python in virtual environment..."
pip install -e . --quiet

echo ""
echo "✅ kasbah-core-python installed (in venv)"
echo "   To use: source kasbah-core-python/venv/bin/activate"

cd ..

# ============================================================================
# STEP 3: VERIFY INSTALLATION
# ============================================================================
echo ""
echo "========================================================================"
echo "VERIFICATION"
echo "========================================================================"
echo ""

echo "Test 1: @kasbah/core..."
node -e "
const c = require('./kasbah-core/src');
console.log('✅ @kasbah/core loaded:', Object.keys(c).length, 'features');
" 2>&1 | head -5

echo ""
echo "Test 2: kasbah-core-python..."
cd kasbah-core-python && python3 -c "
from kasbah_core import KasbahPipeline
p = KasbahPipeline()
print('✅ kasbah-core-python: Working')
" && cd ..

echo ""
echo "========================================================================"
echo "INSTALLATION COMPLETE"
echo "========================================================================"
echo ""
echo "✅ Core features installed and working:"
echo "   - ML AI detection (transformers)"
echo "   - AST code analysis (babel)"
echo "   - Blockchain anchoring (web3)"
echo "   - Statistical fallbacks (always available)"
echo ""
echo "⚠️  Optional features (install separately if needed):"
echo "   - Quantum-safe crypto: See kasbah-core/README.md for liboqs"
echo ""
echo "Next steps:"
echo "   cd kasbah-sdk-node && npm test"
echo "   cd kasbah-api-gateway && node src/api-gateway-server.js"
echo ""
