#!/bin/bash
# Kasbah SDK - Publish All SDKs to Package Registries
# Usage: ./publish_sdks.sh

set -e

echo "=============================================="
echo "  KASBAH SDK - PUBLISH TO REGISTRIES"
echo "=============================================="
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prereqs() {
    log_info "Checking prerequisites..."
    
    # npm
    if ! command -v npm &> /dev/null; then
        log_error "npm not installed"
        exit 1
    fi
    log_info "✓ npm: $(npm --version)"
    
    # python3
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not installed"
        exit 1
    fi
    log_info "✓ python3: $(python3 --version)"
    
    # flutter (optional)
    if command -v flutter &> /dev/null; then
        log_info "✓ flutter: $(flutter --version --short)"
    else
        log_warn "flutter not installed (skipping Flutter SDK)"
    fi
}

# Publish Node.js SDK
publish_nodejs() {
    log_info "Publishing Node.js SDK to npm..."
    
    SDK_DIR="$PROJECT_ROOT/kasbah-sdk-node"
    cd "$SDK_DIR"
    
    # Update version
    log_info "Updating version..."
    npm version patch --no-git-tag-version
    
    # Build if needed
    if [ -f "tsconfig.json" ]; then
        log_info "Building TypeScript..."
        npm run build || log_warn "Build failed, continuing anyway"
    fi
    
    # Publish
    log_info "Publishing to npm..."
    npm publish --access public
    
    log_info "✓ Node.js SDK published"
}

# Publish Python SDK
publish_python() {
    log_info "Publishing Python SDK to PyPI..."
    
    SDK_DIR="$PROJECT_ROOT/kasbah-sdk-python"
    cd "$SDK_DIR"
    
    # Install build tools
    pip3 install --user build twine
    
    # Clean previous builds
    rm -rf dist/ build/ *.egg-info
    
    # Build
    log_info "Building package..."
    python3 -m build
    
    # Publish
    log_info "Publishing to PyPI..."
    python3 -m twine upload dist/*
    
    log_info "✓ Python SDK published"
}

# Publish Flutter SDK
publish_flutter() {
    log_info "Publishing Flutter SDK to pub.dev..."
    
    SDK_DIR="$PROJECT_ROOT/kasbah-sdk-flutter"
    cd "$SDK_DIR"
    
    # Check pubspec.yaml
    if [ ! -f "pubspec.yaml" ]; then
        log_error "pubspec.yaml not found"
        return
    fi
    
    # Validate
    log_info "Validating package..."
    flutter pub publish --dry-run || log_warn "Validation failed"
    
    # Publish
    log_info "Publishing to pub.dev..."
    flutter pub publish --force
    
    log_info "✓ Flutter SDK published"
}

# Publish React Native SDK
publish_react_native() {
    log_info "Publishing React Native SDK to npm..."
    
    SDK_DIR="$PROJECT_ROOT/kasbah-sdk-react-native"
    cd "$SDK_DIR"
    
    # Update version
    log_info "Updating version..."
    npm version patch --no-git-tag-version
    
    # Build if needed
    if [ -f "tsconfig.json" ]; then
        log_info "Building TypeScript..."
        npm run build || log_warn "Build failed, continuing anyway"
    fi
    
    # Publish
    log_info "Publishing to npm..."
    npm publish --access public
    
    log_info "✓ React Native SDK published"
}

# Main
main() {
    check_prereqs
    
    echo ""
    echo "SDKs to publish:"
    echo "1. All SDKs (Node.js, Python, Flutter, React Native)"
    echo "2. Node.js SDK only"
    echo "3. Python SDK only"
    echo "4. Flutter SDK only"
    echo "5. React Native SDK only"
    echo ""
    read -p "Select option (1-5): " option
    
    case $option in
        1)
            publish_nodejs
            publish_python
            publish_flutter
            publish_react_native
            ;;
        2)
            publish_nodejs
            ;;
        3)
            publish_python
            ;;
        4)
            publish_flutter
            ;;
        5)
            publish_react_native
            ;;
        *)
            log_error "Invalid option"
            exit 1
            ;;
    esac
    
    echo ""
    log_info "SDK publishing complete!"
    echo ""
    echo "Verify installations:"
    echo "  npm install @kasbah/sdk"
    echo "  pip install kasbah-sdk"
    echo "  flutter pub add kasbah_sdk"
    echo ""
}

main
