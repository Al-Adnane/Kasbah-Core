#!/bin/bash

# Kasbah Guard — Windows/Linux Desktop Build Script
# Builds desktop apps for Windows and Linux from Tauri source
# Usage: ./build-desktop-platforms.sh

set -e

echo "========================================"
echo "Kasbah Guard — Desktop Platform Builds"
echo "Date: $(date)"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Configuration
DESKTOP_DIR="Kasbah-site/kasbah-guard-dist/apps/desktop"
BUILD_DIR="$DESKTOP_DIR/target/release"
OUTPUT_DIR="$DESKTOP_DIR/dist"

echo "Configuration:"
echo "  Desktop Dir: $DESKTOP_DIR"
echo "  Build Dir: $BUILD_DIR"
echo "  Output Dir: $OUTPUT_DIR"
echo ""

# Check if in desktop directory
if [ ! -d "$DESKTOP_DIR/src-tauri" ]; then
  log_error "Desktop app directory not found: $DESKTOP_DIR"
  exit 1
fi

cd "$DESKTOP_DIR"

# Step 1: Install dependencies
log_step "Step 1: Installing dependencies..."

# Check for Rust
if ! command -v cargo >/dev/null 2>&1; then
  log_error "Rust not installed. Install from https://rustup.rs/"
  exit 1
fi
log_success "Rust installed: $(rustc --version)"

# Check for Node.js
if ! command -v node >/dev/null 2>&1; then
  log_error "Node.js not installed"
  exit 1
fi
log_success "Node.js installed: $(node --version)"

# Install Node dependencies
npm install
log_success "Node dependencies installed"

# Step 2: Build for current platform
log_step "Step 2: Building for current platform..."

npm run tauri build
log_success "Current platform build complete"

# Step 3: Build for Windows (if on Linux/macOS with cross-compilation)
log_step "Step 3: Building for Windows..."

# Add Windows target if not present
rustup target add x86_64-pc-windows-msvc 2>/dev/null || log_warn "Windows target may already be added"

# Build Windows installer
# Note: Actual Windows build requires Windows or cross-compilation setup
log_warn "Windows build requires Windows environment"
log_warn "On Windows: cd $DESKTOP_DIR && npm run tauri build -- --target x86_64-pc-windows-msvc"

# Step 4: Build for Linux
log_step "Step 4: Building for Linux..."

# Add Linux targets
rustup target add x86_64-unknown-linux-gnu 2>/dev/null || log_warn "Linux target may already be added"

# Build Linux packages (AppImage, deb, rpm)
# Note: Actual Linux build requires Linux environment
log_warn "Linux build requires Linux environment"
log_warn "On Linux: cd $DESKTOP_DIR && npm run tauri build -- --target x86_64-unknown-linux-gnu"

# Step 5: Code signing (Windows)
log_step "Step 5: Code signing..."

if [ -n "$WINDOWS_CERTIFICATE" ]; then
  log_success "Windows certificate configured"
  # Sign Windows executable
  # signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f certificate.pfx /p $WINDOWS_CERTIFICATE_PASSWORD build/windows/*.exe
  log_warn "Code signing requires Windows environment and certificate"
else
  log_warn "No Windows certificate configured"
fi

# Step 6: Package outputs
log_step "Step 6: Packaging outputs..."

mkdir -p "$OUTPUT_DIR"

# Copy macOS build
if [ -d "$BUILD_DIR/bundle/macos" ]; then
  cp -r "$BUILD_DIR/bundle/macos"/*.app "$OUTPUT_DIR/" 2>/dev/null || true
  cp -r "$BUILD_DIR/bundle/macos"/*.dmg "$OUTPUT_DIR/" 2>/dev/null || true
  log_success "macOS packages copied"
fi

# Copy Windows build
if [ -d "$BUILD_DIR/bundle/msi" ]; then
  cp -r "$BUILD_DIR/bundle/msi"/*.msi "$OUTPUT_DIR/" 2>/dev/null || true
  cp -r "$BUILD_DIR/bundle/nsis"/*.exe "$OUTPUT_DIR/" 2>/dev/null || true
  log_success "Windows packages copied"
fi

# Copy Linux build
if [ -d "$BUILD_DIR/bundle/appimage" ]; then
  cp -r "$BUILD_DIR/bundle/appimage"/*.AppImage "$OUTPUT_DIR/" 2>/dev/null || true
  cp -r "$BUILD_DIR/bundle/deb"/*.deb "$OUTPUT_DIR/" 2>/dev/null || true
  cp -r "$BUILD_DIR/bundle/rpm"/*.rpm "$OUTPUT_DIR/" 2>/dev/null || true
  log_success "Linux packages copied"
fi

# Summary
echo ""
echo "========================================"
echo "Build Summary"
echo "========================================"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Available packages:"
ls -lh "$OUTPUT_DIR" 2>/dev/null || log_warn "No packages built yet"
echo ""
echo "Platform-specific build instructions:"
echo ""
echo "Windows:"
echo "  1. Install Rust: https://rustup.rs/"
echo "  2. Install Visual Studio Build Tools"
echo "  3. cd $DESKTOP_DIR"
echo "  4. npm install"
echo "  5. npm run tauri build"
echo ""
echo "Linux:"
echo "  1. Install Rust: https://rustup.rs/"
echo "  2. Install build essentials: sudo apt install build-essential"
echo "  3. cd $DESKTOP_DIR"
echo "  4. npm install"
echo "  5. npm run tauri build"
echo ""
echo "macOS:"
echo "  1. Install Rust: https://rustup.rs/"
echo "  2. Install Xcode Command Line Tools"
echo "  3. cd $DESKTOP_DIR"
echo "  4. npm install"
echo "  5. npm run tauri build"
echo ""
log_success "Desktop build script complete!"
echo "========================================"

log_step() { echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${YELLOW}$1${NC}"; echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
