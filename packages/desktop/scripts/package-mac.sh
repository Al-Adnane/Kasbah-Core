#!/usr/bin/env bash
# Package Kasbah Guard Desktop as a real .app + .dmg without electron-builder.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # packages/desktop
REPO="$(cd "$ROOT/../.." && pwd)"                 # KasbahFinal
OUT="$ROOT/dist"
APP_NAME="Kasbah Privacy"
BUNDLE_ID="com.kasbah.privacy"
VERSION="$(node -p "require('$ROOT/package.json').version")"
ELECTRON_APP="$ROOT/node_modules/electron/dist/Electron.app"
APP="$OUT/$APP_NAME.app"

echo "==> packaging $APP_NAME $VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> copy Electron runtime"
ditto "$ELECTRON_APP" "$APP"

echo "==> inject application"
RES="$APP/Contents/Resources"
rm -rf "$RES/default_app.asar"
mkdir -p "$RES/app"
# App source (no backup html copies)
rsync -a --exclude 'index *.html' "$ROOT/src/" "$RES/app/src/"
cp "$ROOT/package.json" "$RES/app/package.json"

# VPN package (core product) — ship this only; API is optional and heavy.
mkdir -p "$RES/packages/kasbah-vpn"
rsync -a --exclude node_modules --exclude test.js --exclude test-obfs.js \
  --exclude webui --exclude .DS_Store \
  "$REPO/packages/kasbah-vpn/" "$RES/packages/kasbah-vpn/"

# receipts.js requires ../../kasbah-receipts/src/index.js — must sit beside kasbah-vpn
mkdir -p "$RES/packages/kasbah-receipts"
rsync -a --exclude node_modules --exclude test.js --exclude .DS_Store \
  "$REPO/packages/kasbah-receipts/" "$RES/packages/kasbah-receipts/"

# Stub api-server so startApiServer finds the file and exits cleanly.
mkdir -p "$RES/packages/api-server"
cat > "$RES/packages/api-server/server.js" <<'STUB'
// Packaged VPN-first build: full api-server not bundled.
// Kasbah Guard desktop VPN (keys, configs, receipts, tunnel) does not need it.
console.log('[kasbah] VPN-only package — api-server not bundled');
process.exit(0);
STUB

# Peer dep for PQ PSK — must resolve from packages/kasbah-vpn/src/psk.js
mkdir -p "$RES/packages/kasbah-vpn/node_modules/@noble"
if [ -d "$REPO/node_modules/@noble/post-quantum" ]; then
  ditto "$REPO/node_modules/@noble/post-quantum" "$RES/packages/kasbah-vpn/node_modules/@noble/post-quantum"
elif [ -d "$ROOT/node_modules/@noble/post-quantum" ]; then
  ditto "$ROOT/node_modules/@noble/post-quantum" "$RES/packages/kasbah-vpn/node_modules/@noble/post-quantum"
fi

echo "==> Info.plist"
PLIST="$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName $APP_NAME" "$PLIST" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleName string $APP_NAME" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName $APP_NAME" "$PLIST" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string $APP_NAME" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$PLIST"
# Point executable at Electron (already named Electron) — keep as-is.

# Icon if present
if [ -f "$ROOT/resources/icon.icns" ]; then
  cp "$ROOT/resources/icon.icns" "$RES/electron.icns"
  /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile electron.icns" "$PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string electron.icns" "$PLIST"
fi

# Ad-hoc sign (no --deep: deep can hang on Electron frameworks)
echo "==> ad-hoc codesign"
codesign --force --sign - "$APP" 2>&1 | tail -8 || true
# Re-sign frameworks quickly if needed for local launch
codesign --force --sign - "$APP/Contents/Frameworks/Electron Framework.framework" 2>/dev/null || true


echo "==> create DMG"
DMG="$OUT/${APP_NAME// /}-$VERSION.dmg"
hdiutil create -volname "$APP_NAME" -srcfolder "$APP" -ov -format UDZO "$DMG" >/dev/null
echo "==> done"
ls -lah "$APP" "$DMG"
echo "APP=$APP"
echo "DMG=$DMG"
