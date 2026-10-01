#!/bin/bash
# Kasbah kill-switch helper — root only, passwordless via sudoers NOPASSWD.
# Mirrors the existing kasbah-wg helper pattern so applyKillSwitch() in
# main-vpn.js never has to fall back to an osascript GUI admin prompt,
# which was the actual cause of "connect, then nothing happens" — with
# killSwitch defaulting to true, that dialog popped on every connect.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
ACTION="${1:-}"

case "$ACTION" in
  enable)
    RULES_FILE="$(mktemp -t kasbah-ks)"
    printf 'set skip on lo0\nblock out quick inet\npass out quick on utun+ inet\n' > "$RULES_FILE"
    pfctl -f "$RULES_FILE" || { rm -f "$RULES_FILE"; exit 1; }
    rm -f "$RULES_FILE"
    pfctl -e 2>&1 | grep -qi 'already enabled' || true
    pfctl -s info
    echo "KASBAH_ADMIN_OK enable"
    ;;
  disable)
    pfctl -d 2>&1 || true
    pfctl -s info
    echo "KASBAH_ADMIN_OK disable"
    ;;
  status)
    pfctl -s info
    ;;
  *)
    echo "usage: kasbah-killswitch enable|disable|status" >&2
    exit 1
    ;;
esac
