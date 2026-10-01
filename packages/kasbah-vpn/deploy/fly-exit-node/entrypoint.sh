#!/usr/bin/env bash
# Kasbah VPN exit node — Fly.io entrypoint.
# WG0_CONF (base64-encoded wg0.conf, containing the real private key) is
# injected as a Fly secret at deploy time — never present in the image.
set -euo pipefail

if [ -z "${WG0_CONF:-}" ]; then
  echo "FATAL: WG0_CONF secret not set" >&2
  exit 1
fi

echo "$WG0_CONF" | base64 -d > /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf

echo 1 > /proc/sys/net/ipv4/ip_forward || true

wg-quick up wg0

echo "kasbah exit node up — $(wg show wg0 public-key 2>/dev/null || echo unknown)"

# DPI bypass: accept WebSocket/TCP on 443 and hand UDP to local WireGuard.
# Clients on censored networks (Myanmar) use wstunnel → this port.
if command -v wstunnel >/dev/null 2>&1; then
  echo "starting wstunnel server on :443 → 127.0.0.1:51820"
  # --restrict-to limits which backend the tunnel may reach.
  wstunnel server --restrict-to '127.0.0.1:51820' 'ws://0.0.0.0:443' &
  WST_PID=$!
else
  echo "wstunnel not installed — UDP only" >&2
  WST_PID=""
fi

# Keep the machine alive; wg-quick's PostUp already configured NAT.
cleanup() {
  [ -n "${WST_PID:-}" ] && kill "$WST_PID" 2>/dev/null || true
  wg-quick down wg0 || true
  exit 0
}
trap cleanup TERM INT
tail -f /dev/null &
wait $!
