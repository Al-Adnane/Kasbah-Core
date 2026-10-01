'use strict';

/**
 * Censorship-resistant transport helpers for Myanmar and similar DPI regimes.
 *
 * Plain WireGuard is UDP with a distinctive handshake. Many Myanmar ISPs
 * (MPT, Mytel, ATOM) throttle or drop it. The working pattern is:
 *
 *   client  --TCP:443 (looks like HTTPS)-->  wstunnel  --UDP:51820-->  WireGuard
 *
 * We do not reimplement a DPI-evasion stack. We generate:
 *   1. A client wg-quick config whose Endpoint is a local UDP bridge
 *   2. Exact wstunnel client/server commands (TCP or WSS on 443)
 *
 * wstunnel is optional at runtime: if it is not installed, scripts still
 * print and configs remain valid for any UDP-over-TCP bridge with the same
 * local ports.
 */

const DEFAULT_LOCAL_PORT = 51821;
const DEFAULT_OBFS_PORT = 443;

/** Parse "host:port" / "[v6]:port". */
function splitEndpoint(endpoint) {
  const s = String(endpoint);
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    return { host: s.slice(1, close), port: s.slice(close + 2) };
  }
  const i = s.lastIndexOf(':');
  return { host: i === -1 ? s : s.slice(0, i), port: i === -1 ? '' : s.slice(i + 1) };
}

/**
 * Build client/server obfuscation plan.
 * @param {object} o
 *   endpoint      "exit.example.com:51820"  real WireGuard endpoint
 *   obfsHost      hostname/IP the client connects to on TCP/WSS (often same host)
 *   obfsPort      TCP port to look like (default 443)
 *   localPort     client-side UDP port for the bridge (default 51821)
 *   mode          'tcp' (raw TCP) | 'wss' (WebSocket over TLS — harder to block)
 */
function obfsPlan(o) {
  if (!o.endpoint) throw new Error('obfsPlan requires endpoint');
  const { host: wgHost, port: wgPort } = splitEndpoint(o.endpoint);
  const obfsHost = o.obfsHost || wgHost;
  const obfsPort = Number(o.obfsPort || DEFAULT_OBFS_PORT);
  const localPort = Number(o.localPort || DEFAULT_LOCAL_PORT);
  const mode = o.mode === 'wss' ? 'wss' : 'tcp';
  const wgRemote = `${wgHost}:${wgPort || 51820}`;

  // Client: wstunnel listens UDP locally and forwards over TCP/WSS to exit.
  // timeout_sec=0 disables wstunnel's default 30s UDP idle close (WG is long-lived).
  const clientCmd =
    mode === 'wss'
      ? `wstunnel client -L 'udp://127.0.0.1:${localPort}:${wgRemote}?timeout_sec=0' 'wss://${obfsHost}:${obfsPort}'`
      : `wstunnel client -L 'udp://127.0.0.1:${localPort}:${wgRemote}?timeout_sec=0' 'ws://${obfsHost}:${obfsPort}'`;

  // Server: accept TCP/WSS on 443, hand UDP to local WireGuard.
  const serverCmd =
    mode === 'wss'
      ? `wstunnel server --restrict-to '127.0.0.1:${wgPort || 51820}' 'wss://0.0.0.0:${obfsPort}'`
      : `wstunnel server --restrict-to '127.0.0.1:${wgPort || 51820}' 'ws://0.0.0.0:${obfsPort}'`;

  return {
    mode,
    obfsHost,
    obfsPort,
    localPort,
    wgRemote,
    clientEndpoint: `127.0.0.1:${localPort}`,
    clientCmd,
    serverCmd,
    notes: [
      `WireGuard stays on ${wgRemote} but is only reachable via local wstunnel.`,
      `Client talks TCP${mode === 'wss' ? '/WSS' : ''} to ${obfsHost}:${obfsPort} — same shape as HTTPS on 443.`,
      'Exit node must NOT expose UDP 51820 to the public internet when obfs is required.',
      'Prefer a regional exit (Singapore/Tokyo/Bangkok) — Amsterdam adds 200ms+ from Myanmar.',
    ],
  };
}

/**
 * Rewrite a client wg-quick config so Endpoint points at the local bridge.
 * Keeps every other field (keys, AllowedIPs, kill-switch PostUp) unchanged.
 */
function applyObfsToClientConf(confText, plan) {
  return String(confText).replace(
    /^Endpoint\s*=\s*.+$/m,
    `Endpoint = ${plan.clientEndpoint}`
  );
}

/** Shell script the exit node operator runs (systemd + wstunnel + wg). */
function serverDeployScript(plan, { wgConfPath = '/etc/wireguard/kasbah0.conf' } = {}) {
  return `#!/usr/bin/env bash
# Kasbah VPN exit node — WireGuard + TCP/WSS obfuscation (Myanmar-class DPI)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -qy wireguard wireguard-tools iptables curl

# wstunnel (UDP-over-TCP/WSS). Pin a release in production.
if ! command -v wstunnel >/dev/null 2>&1; then
  curl -fsSL https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-linux -o /usr/local/bin/wstunnel
  chmod +x /usr/local/bin/wstunnel
fi

install -d -m 700 /etc/wireguard
if [ ! -f ${wgConfPath} ]; then
  echo "write your kasbah-vpn config server output into ${wgConfPath}" >&2
  exit 1
fi

systemctl enable --now wg-quick@kasbah0

# Obfuscation front — bind 443, restrict backend to local WireGuard only.
cat > /etc/systemd/system/kasbah-wstunnel.service <<'UNIT'
[Unit]
Description=Kasbah VPN obfuscation front (wstunnel)
After=network-online.target wg-quick@kasbah0.service
Wants=network-online.target

[Service]
ExecStart=${plan.serverCmd}
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now kasbah-wstunnel.service

# Do not publish raw WireGuard to the WAN when obfs is on.
iptables -D INPUT -p udp --dport ${plan.wgRemote.split(':')[1] || 51820} -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p udp --dport ${plan.wgRemote.split(':')[1] || 51820} -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport ${plan.obfsPort} -j ACCEPT

echo "exit node ready: WG local-only, obfs TCP ${plan.obfsPort}"
`;
}

module.exports = {
  DEFAULT_LOCAL_PORT,
  DEFAULT_OBFS_PORT,
  splitEndpoint,
  obfsPlan,
  applyObfsToClientConf,
  serverDeployScript,
};
