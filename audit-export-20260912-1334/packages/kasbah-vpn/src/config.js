'use strict';

/**
 * wg-quick config generation: personal full tunnel, exit server, split-AI
 * tunnel, and governed mesh. Pure functions — profile objects in, .conf
 * strings out — so every shape is unit-testable without touching the network
 * or a real interface.
 */

const dns = require('dns').promises;
const { AI_PROVIDERS } = require('./providers');

const DEFAULT_SUBNET = '10.77.0';
// Fixed ULA (RFC 4193) prefix for the mirrored IPv6 mesh/tunnel subnet — same
// private-use rationale as DEFAULT_SUBNET, just IPv6. Override via subnet6 if
// you run more than one Kasbah network on hosts that share a routing table.
const DEFAULT_SUBNET6 = 'fd7a:6b1a:cafe::';
const DEFAULT_PORT = 51820;
const DEFAULT_DNS = '1.1.1.1';
const DEFAULT_KEEPALIVE = 25;

function iniSection(name, entries) {
  const lines = [`[${name}]`];
  for (const [k, v] of entries) {
    if (v === undefined || v === null || v === '') continue;
    lines.push(`${k} = ${v}`);
  }
  return lines.join('\n');
}

/** Last dotted octet of an IPv4 (CIDR or bare) address — used as the shared host number for the mirrored IPv6 address. */
function hostNumOf(address) {
  const m = address && String(address).match(/\.(\d+)(?:\/\d+)?$/);
  return m ? Number(m[1]) : null;
}

/** Derive this host's IPv6 address (no prefix) from its IPv4 address, unless explicitly disabled with `false`. */
function subnet6For(address, subnet6 = DEFAULT_SUBNET6) {
  if (subnet6 === false) return null;
  const n = hostNumOf(address);
  return n ? `${subnet6}${n}` : null;
}

/** Split "host:port" / "[ipv6]:port" into { host, port }. */
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
 * Kill-switch PostUp/PreDown pair: block all non-tunnel egress while the
 * interface is up, so a dropped tunnel fails closed instead of silently
 * falling back to the normal internet path (parity with commercial VPN
 * clients). Platform-specific because there's no portable firewall API.
 *  - Linux: the documented wg-quick(8) idiom — reject everything not exiting
 *    via %i or carrying WireGuard's own fwmark, so the handshake itself is
 *    never blocked.
 *  - macOS: a dedicated pf anchor scoped to this interface; default-deny,
 *    explicit allow for loopback, the tunnel interface, and the endpoint
 *    (needed for the handshake/keepalive to reach the server at all).
 */
function killSwitchRules(o) {
  const platform = o.platform || process.platform;
  if (platform === 'darwin') {
    const { host } = splitEndpoint(o.endpoint);
    const rules = `block drop out all\\npass out quick on lo0\\npass out quick on %i\\npass out quick proto { udp tcp } to ${host}\\n`;
    return {
      postUp: `printf '${rules}' | pfctl -a kasbah/%i -f -; pfctl -e 2>/dev/null || true`,
      preDown: `pfctl -a kasbah/%i -F all`,
    };
  }
  return {
    postUp:
      `iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT; ` +
      `ip6tables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT`,
    preDown:
      `iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT; ` +
      `ip6tables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT`,
  };
}

/**
 * Personal client config (full dual-stack tunnel by default).
 * @param {object} o { privateKey, address, address6?, dns?, serverPublicKey, presharedKey?,
 *                     endpoint, allowedIPs?, keepalive?, mtu?, killSwitch?, platform? }
 *   address6: pass `false` to keep the interface IPv4-only (e.g. split-AI,
 *   where the AllowedIPs allowlist never includes v6 anyway).
 */
function clientConf(o) {
  if (!o.privateKey || !o.serverPublicKey || !o.endpoint || !o.address) {
    throw new Error('clientConf requires privateKey, serverPublicKey, endpoint, address');
  }
  const address6 = o.address6 === false ? null : o.address6 || subnet6For(o.address);
  const ks = o.killSwitch ? killSwitchRules(o) : null;
  const iface = iniSection('Interface', [
    ['PrivateKey', o.privateKey],
    ['Address', address6 ? `${o.address}, ${address6}/64` : o.address],
    ['DNS', o.dns === false ? null : o.dns || DEFAULT_DNS],
    ['MTU', o.mtu],
    ['PostUp', ks?.postUp],
    ['PreDown', ks?.preDown],
  ]);
  const peer = iniSection('Peer', [
    ['PublicKey', o.serverPublicKey],
    ['PresharedKey', o.presharedKey],
    ['AllowedIPs', o.allowedIPs || (address6 ? '0.0.0.0/0, ::/0' : '0.0.0.0/0')],
    ['Endpoint', o.endpoint],
    ['PersistentKeepalive', o.keepalive ?? DEFAULT_KEEPALIVE],
  ]);
  return `${iface}\n\n${peer}\n`;
}

/**
 * Exit-node server config with dual-stack NAT masquerade.
 * @param {object} o { privateKey, subnet?, subnet6?, port?, wanInterface?, peers: [{name?,
 *                     publicKey, presharedKey?, address, address6?}] }
 *   subnet6: pass `false` to disable IPv6 entirely (no address, no ip6tables).
 */
function serverConf(o) {
  if (!o.privateKey || !Array.isArray(o.peers)) {
    throw new Error('serverConf requires privateKey and peers[]');
  }
  const subnet = o.subnet || DEFAULT_SUBNET;
  const subnet6 = o.subnet6 === false ? null : o.subnet6 || DEFAULT_SUBNET6;
  const wan = o.wanInterface || 'eth0';
  const nat6 = subnet6
    ? `; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE`
    : '';
  const unnat6 = subnet6
    ? `; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${wan} -j MASQUERADE`
    : '';
  const nat =
    `iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; ` +
    `iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE${nat6}`;
  const unnat =
    `iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; ` +
    `iptables -t nat -D POSTROUTING -o ${wan} -j MASQUERADE${unnat6}`;
  const iface = iniSection('Interface', [
    ['Address', subnet6 ? `${subnet}.1/24, ${subnet6}1/64` : `${subnet}.1/24`],
    ['ListenPort', o.port || DEFAULT_PORT],
    ['PrivateKey', o.privateKey],
    ['PostUp', nat],
    ['PostDown', unnat],
  ]);
  const peers = o.peers.map((p) => {
    if (!p.publicKey || !p.address) throw new Error('each peer requires publicKey and address');
    const address6 = subnet6 ? p.address6 || subnet6For(p.address, subnet6) : null;
    const section = iniSection('Peer', [
      ['PublicKey', p.publicKey],
      ['PresharedKey', p.presharedKey],
      ['AllowedIPs', address6 ? `${p.address}/32, ${address6}/128` : `${p.address}/32`],
    ]);
    return p.name ? `# ${p.name}\n${section}` : section;
  });
  return [iface, ...peers].join('\n\n') + '\n';
}

/**
 * Resolve AI provider hostnames → AllowedIPs list for a split-AI tunnel.
 * Best-effort: providers behind rotating CDN IPs may drift out of the route
 * set; callers regenerate periodically or use full tunnel.
 */
async function resolveAiAllowedIPs({ providers = AI_PROVIDERS, lookup = dns.lookup } = {}) {
  const out = [];
  for (const p of providers) {
    try {
      const addrs = await lookup(p.host, { all: true, family: 4 });
      for (const a of addrs) out.push({ provider: p.slug, host: p.host, cidr: `${a.address}/32` });
    } catch {
      // Unresolvable host (offline, blocked): skip — split config stays valid.
    }
  }
  // Dedupe CIDRs while keeping first provider attribution.
  const seen = new Set();
  return out.filter((e) => (seen.has(e.cidr) ? false : (seen.add(e.cidr), true)));
}

/**
 * Split-AI client config: only resolved AI provider IPs (plus the VPN subnet)
 * route through the tunnel; everything else stays on the local network.
 */
async function splitAiClientConf(o, resolveOpts) {
  const entries = await resolveAiAllowedIPs(resolveOpts);
  if (entries.length === 0) {
    throw new Error('could not resolve any AI provider IPs — offline? Use full tunnel instead.');
  }
  const subnet = o.subnet || DEFAULT_SUBNET;
  const allowedIPs = [`${subnet}.0/24`, ...entries.map((e) => e.cidr)].join(', ');
  // AI provider IPs are resolved IPv4-only (family: 4 above), so there's
  // nothing for an IPv6 address on this interface to route — keep it v4-only
  // rather than advertise dual-stack and have ::/0 silently do nothing.
  const conf = clientConf({ ...o, allowedIPs, dns: o.dns ?? false, address6: false });
  const header =
    `# Kasbah split-AI tunnel — only AI provider traffic routes through the VPN.\n` +
    `# Resolved ${entries.length} endpoints at ${new Date().toISOString()}.\n` +
    `# Provider IPs rotate behind CDNs: regenerate periodically (kasbah-vpn config client --split ai).\n`;
  return { conf: header + conf, entries };
}

/**
 * Extract the port a node should listen on from its own advertised endpoint
 * (e.g. "127.0.0.1:51901" or "[::1]:51901" -> 51901). Falls back to an
 * explicit node.port, then the mesh-wide default. Using the shared default
 * for every anchored node breaks same-host mesh tests (two nodes bound to
 * different endpoint ports still both try to listen on the one default port).
 */
function listenPortFor(node, fallbackPort) {
  if (node.port) return node.port;
  const m = node.endpoint && String(node.endpoint).match(/:(\d+)$/);
  return m ? Number(m[1]) : fallbackPort;
}

/**
 * Governed mesh: N nodes, full peer sections each way. MCP servers/agents on
 * different machines talk over encrypted WG links with stable dual-stack IPs.
 * @param {Array<{name, privateKey, publicKey, endpoint?, port?, psk?: Record<peerName,string>}>} nodes
 * @param {{subnet?, subnet6?: string|false, port?}} opts subnet6: false for IPv4-only mesh
 * @returns {Record<name, string>} name → .conf
 */
function meshConfs(nodes, { subnet = DEFAULT_SUBNET, subnet6 = DEFAULT_SUBNET6, port = DEFAULT_PORT } = {}) {
  if (!Array.isArray(nodes) || nodes.length < 2) throw new Error('mesh needs at least 2 nodes');
  const names = new Set();
  for (const n of nodes) {
    if (!n.name || !n.privateKey || !n.publicKey) {
      throw new Error('each mesh node requires name, privateKey, publicKey');
    }
    if (names.has(n.name)) throw new Error(`duplicate mesh node name: ${n.name}`);
    names.add(n.name);
  }
  const addressed = nodes.map((n, i) => ({
    ...n,
    address: `${subnet}.${i + 1}`,
    address6: subnet6 === false ? null : `${subnet6}${i + 1}`,
  }));
  const confs = {};
  for (const node of addressed) {
    const iface = iniSection('Interface', [
      ['Address', node.address6 ? `${node.address}/24, ${node.address6}/64` : `${node.address}/24`],
      ['ListenPort', node.endpoint ? listenPortFor(node, port) : null],
      ['PrivateKey', node.privateKey],
    ]);
    const peers = addressed
      .filter((p) => p.name !== node.name)
      .map((p) =>
        `# ${p.name}\n` +
        iniSection('Peer', [
          ['PublicKey', p.publicKey],
          ['PresharedKey', node.psk?.[p.name] || p.psk?.[node.name]],
          ['AllowedIPs', p.address6 ? `${p.address}/32, ${p.address6}/128` : `${p.address}/32`],
          ['Endpoint', p.endpoint],
          ['PersistentKeepalive', p.endpoint ? null : DEFAULT_KEEPALIVE],
        ])
      );
    confs[node.name] = [
      `# Kasbah governed mesh — node "${node.name}" (${node.address})`,
      iface,
      ...peers,
    ].join('\n\n') + '\n';
  }
  return confs;
}

module.exports = {
  clientConf,
  serverConf,
  splitAiClientConf,
  resolveAiAllowedIPs,
  meshConfs,
  killSwitchRules,
  DEFAULT_SUBNET,
  DEFAULT_SUBNET6,
  DEFAULT_PORT,
};
