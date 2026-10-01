#!/usr/bin/env node
'use strict';

/**
 * Local dashboard for kasbah-vpn — thin HTTP wrapper over src/*.js so you can
 * click through init/join/config/mesh/receipts instead of typing CLI flags.
 * No new logic lives here; every route just calls the same functions the CLI
 * calls. Binds to 127.0.0.1 only.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const keys = require('../src/keys');
const psk = require('../src/psk');
const config = require('../src/config');
const store = require('../src/store');
const receipts = require('../src/receipts');
const wg = require('../src/wg');
const { startAiLane, DEFAULT_PORT: AI_LANE_PORT, DEFAULT_GATEWAY } = require('../src/ai-lane');

const PORT = Number(process.env.PORT || 4500);
let aiLaneHandle = null;
let lastAiLaneEvents = [];

// Strip private key material before it ever reaches the browser — the
// dashboard only needs to display public keys and public metadata.
function redactProfile(profile) {
  if (!profile) return profile;
  return {
    ...profile,
    wg: profile.wg ? { publicKey: profile.wg.publicKey } : null,
    kem: profile.kem ? { publicKey: profile.kem.publicKey } : null,
    client: profile.client ? { ...profile.client, presharedKey: profile.client.presharedKey ? '(set)' : null } : null,
    peers: (profile.peers || []).map((p) => ({ ...p, presharedKey: p.presharedKey ? '(set)' : null })),
  };
}

function json(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj, null, 2));
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return {};
  }
}

const routes = {
  'GET /api/state': async () => {
    const profile = store.loadProfile();
    const tools = wg.detect();
    return {
      profile: redactProfile(profile),
      wireguard: tools,
      receipts: receipts.list(),
      aiLane: aiLaneHandle ? { running: true, port: aiLaneHandle.port, gateway: aiLaneHandle.gateway } : { running: false },
      aiLaneEvents: lastAiLaneEvents.slice(-20),
    };
  },

  'POST /api/init': async (req) => {
    const body = await readBody(req);
    if (store.loadProfile() && !body.force) throw new Error('profile exists — pass force to overwrite');
    const wgKeys = keys.generateWgKeypair();
    let kem = null;
    try { kem = psk.kemKeypair(); } catch { /* optional dep missing */ }
    const profile = {
      name: body.name || 'kasbah-vpn',
      created: new Date().toISOString(),
      wg: wgKeys,
      kem,
      peers: [],
      server: null,
      client: null,
    };
    store.saveProfile(profile);
    receipts.record('vpn.init', { publicKey: wgKeys.publicKey, pq: !!kem });
    return { ok: true, profile: redactProfile(profile) };
  },

  'POST /api/server-init': async (req) => {
    const body = await readBody(req);
    const profile = store.loadProfile();
    if (!profile) throw new Error('no profile — init first');
    if (!body.endpoint) throw new Error('endpoint required');
    profile.server = {
      endpoint: body.endpoint,
      port: Number(body.port || config.DEFAULT_PORT),
      subnet: body.subnet || config.DEFAULT_SUBNET,
      subnet6: body.noIpv6 ? false : body.subnet6 || config.DEFAULT_SUBNET6,
      wanInterface: body.wanInterface || 'eth0',
    };
    store.saveProfile(profile);
    receipts.record('server.init', { endpoint: profile.server.endpoint, port: profile.server.port });
    return { ok: true, profile: redactProfile(profile) };
  },

  'POST /api/join': async (req) => {
    const body = await readBody(req);
    const profile = store.loadProfile();
    if (!profile) throw new Error('no profile — init first');
    if (!body.endpoint || !body.serverPublicKey) throw new Error('endpoint and serverPublicKey required');
    if (!keys.isWgKey(body.serverPublicKey)) throw new Error('serverPublicKey is not a valid WireGuard key');
    let presharedKey = null, ciphertext = null;
    if (body.serverKemPub) {
      const enc = psk.encapsulate(body.serverKemPub);
      presharedKey = enc.psk;
      ciphertext = enc.ciphertext;
    }
    profile.client = {
      endpoint: body.endpoint,
      serverPublicKey: body.serverPublicKey,
      address: body.address || `${config.DEFAULT_SUBNET}.2/24`,
      presharedKey,
    };
    store.saveProfile(profile);
    receipts.record('vpn.join', { endpoint: body.endpoint, serverPublicKey: body.serverPublicKey, pqPsk: !!presharedKey });
    return { ok: true, profile: redactProfile(profile), kemCiphertext: ciphertext };
  },

  'POST /api/peer-add': async (req) => {
    const body = await readBody(req);
    const profile = store.loadProfile();
    if (!profile) throw new Error('no profile — init first');
    if (!profile.server) throw new Error('run server-init first');
    if (!body.name || !body.publicKey) throw new Error('name and publicKey required');
    if (!keys.isWgKey(body.publicKey)) throw new Error('publicKey is not a valid WireGuard key');
    if (profile.peers.some((p) => p.name === body.name)) throw new Error(`peer "${body.name}" already exists`);
    let presharedKey = null;
    if (body.kemCiphertext) {
      if (!profile.kem) throw new Error('profile has no KEM key');
      presharedKey = psk.decapsulate(profile.kem.secretKey, body.kemCiphertext).psk;
    }
    const subnet = profile.server.subnet;
    const used = new Set(profile.peers.map((p) => p.address));
    let hostNum = 2;
    while (used.has(`${subnet}.${hostNum}`)) hostNum++;
    const peer = { name: body.name, publicKey: body.publicKey, address: `${subnet}.${hostNum}`, presharedKey };
    profile.peers.push(peer);
    store.saveProfile(profile);
    receipts.record('peer.add', { name: peer.name, publicKey: peer.publicKey, address: peer.address, pqPsk: !!presharedKey });
    return { ok: true, peer: { ...peer, presharedKey: peer.presharedKey ? '(set)' : null }, profile: redactProfile(profile) };
  },

  'GET /api/config/client': async (req, res, url) => {
    const profile = store.loadProfile();
    if (!profile?.client) throw new Error('no client config — join first');
    const base = {
      privateKey: profile.wg.privateKey,
      address: profile.client.address,
      serverPublicKey: profile.client.serverPublicKey,
      presharedKey: profile.client.presharedKey || undefined,
      endpoint: profile.client.endpoint,
      killSwitch: url.searchParams.get('killSwitch') === 'true',
    };
    if (url.searchParams.get('split') === 'ai') {
      const { conf, entries } = await config.splitAiClientConf(base);
      return { conf, entries };
    }
    return { conf: config.clientConf(base) };
  },

  'GET /api/config/server': async () => {
    const profile = store.loadProfile();
    if (!profile?.server) throw new Error('no server config — server-init first');
    const conf = config.serverConf({
      privateKey: profile.wg.privateKey,
      subnet: profile.server.subnet,
      subnet6: profile.server.subnet6,
      port: profile.server.port,
      wanInterface: profile.server.wanInterface,
      peers: profile.peers,
    });
    return { conf };
  },

  'POST /api/mesh': async (req) => {
    const body = await readBody(req);
    const names = (body.nodes || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (names.length < 2) throw new Error('need at least 2 comma-separated node names');
    const endpoints = {};
    for (const pair of (body.endpoints || '').split(',').filter(Boolean)) {
      const [n, ...ep] = pair.split('=');
      endpoints[n.trim()] = ep.join('=').trim();
    }
    const nodes = names.map((name) => ({
      name,
      ...keys.generateWgKeypair(),
      endpoint: endpoints[name] ? (endpoints[name].includes(':') ? endpoints[name] : `${endpoints[name]}:${config.DEFAULT_PORT}`) : undefined,
      psk: {},
    }));
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) nodes[i].psk[nodes[j].name] = psk.randomPsk();
    }
    const confs = config.meshConfs(nodes);
    receipts.record('mesh.init', { nodes: names, endpoints });
    return { ok: true, confs, nodes: nodes.map((n) => ({ name: n.name, publicKey: n.publicKey, endpoint: n.endpoint || '(roaming)' })) };
  },

  'POST /api/ai-lane/start': async (req) => {
    const body = await readBody(req);
    if (aiLaneHandle) return { ok: true, already: true, port: aiLaneHandle.port, gateway: aiLaneHandle.gateway };
    lastAiLaneEvents = [];
    const lane = await startAiLane({
      port: Number(body.port || AI_LANE_PORT),
      gateway: body.gateway || DEFAULT_GATEWAY,
      onEvent: (e) => { lastAiLaneEvents.push({ ...e, ts: Date.now() }); },
    });
    aiLaneHandle = lane;
    receipts.record('ai-lane.start', { port: lane.port, gateway: lane.gateway });
    return { ok: true, port: lane.port, gateway: lane.gateway };
  },

  'POST /api/ai-lane/stop': async () => {
    if (aiLaneHandle) {
      aiLaneHandle.server.close();
      receipts.record('ai-lane.stop', { port: aiLaneHandle.port });
      aiLaneHandle = null;
    }
    return { ok: true };
  },

  'GET /api/receipts/verify': async () => receipts.verifyAll(),
};

// Any web page open in the same browser can fire a cross-origin fetch at a
// localhost port with a body/content-type that skips CORS preflight (e.g.
// `Content-Type: text/plain`) — the browser still sends it, it just can't
// read the response. Since these routes mint keys, overwrite the profile,
// and generate mesh configs, that's enough for a malicious page to trigger
// them blind. Browsers attach Origin on every state-changing request (not
// just cross-origin ones), so reject any mismatch — same-origin dashboard
// fetches and non-browser clients (curl, no Origin header) still pass.
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  return origin === `http://127.0.0.1:${PORT}` || origin === `http://localhost:${PORT}`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const key = `${req.method} ${url.pathname}`;

  if (req.method !== 'GET' && !originAllowed(req)) {
    json(res, 403, { error: 'cross-origin request rejected' });
    return;
  }

  if (routes[key]) {
    try {
      const result = await routes[key](req, res, url);
      json(res, 200, result);
    } catch (err) {
      json(res, 400, { error: err.message });
    }
    return;
  }

  // static file serving
  let filePath = url.pathname === '/' ? '/index.html' : url.pathname;
  filePath = path.join(__dirname, 'public', filePath);
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    res.writeHead(403); res.end('forbidden'); return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('not found'); return; }
    const ext = path.extname(filePath);
    const type = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' }[ext] || 'text/plain';
    res.writeHead(200, { 'content-type': type });
    res.end(data);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`kasbah-vpn dashboard on http://127.0.0.1:${PORT}`);
});
