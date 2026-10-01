#!/usr/bin/env node
'use strict';

/**
 * kasbah-vpn — personal WireGuard VPN with post-quantum hybrid PSKs,
 * AI-traffic governance lane, governed MCP mesh, and signed session receipts.
 *
 *   init                          mint WG + KEM + receipt keys
 *   join --endpoint --server-pubkey [--server-kem-pub] [--address]
 *                                 configure this machine as a client
 *   server init --endpoint [--port] [--subnet] [--subnet6] [--no-ipv6]
 *   peer add <name> --pubkey [--kem-ciphertext]
 *   psk offer <server-kem-pub>    encapsulate → PSK + ciphertext (client side)
 *   psk accept <ciphertext>       decapsulate → same PSK (server side)
 *   config client [--split ai] [--kill-switch] [--out FILE]
 *   config server [--out FILE]
 *   mesh init --nodes a,b,c [--endpoints a=host:port,...] [--out-dir DIR]
 *   up [--split ai] [--kill-switch] / down   wraps wg-quick (prints commands if missing)
 *   ai-lane [--port 8790] [--gateway URL]
 *   receipts list | verify
 *   status
 */

const fs = require('fs');
const path = require('path');
const keys = require('../src/keys');
const psk = require('../src/psk');
const config = require('../src/config');
const store = require('../src/store');
const receipts = require('../src/receipts');
const wg = require('../src/wg');
const { startAiLane, DEFAULT_PORT, DEFAULT_GATEWAY } = require('../src/ai-lane');

const argv = process.argv.slice(2);

function flag(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const v = argv[i + 1];
  return v && !v.startsWith('--') ? v : true;
}
function positional(n) {
  return argv.filter((a) => !a.startsWith('--')).filter((a, i, all) => {
    // drop values consumed by flags
    const prev = argv[argv.indexOf(a) - 1];
    return !(prev && prev.startsWith('--'));
  })[n];
}
function die(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}
function out(obj) {
  console.log(typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2));
}
function requireProfile() {
  const p = store.loadProfile();
  if (!p) die('no profile — run: kasbah-vpn init');
  return p;
}
function writeConf(conf, file) {
  if (file && file !== true) {
    fs.writeFileSync(file, conf, { mode: 0o600 });
    out(`wrote ${file}`);
  } else {
    process.stdout.write(conf);
  }
}

async function main() {
  const cmd = argv[0];
  const sub = argv[1];

  switch (cmd) {
    case 'init': {
      if (store.loadProfile() && !flag('force')) die('profile exists — use --force to overwrite');
      const wgKeys = keys.generateWgKeypair();
      let kem = null;
      try {
        kem = psk.kemKeypair();
      } catch {
        // @noble/post-quantum missing — classical-only profile, noted in output.
      }
      const profile = {
        name: typeof flag('name') === 'string' ? flag('name') : 'kasbah-vpn',
        created: new Date().toISOString(),
        wg: wgKeys,
        kem,
        peers: [],
        server: null,
        client: null,
      };
      store.saveProfile(profile);
      receipts.record('vpn.init', { publicKey: wgKeys.publicKey, pq: !!kem });
      out({
        ok: true,
        stateDir: store.stateDir(),
        publicKey: wgKeys.publicKey,
        kemPublicKey: kem ? kem.publicKey.slice(0, 32) + '… (full key: kasbah-vpn status --keys)' : null,
        postQuantum: kem ? 'ML-KEM-768 ready' : 'unavailable — install @noble/post-quantum',
      });
      break;
    }

    case 'join': {
      const profile = requireProfile();
      const endpoint = flag('endpoint');
      const serverPubkey = flag('server-pubkey');
      if (!endpoint || !serverPubkey) die('join requires --endpoint host:port and --server-pubkey');
      if (!keys.isWgKey(serverPubkey)) die('--server-pubkey is not a valid WireGuard key');
      let presharedKey = null;
      let ciphertext = null;
      const serverKemPub = flag('server-kem-pub');
      if (serverKemPub && serverKemPub !== true) {
        const enc = psk.encapsulate(serverKemPub);
        presharedKey = enc.psk;
        ciphertext = enc.ciphertext;
      }
      profile.client = {
        endpoint,
        serverPublicKey: serverPubkey,
        address: typeof flag('address') === 'string' ? flag('address') : `${config.DEFAULT_SUBNET}.2/24`,
        presharedKey,
      };
      store.saveProfile(profile);
      receipts.record('vpn.join', { endpoint, serverPublicKey: serverPubkey, pqPsk: !!presharedKey });
      out({
        ok: true,
        endpoint,
        pqPsk: !!presharedKey,
        ...(ciphertext
          ? { sendToServerOperator: { kemCiphertext: ciphertext, note: 'server runs: kasbah-vpn psk accept <ciphertext>' } }
          : { note: 'no --server-kem-pub given — tunnel is classical WG only (no PQ PSK)' }),
      });
      break;
    }

    case 'server': {
      if (sub !== 'init') die('usage: kasbah-vpn server init --endpoint <public-host>');
      const profile = requireProfile();
      const endpoint = flag('endpoint');
      if (!endpoint || endpoint === true) die('server init requires --endpoint <public-host>');
      profile.server = {
        endpoint,
        port: Number(flag('port', config.DEFAULT_PORT)),
        subnet: typeof flag('subnet') === 'string' ? flag('subnet') : config.DEFAULT_SUBNET,
        subnet6: flag('no-ipv6') ? false : typeof flag('subnet6') === 'string' ? flag('subnet6') : config.DEFAULT_SUBNET6,
        wanInterface: typeof flag('wan') === 'string' ? flag('wan') : 'eth0',
      };
      store.saveProfile(profile);
      receipts.record('server.init', { endpoint, port: profile.server.port });
      out({ ok: true, server: profile.server, kemPublicKey: profile.kem?.publicKey || null });
      break;
    }

    case 'peer': {
      if (sub !== 'add') die('usage: kasbah-vpn peer add <name> --pubkey <wg-pubkey> [--kem-ciphertext <ct>]');
      const profile = requireProfile();
      if (!profile.server) die('run: kasbah-vpn server init first');
      const name = positional(2) || flag('name');
      const pubkey = flag('pubkey');
      if (!name || !pubkey || pubkey === true) die('peer add requires a name and --pubkey');
      if (!keys.isWgKey(pubkey)) die('--pubkey is not a valid WireGuard key');
      if (profile.peers.some((p) => p.name === name)) die(`peer "${name}" already exists`);
      let presharedKey = null;
      const ct = flag('kem-ciphertext');
      if (ct && ct !== true) {
        if (!profile.kem) die('profile has no KEM key — reinit with @noble/post-quantum installed');
        presharedKey = psk.decapsulate(profile.kem.secretKey, ct).psk;
      }
      const subnet = profile.server.subnet;
      const used = new Set(profile.peers.map((p) => p.address));
      let hostNum = 2;
      while (used.has(`${subnet}.${hostNum}`)) hostNum++;
      const peer = { name, publicKey: pubkey, address: `${subnet}.${hostNum}`, presharedKey };
      profile.peers.push(peer);
      store.saveProfile(profile);
      receipts.record('peer.add', { name, publicKey: pubkey, address: peer.address, pqPsk: !!presharedKey });
      out({ ok: true, peer: { ...peer, presharedKey: presharedKey ? '(set)' : null } });
      break;
    }

    case 'psk': {
      if (sub === 'offer') {
        const kemPub = positional(2);
        if (!kemPub) die('usage: kasbah-vpn psk offer <server-kem-public-key-b64>');
        const enc = psk.encapsulate(kemPub);
        out({ psk: enc.psk, kemCiphertext: enc.ciphertext, note: 'give ciphertext to the server; keep psk for your [Peer] PresharedKey' });
      } else if (sub === 'accept') {
        const profile = requireProfile();
        if (!profile.kem) die('profile has no KEM key');
        const ct = positional(2);
        if (!ct) die('usage: kasbah-vpn psk accept <ciphertext-b64>');
        out({ psk: psk.decapsulate(profile.kem.secretKey, ct).psk });
      } else {
        die('usage: kasbah-vpn psk offer|accept …');
      }
      break;
    }

    case 'config': {
      const profile = requireProfile();
      if (sub === 'client') {
        if (!profile.client) die('run: kasbah-vpn join first');
        const base = {
          privateKey: profile.wg.privateKey,
          address: profile.client.address,
          serverPublicKey: profile.client.serverPublicKey,
          presharedKey: profile.client.presharedKey || undefined,
          endpoint: profile.client.endpoint,
          killSwitch: !!flag('kill-switch'),
        };
        if (flag('split') === 'ai') {
          const { conf, entries } = await config.splitAiClientConf(base);
          console.error(`# split-AI: routing ${entries.length} resolved AI endpoints through the tunnel`);
          writeConf(conf, flag('out'));
        } else {
          writeConf(config.clientConf(base), flag('out'));
        }
      } else if (sub === 'server') {
        if (!profile.server) die('run: kasbah-vpn server init first');
        const conf = config.serverConf({
          privateKey: profile.wg.privateKey,
          subnet: profile.server.subnet,
          subnet6: profile.server.subnet6,
          port: profile.server.port,
          wanInterface: profile.server.wanInterface,
          peers: profile.peers,
        });
        writeConf(conf, flag('out'));
      } else {
        die('usage: kasbah-vpn config client|server [--split ai] [--kill-switch] [--out FILE]');
      }
      break;
    }

    case 'mesh': {
      if (sub !== 'init') die('usage: kasbah-vpn mesh init --nodes a,b,c [--endpoints a=host:port,b=…]');
      const nodeNames = String(flag('nodes', '')).split(',').map((s) => s.trim()).filter(Boolean);
      if (nodeNames.length < 2) die('mesh init requires --nodes with at least 2 comma-separated names');
      const endpoints = {};
      for (const pair of String(flag('endpoints', '')).split(',').filter(Boolean)) {
        const [n, ...ep] = pair.split('=');
        endpoints[n.trim()] = ep.join('=').trim();
      }
      // All keys are generated on this machine (the operator owns every node),
      // so pairwise PSKs are local random 32-byte keys — the KEM exchange adds
      // nothing when both ends' secrets already share a filesystem.
      const nodes = nodeNames.map((name) => ({
        name,
        ...keys.generateWgKeypair(),
        endpoint: endpoints[name] ? (endpoints[name].includes(':') ? endpoints[name] : `${endpoints[name]}:${config.DEFAULT_PORT}`) : undefined,
        psk: {},
      }));
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          nodes[i].psk[nodes[j].name] = psk.randomPsk();
        }
      }
      const confs = config.meshConfs(nodes);
      const dir = typeof flag('out-dir') === 'string' ? flag('out-dir') : path.join(store.stateDir(), 'mesh');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      for (const [name, conf] of Object.entries(confs)) {
        fs.writeFileSync(path.join(dir, `${name}.conf`), conf, { mode: 0o600 });
      }
      receipts.record('mesh.init', { nodes: nodeNames, endpoints });
      out({
        ok: true,
        dir,
        nodes: nodes.map((n) => ({ name: n.name, publicKey: n.publicKey, endpoint: n.endpoint || '(roaming)' })),
        note: 'copy each <node>.conf to its machine, then: sudo wg-quick up ./<node>.conf',
      });
      break;
    }

    case 'up':
    case 'down': {
      const profile = requireProfile();
      if (!profile.client) die('run: kasbah-vpn join first');
      const base = {
        privateKey: profile.wg.privateKey,
        address: profile.client.address,
        serverPublicKey: profile.client.serverPublicKey,
        presharedKey: profile.client.presharedKey || undefined,
        endpoint: profile.client.endpoint,
        killSwitch: !!flag('kill-switch'),
      };
      const conf =
        flag('split') === 'ai' ? (await config.splitAiClientConf(base)).conf : config.clientConf(base);
      const r = wg.run(cmd, conf);
      receipts.record(`vpn.${cmd}`, {
        method: r.method,
        ok: r.ok,
        split: flag('split') === 'ai' ? 'ai' : 'full',
        endpoint: profile.client.endpoint,
      });
      out(r.output.trim() || (r.ok ? `tunnel ${cmd}` : 'failed'));
      if (!r.ok && r.method !== 'manual') process.exit(1);
      break;
    }

    case 'ai-lane': {
      const port = Number(flag('port', DEFAULT_PORT));
      const gateway = typeof flag('gateway') === 'string' ? flag('gateway') : DEFAULT_GATEWAY;
      const lane = await startAiLane({
        port,
        gateway,
        onEvent: (e) => console.error(`[ai-lane] ${e.type} ${e.provider} ${e.status}`),
      });
      receipts.record('ai-lane.start', { port: lane.port, gateway: lane.gateway });
      console.log(`AI lane on http://127.0.0.1:${lane.port} → ${lane.gateway}/v1/proxy/*`);
      console.log(`  OPENAI_BASE_URL=http://127.0.0.1:${lane.port}/openai/v1`);
      console.log(`  ANTHROPIC_BASE_URL=http://127.0.0.1:${lane.port}/anthropic`);
      break;
    }

    case 'receipts': {
      if (sub === 'verify') {
        const r = receipts.verifyAll();
        out(r);
        if (r.valid !== r.total) process.exit(1);
      } else {
        out(receipts.list().map((e) => ({ id: e.decoded.id, action: e.decoded.action, ts: new Date(e.decoded.ts).toISOString() })));
      }
      break;
    }

    case 'status': {
      const profile = store.loadProfile();
      const tools = wg.detect();
      out({
        profile: profile
          ? {
              name: profile.name,
              publicKey: profile.wg.publicKey,
              postQuantum: !!profile.kem,
              ...(flag('keys') ? { kemPublicKey: profile.kem?.publicKey } : {}),
              role: profile.server ? 'server' : profile.client ? 'client' : 'unconfigured',
              peers: profile.peers.length,
            }
          : null,
        wireguard: { installed: !!tools.wgQuick, ...tools },
        tunnel: tools.wg ? wg.status().output : 'wg not installed',
        receipts: receipts.list().length,
      });
      break;
    }

    default:
      out(
        [
          'kasbah-vpn — WireGuard VPN with post-quantum PSKs, AI governance lane, mesh, signed receipts',
          '',
          '  init [--name N] [--force]           mint keys',
          '  join --endpoint H:P --server-pubkey K [--server-kem-pub K] [--address IP/24]',
          '  server init --endpoint HOST [--port] [--subnet] [--subnet6] [--no-ipv6] [--wan IFACE]',
          '  peer add NAME --pubkey K [--kem-ciphertext CT]',
          '  psk offer KEM_PUB | psk accept CT   post-quantum PSK exchange',
          '  config client [--split ai] [--kill-switch] [--out F]',
          '  config server [--out F]',
          '  mesh init --nodes a,b,c [--endpoints a=host:port,...] [--out-dir D]',
          '  up [--split ai] [--kill-switch] | down   needs wireguard-tools + sudo',
          '    --kill-switch: block all non-tunnel egress while up (fails closed if the tunnel drops)',
          '  ai-lane [--port 8790] [--gateway URL]',
          '  receipts list | verify',
          '  status [--keys]',
        ].join('\n')
      );
  }
}

main().catch((e) => die(e.message));
