'use strict';

/** kasbah-vpn test suite — `node test.js`. No network, no root, no wg needed. */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

// Isolate state before requiring modules that read the env at call time.
process.env.KASBAH_VPN_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'kasbah-vpn-test-'));

const keys = require('./src/keys');
const psk = require('./src/psk');
const config = require('./src/config');
const receipts = require('./src/receipts');
const { startAiLane } = require('./src/ai-lane');
const { AI_PROVIDERS } = require('./src/providers');

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failures.push({ name, error: e.message });
    console.log(`  ✗ ${name}: ${e.message}`);
  }
}

(async () => {
  console.log('kasbah-vpn tests\n');

  // ── keys ──
  await test('generates valid wg keypair (32-byte base64)', () => {
    const kp = keys.generateWgKeypair();
    assert.ok(keys.isWgKey(kp.privateKey));
    assert.ok(keys.isWgKey(kp.publicKey));
    assert.notStrictEqual(kp.privateKey, kp.publicKey);
  });

  await test('wgPublicKeyOf derives the matching public key', () => {
    const kp = keys.generateWgKeypair();
    assert.strictEqual(keys.wgPublicKeyOf(kp.privateKey), kp.publicKey);
  });

  await test('isWgKey rejects garbage', () => {
    assert.strictEqual(keys.isWgKey('not-a-key'), false);
    assert.strictEqual(keys.isWgKey(Buffer.from('short').toString('base64')), false);
  });

  // ── post-quantum PSK ──
  await test('ML-KEM-768: initiator and responder derive identical PSK', () => {
    const server = psk.kemKeypair();
    const offer = psk.encapsulate(server.publicKey);
    const accept = psk.decapsulate(server.secretKey, offer.ciphertext);
    assert.strictEqual(offer.psk, accept.psk);
    assert.strictEqual(Buffer.from(offer.psk, 'base64').length, 32);
  });

  await test('different encapsulations yield different PSKs', () => {
    const server = psk.kemKeypair();
    const a = psk.encapsulate(server.publicKey);
    const b = psk.encapsulate(server.publicKey);
    assert.notStrictEqual(a.psk, b.psk);
  });

  await test('randomPsk is a valid 32-byte wg key', () => {
    assert.strictEqual(Buffer.from(psk.randomPsk(), 'base64').length, 32);
  });

  // ── config generation ──
  const kpC = keys.generateWgKeypair();
  const kpS = keys.generateWgKeypair();

  await test('clientConf renders full tunnel', () => {
    const conf = config.clientConf({
      privateKey: kpC.privateKey,
      address: '10.77.0.2/24',
      serverPublicKey: kpS.publicKey,
      presharedKey: psk.randomPsk(),
      endpoint: 'vpn.example.com:51820',
    });
    assert.ok(conf.includes('[Interface]') && conf.includes('[Peer]'));
    assert.ok(conf.includes('AllowedIPs = 0.0.0.0/0, ::/0'));
    assert.ok(conf.includes('PresharedKey ='));
    assert.ok(conf.includes('Endpoint = vpn.example.com:51820'));
    assert.ok(conf.includes('DNS = 1.1.1.1'));
  });

  await test('clientConf requires mandatory fields', () => {
    assert.throws(() => config.clientConf({ privateKey: kpC.privateKey }));
  });

  await test('clientConf auto-derives a mirrored IPv6 address (dual-stack by default)', () => {
    const conf = config.clientConf({
      privateKey: kpC.privateKey,
      address: '10.77.0.2/24',
      serverPublicKey: kpS.publicKey,
      endpoint: 'vpn.example.com:51820',
    });
    assert.ok(conf.includes('Address = 10.77.0.2/24, fd7a:6b1a:cafe::2/64'));
  });

  await test('clientConf address6: false stays IPv4-only (no false ::/0 promise)', () => {
    const conf = config.clientConf({
      privateKey: kpC.privateKey,
      address: '10.77.0.2/24',
      serverPublicKey: kpS.publicKey,
      endpoint: 'vpn.example.com:51820',
      address6: false,
    });
    assert.ok(conf.includes('Address = 10.77.0.2/24'));
    assert.ok(!conf.includes('fd7a'));
    assert.ok(conf.includes('AllowedIPs = 0.0.0.0/0'));
    assert.ok(!conf.includes('::/0'));
  });

  await test('clientConf killSwitch on Linux uses the wg-quick(8) fwmark idiom', () => {
    const conf = config.clientConf({
      privateKey: kpC.privateKey,
      address: '10.77.0.2/24',
      serverPublicKey: kpS.publicKey,
      endpoint: 'vpn.example.com:51820',
      killSwitch: true,
      platform: 'linux',
    });
    assert.ok(conf.includes('PostUp = iptables -I OUTPUT ! -o %i'));
    assert.ok(conf.includes('ip6tables -I OUTPUT'));
    assert.ok(conf.includes('PreDown = iptables -D OUTPUT ! -o %i'));
  });

  await test('clientConf killSwitch on macOS scopes a pf anchor and allows the endpoint through', () => {
    const conf = config.clientConf({
      privateKey: kpC.privateKey,
      address: '10.77.0.2/24',
      serverPublicKey: kpS.publicKey,
      endpoint: '203.0.113.10:51820',
      killSwitch: true,
      platform: 'darwin',
    });
    assert.ok(conf.includes('pfctl -a kasbah/%i -f -'));
    assert.ok(conf.includes('to 203.0.113.10'));
    assert.ok(conf.includes('PreDown = pfctl -a kasbah/%i -F all'));
  });

  await test('serverConf renders NAT + one section per peer', () => {
    const conf = config.serverConf({
      privateKey: kpS.privateKey,
      peers: [
        { name: 'alice', publicKey: kpC.publicKey, address: '10.77.0.2' },
        { name: 'bob', publicKey: keys.generateWgKeypair().publicKey, address: '10.77.0.3' },
      ],
    });
    assert.strictEqual((conf.match(/\[Peer\]/g) || []).length, 2);
    assert.ok(conf.includes('MASQUERADE'));
    assert.ok(conf.includes('ip6tables -t nat -A POSTROUTING'));
    assert.ok(conf.includes('ListenPort = 51820'));
    assert.ok(conf.includes('AllowedIPs = 10.77.0.2/32, fd7a:6b1a:cafe::2/128'));
  });

  await test('serverConf subnet6: false disables IPv6 entirely', () => {
    const conf = config.serverConf({
      privateKey: kpS.privateKey,
      subnet6: false,
      peers: [{ name: 'alice', publicKey: kpC.publicKey, address: '10.77.0.2' }],
    });
    assert.ok(!conf.includes('ip6tables'));
    assert.ok(!conf.includes('fd7a'));
    assert.ok(conf.includes('AllowedIPs = 10.77.0.2/32'));
  });

  await test('splitAiClientConf routes only resolved AI IPs (mock DNS)', async () => {
    const lookup = async (host) => [{ address: '203.0.113.7', family: 4 }];
    const { conf, entries } = await config.splitAiClientConf(
      {
        privateKey: kpC.privateKey,
        address: '10.77.0.2/24',
        serverPublicKey: kpS.publicKey,
        endpoint: 'vpn.example.com:51820',
      },
      { providers: [{ slug: 'openai', host: 'api.openai.com' }], lookup }
    );
    assert.strictEqual(entries.length, 1);
    assert.ok(conf.includes('AllowedIPs = 10.77.0.0/24, 203.0.113.7/32'));
    assert.ok(!conf.includes('0.0.0.0/0'));
  });

  await test('splitAiClientConf fails closed when nothing resolves', async () => {
    const lookup = async () => {
      throw new Error('offline');
    };
    await assert.rejects(
      config.splitAiClientConf(
        { privateKey: kpC.privateKey, address: '10.77.0.2/24', serverPublicKey: kpS.publicKey, endpoint: 'e:1' },
        { providers: AI_PROVIDERS, lookup }
      )
    );
  });

  await test('meshConfs: every node peers with every other, PSKs symmetric', () => {
    const nodes = ['a', 'b', 'c'].map((name) => ({ name, ...keys.generateWgKeypair(), psk: {} }));
    nodes[0].psk.b = psk.randomPsk();
    nodes[0].psk.c = psk.randomPsk();
    nodes[1].psk.c = psk.randomPsk();
    nodes[0].endpoint = '198.51.100.1:51820';
    const confs = config.meshConfs(nodes);
    assert.deepStrictEqual(Object.keys(confs).sort(), ['a', 'b', 'c']);
    for (const conf of Object.values(confs)) {
      assert.strictEqual((conf.match(/\[Peer\]/g) || []).length, 2);
    }
    // a↔b share the same PSK line in both configs
    const pskAB = nodes[0].psk.b;
    assert.ok(confs.a.includes(pskAB) && confs.b.includes(pskAB));
    // roaming nodes keepalive toward the anchored one
    assert.ok(confs.b.includes('PersistentKeepalive'));
  });

  await test('meshConfs: same-host nodes with distinct endpoint ports do not collide', () => {
    // Regression: both nodes used to get ListenPort = DEFAULT_PORT regardless
    // of their own endpoint, so two loopback peers on one machine collided
    // on 51820 ("Unable to modify interface: Address already in use").
    const a = { name: 'this-mac-a', ...keys.generateWgKeypair(), endpoint: '127.0.0.1:51900', psk: {} };
    const b = { name: 'this-mac-b', ...keys.generateWgKeypair(), endpoint: '127.0.0.1:51901', psk: {} };
    a.psk.b = psk.randomPsk();
    const confs = config.meshConfs([a, b]);
    assert.ok(confs['this-mac-a'].includes('ListenPort = 51900'));
    assert.ok(confs['this-mac-b'].includes('ListenPort = 51901'));
  });

  await test('meshConfs mirrors dual-stack addressing per node', () => {
    const nodes = ['a', 'b'].map((name) => ({ name, ...keys.generateWgKeypair(), psk: {} }));
    nodes[0].psk.b = psk.randomPsk();
    const confs = config.meshConfs(nodes);
    assert.ok(confs.a.includes('Address = 10.77.0.1/24, fd7a:6b1a:cafe::1/64'));
    assert.ok(confs.a.includes('AllowedIPs = 10.77.0.2/32, fd7a:6b1a:cafe::2/128'));
  });

  await test('meshConfs rejects <2 nodes and duplicate names', () => {
    assert.throws(() => config.meshConfs([{ name: 'a', ...keys.generateWgKeypair() }]));
    const kp = keys.generateWgKeypair();
    assert.throws(() =>
      config.meshConfs([
        { name: 'x', ...kp },
        { name: 'x', ...keys.generateWgKeypair() },
      ])
    );
  });

  // ── receipts ──
  await test('records chained receipts that verify offline', () => {
    receipts.record('vpn.up', { split: 'full', endpoint: 'vpn.example.com:51820' });
    receipts.record('vpn.down', { endpoint: 'vpn.example.com:51820' });
    const all = receipts.list();
    assert.ok(all.length >= 2);
    const last = all[all.length - 1];
    assert.strictEqual(last.decoded.action, 'vpn.down');
    assert.strictEqual(last.decoded.parentReceipt, all[all.length - 2].receipt);
    const v = receipts.verifyAll();
    assert.strictEqual(v.valid, v.total);
  });

  await test('tampered receipt log fails verification', () => {
    const logPath = path.join(process.env.KASBAH_VPN_DIR, 'receipts.jsonl');
    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    const entry = JSON.parse(lines[0]);
    entry.payload = Buffer.from(JSON.stringify({ forged: true })).toString('base64url');
    lines[0] = JSON.stringify(entry);
    const backup = fs.readFileSync(logPath);
    fs.writeFileSync(logPath, lines.join('\n') + '\n');
    const v = receipts.verifyAll();
    fs.writeFileSync(logPath, backup);
    assert.ok(v.valid < v.total);
  });

  // ── AI lane ──
  await test('ai-lane forwards provider requests to gateway /v1/proxy/*', async () => {
    let seen = null;
    const mockGateway = http.createServer((req, res) => {
      seen = { url: req.url, method: req.method, auth: req.headers.authorization };
      res.writeHead(200, { 'content-type': 'application/json', 'x-kasbah-receipt': 'kasbah_receipt:v3:test' });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise((r) => mockGateway.listen(0, '127.0.0.1', r));
    const gwPort = mockGateway.address().port;
    const lane = await startAiLane({ port: 0, gateway: `http://127.0.0.1:${gwPort}` });
    const lanePort = lane.server.address().port;

    const resp = await fetch(`http://127.0.0.1:${lanePort}/openai/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer sk-test' },
      body: JSON.stringify({ model: 'gpt-4o', messages: [] }),
    });
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.headers.get('x-kasbah-receipt'), 'kasbah_receipt:v3:test');
    assert.strictEqual(seen.url, '/v1/proxy/openai/v1/chat/completions');
    assert.strictEqual(seen.auth, 'Bearer sk-test');

    const unknown = await fetch(`http://127.0.0.1:${lanePort}/notaprovider/x`);
    assert.strictEqual(unknown.status, 404);

    lane.server.close();
    mockGateway.close();
  });

  await test('ai-lane health endpoint lists providers', async () => {
    const lane = await startAiLane({ port: 0, gateway: 'http://127.0.0.1:1' });
    const port = lane.server.address().port;
    const health = await (await fetch(`http://127.0.0.1:${port}/health`)).json();
    assert.strictEqual(health.service, 'kasbah-vpn ai-lane');
    assert.ok(health.providers.includes('anthropic'));
    lane.server.close();
  });

  // ── summary ──
  const total = passed + failures.length;
  console.log(`\n${passed}/${total} tests passed`);
  if (failures.length) {
    for (const f of failures) console.error(`FAIL: ${f.name} — ${f.error}`);
    process.exit(1);
  }
})();
