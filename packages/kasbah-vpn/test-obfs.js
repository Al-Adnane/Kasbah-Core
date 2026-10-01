'use strict';
/** Obfuscation plan tests — Myanmar / DPI mode. No network. */

const assert = require('assert');
const { obfsPlan, applyObfsToClientConf, serverDeployScript, splitEndpoint } = require('./src/obfs');
const { clientConf } = require('./src/config');
const { generateWgKeypair } = require('./src/keys');
const { randomPsk } = require('./src/psk');

let pass = 0, fail = 0;
function ok(m) { console.log('  ✓ ' + m); pass++; }
function bad(m) { console.error('  ✗ ' + m); fail++; }

function t(name, fn) {
  try { fn(); ok(name); } catch (e) { bad(name + ' — ' + e.message); }
}

console.log('kasbah-vpn obfs tests\n');

t('splitEndpoint parses host:port', () => {
  assert.deepStrictEqual(splitEndpoint('203.0.113.10:51820'), { host: '203.0.113.10', port: '51820' });
});

t('obfsPlan defaults to TCP 443 + local 51821', () => {
  const p = obfsPlan({ endpoint: 'sg.example.com:51820' });
  assert.strictEqual(p.mode, 'tcp');
  assert.strictEqual(p.obfsPort, 443);
  assert.strictEqual(p.localPort, 51821);
  assert.strictEqual(p.clientEndpoint, '127.0.0.1:51821');
  assert.ok(p.clientCmd.includes('udp://127.0.0.1:51821:sg.example.com:51820'));
  assert.ok(p.clientCmd.includes('ws://sg.example.com:443'));
  assert.ok(p.serverCmd.includes('ws://0.0.0.0:443'));
  assert.ok(p.serverCmd.includes('restrict-to'));
});

t('obfsPlan wss mode uses wss://', () => {
  const p = obfsPlan({ endpoint: 'hk.example.com:51820', mode: 'wss', obfsPort: 443 });
  assert.ok(p.clientCmd.includes('wss://'));
  assert.ok(p.serverCmd.includes('wss://'));
});

t('applyObfsToClientConf rewrites Endpoint only', () => {
  const keys = generateWgKeypair();
  const conf = clientConf({
    privateKey: keys.privateKey,
    serverPublicKey: keys.publicKey,
    presharedKey: randomPsk(),
    endpoint: 'sg.example.com:51820',
    address: '10.77.0.2/24',
    killSwitch: true,
    platform: 'linux',
  });
  const p = obfsPlan({ endpoint: 'sg.example.com:51820' });
  const out = applyObfsToClientConf(conf, p);
  assert.ok(out.includes('Endpoint = 127.0.0.1:51821'));
  assert.ok(!out.includes('Endpoint = sg.example.com:51820'));
  assert.ok(out.includes('PrivateKey')); // rest intact
  assert.ok(out.includes('iptables')); // kill-switch kept
});

t('serverDeployScript includes wstunnel unit + local-only WG', () => {
  const p = obfsPlan({ endpoint: 'sg.example.com:51820' });
  const s = serverDeployScript(p);
  assert.ok(s.includes('kasbah-wstunnel.service'));
  assert.ok(s.includes('wstunnel'));
  assert.ok(s.includes('wg-quick@kasbah0'));
});

console.log(`\n${pass} passed · ${fail} failed`);
process.exit(fail ? 1 : 0);
