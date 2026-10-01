#!/usr/bin/env node
'use strict';
/**
 * Regenerates the test vectors in docs/RECEIPT-SPEC.md from the reference
 * Ed25519 implementation. Uses a fixed private key so output is reproducible.
 *
 * Usage: node bench/generate-spec-vectors.js
 */

const crypto = require('crypto');

// ─── Reference canonical JSON (matches engine-key.js + RECEIPT-SPEC §3) ──────
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
}

// ─── Fixed test key (RFC 8032 §7.1 test vector 1) ────────────────────────────
const PRIV_HEX = '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42';
const PUB_HEX  = 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf';

// Wrap raw 32-byte Ed25519 private key in PKCS#8.
function rawPrivToPkcs8(raw32) {
  // OID 1.3.101.112 for Ed25519, then OCTET STRING of OCTET STRING (the key)
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return Buffer.concat([prefix, raw32]);
}
function rawPubToSpki(raw32) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return Buffer.concat([prefix, raw32]);
}

const privKey = crypto.createPrivateKey({
  key: rawPrivToPkcs8(Buffer.from(PRIV_HEX, 'hex')), format: 'der', type: 'pkcs8'
});
const pubKey  = crypto.createPublicKey({
  key: rawPubToSpki(Buffer.from(PUB_HEX, 'hex')), format: 'der', type: 'spki'
});

const pubRaw = Buffer.from(PUB_HEX, 'hex');
const keyId  = crypto.createHash('sha256').update(pubRaw).digest('hex').slice(0, 16);

function sign(payloadObj) {
  const full = { ...payloadObj, v: 2, engine: '1.0.0', keyId };
  const canon = canonicalJSON(full);
  const sig = crypto.sign(null, Buffer.from(canon, 'utf8'), privKey);
  return {
    receipt: `kasbah_receipt:v2:ed25519:${keyId}:${b64url(sig)}`,
    payloadB64: b64url(Buffer.from(canon, 'utf8')),
    canonical: canon
  };
}

function verify(receipt, payloadB64) {
  const parts = receipt.split(':');
  const sig = Buffer.from(parts[4].replace(/-/g,'+').replace(/_/g,'/') + '==='.slice(0, (4 - parts[4].length % 4) % 4), 'base64');
  const canon = Buffer.from(payloadB64.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice(0, (4 - payloadB64.length % 4) % 4), 'base64');
  return crypto.verify(null, canon, pubKey, sig);
}

console.log('keyId:', keyId, '\n');

// Vector 1
const v1 = sign({
  id: 'rcpt_test_001', ts: 1700000000000,
  verdict: 'ALLOW', risk: 0,
  requestId: 'req_test_001',
  subject: null, passportId: null
});
console.log('── Vector 1 (minimum, ALLOW) ──────────────────────────────');
console.log('canonical:', v1.canonical);
console.log('receipt:  ', v1.receipt);
console.log('payloadB64:', v1.payloadB64);
console.log('verifies: ', verify(v1.receipt, v1.payloadB64), '\n');

// Vector 2
const v2 = sign({
  id: 'rcpt_test_002', ts: 1700000000000,
  verdict: 'DENY', risk: 0.9421,
  requestId: 'req_test_002',
  subject: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  passportId: 'kp_demo'
});
console.log('── Vector 2 (DENY with risk) ──────────────────────────────');
console.log('canonical:', v2.canonical);
console.log('receipt:  ', v2.receipt);
console.log('payloadB64:', v2.payloadB64);
console.log('verifies: ', verify(v2.receipt, v2.payloadB64), '\n');

// Vector 3: tampered — verdict swapped
const v3canon = canonicalJSON({
  ...JSON.parse(v1.canonical), verdict: 'DENY'
});
const v3payloadB64 = b64url(Buffer.from(v3canon, 'utf8'));
console.log('── Vector 3 (tampered — MUST fail) ────────────────────────');
console.log('tampered payloadB64:', v3payloadB64);
console.log('verifies (must be false):', verify(v1.receipt, v3payloadB64), '\n');

// Vector 4: wrong keyId in payload
const v4canon = canonicalJSON({
  ...JSON.parse(v1.canonical), keyId: 'deadbeefdeadbeef'
});
const v4payloadB64 = b64url(Buffer.from(v4canon, 'utf8'));
console.log('── Vector 4 (wrong keyId — MUST fail at step 7) ───────────');
console.log('tampered payloadB64:', v4payloadB64);
console.log('signature still verifies cryptographically:', verify(v1.receipt, v4payloadB64));
console.log('but step 7 of §5 rejects: payload.keyId !== receipt.keyId\n');
