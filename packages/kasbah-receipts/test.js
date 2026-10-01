'use strict';

/* Tests for @kasbah/receipts — run: node test.js */

const crypto = require('crypto');
const {
  sign, verify, verifyChain, merkleBatch, verifyMerkleProof,
  canonicalJSON, generateKeyPair, b64url, b64urlDecode,
} = require('./src/index.js');

let passed = 0, failed = 0;
function assert(cond, name) {
  if (cond) { passed++; console.log('  ✓ ' + name); }
  else { failed++; console.error('  ✗ ' + name); }
}

// ── 1 · canonical JSON ───────────────────────────────────────────────────────
console.log('1 · canonical JSON');
assert(canonicalJSON({ b: 1, a: 2 }) === '{"a":2,"b":1}', 'keys sorted');
assert(canonicalJSON({ a: undefined, b: null }) === '{"b":null}', 'undefined dropped, null kept');
assert(canonicalJSON([3, { z: 1, y: 2 }]) === '[3,{"y":2,"z":1}]', 'arrays preserve order, nested sort');

// ── 2 · RFC 8032 test vector key (SPEC §8 Vector 1) ─────────────────────────
console.log('2 · spec test-vector key');
const seed = Buffer.from('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42', 'hex');
const expectPub = 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf';
const expectKeyId = crypto.createHash('sha256').update(Buffer.from(expectPub, 'hex')).digest('hex').slice(0, 16);
const sv = sign({ verdict: 'ALLOW', risk: 0, requestId: 'req_test_001', subject: null, passportId: null, id: 'rcpt_test_001', ts: 1700000000000, engine: '3.0.0' }, { privateKey: seed });
assert(sv.keyId === expectKeyId, `keyId derives from RFC 8032 pubkey (${expectKeyId})`);
assert(sv.receipt.startsWith(`kasbah_receipt:v3:ed25519:${expectKeyId}:`), 'receipt string format');

// ── 3 · sign → verify roundtrip ──────────────────────────────────────────────
console.log('3 · sign → verify roundtrip');
const kp = generateKeyPair();
const r1 = sign({ verdict: 'ALLOW', risk: 0.1, requestId: 'r1', subject: null, passportId: null }, { privateKey: kp.privateKeyPem });
assert(verify(r1.receipt, r1.payload, kp.publicKeyPem).valid === true, 'verifies with PEM');
assert(verify(r1.receipt, r1.payload, kp.publicKeyRaw).valid === true, 'verifies with raw 32-byte key');

// tamper detection
const tampered = JSON.parse(b64urlDecode(r1.payload).toString('utf8'));
tampered.verdict = 'DENY';
const tamperedB64 = b64url(Buffer.from(canonicalJSON(tampered), 'utf8'));
assert(verify(r1.receipt, tamperedB64, kp.publicKeyPem).valid === false, 'tampered payload rejected');

// wrong key
const kp2 = generateKeyPair();
assert(verify(r1.receipt, r1.payload, kp2.publicKeyPem).valid === false, 'wrong public key rejected');

// v2 receipts still verify (backward compat)
const v2canon = canonicalJSON({ v: 2, engine: '1.0.0', keyId: kp.keyId, verdict: 'ALLOW', risk: 0, id: 'x', ts: 1, requestId: 'r' });
const v2sig = crypto.sign(null, Buffer.from(v2canon, 'utf8'), crypto.createPrivateKey(kp.privateKeyPem));
const v2receipt = `kasbah_receipt:v2:ed25519:${kp.keyId}:${b64url(v2sig)}`;
assert(verify(v2receipt, b64url(Buffer.from(v2canon, 'utf8')), kp.publicKeyPem).valid === true, 'v2 receipt verifies');

// ── 4 · chaining (SPEC §6) ───────────────────────────────────────────────────
console.log('4 · chaining');
const root = sign({ verdict: 'ALLOW', risk: 0, requestId: 'wf', subject: null, passportId: null, chainId: 'wf_1' }, { privateKey: kp.privateKeyPem });
const child = sign({ verdict: 'ALLOW', risk: 0.2, requestId: 'wf', subject: null, passportId: null, chainId: 'wf_1', parentReceipt: root.receipt }, { privateKey: kp.privateKeyPem });
const leaf = sign({ verdict: 'WARN', risk: 0.5, requestId: 'wf', subject: null, passportId: null, chainId: 'wf_1', parentReceipt: child.receipt }, { privateKey: kp.privateKeyPem });
const chainOk = verifyChain([
  { receipt: leaf.receipt, payload: leaf.payload },
  { receipt: child.receipt, payload: child.payload },
  { receipt: root.receipt, payload: root.payload },
], kp.publicKeyPem);
assert(chainOk.valid === true && chainOk.depth === 3 && chainOk.chainId === 'wf_1', 'leaf→root chain verifies');
const chainBad = verifyChain([
  { receipt: leaf.receipt, payload: leaf.payload },
  { receipt: root.receipt, payload: root.payload },
], kp.publicKeyPem);
assert(chainBad.valid === false, 'broken chain rejected');

// ── 5 · Merkle batching (SPEC §7) ────────────────────────────────────────────
console.log('5 · Merkle batching');
const batch = [];
for (let i = 0; i < 7; i++) {
  batch.push(sign({ verdict: 'ALLOW', risk: 0, requestId: 'b' + i, subject: null, passportId: null }, { privateKey: kp.privateKeyPem }));
}
const items = batch.map(b => ({ receipt: b.receipt, payload: b.payload }));
const { root: mroot, proofs } = merkleBatch(items);
let allOk = true;
for (const it of items) {
  if (!verifyMerkleProof(it.receipt, it.payload, proofs.get(it.receipt), mroot).valid) allOk = false;
}
assert(allOk, 'all 7 receipts prove membership against single root');
assert(verifyMerkleProof(items[0].receipt, items[1].payload, proofs.get(items[0].receipt), mroot).valid === false, 'wrong payload fails Merkle proof');
// power-of-two batch too
const items4 = items.slice(0, 4);
const m4 = merkleBatch(items4);
assert(items4.every(it => verifyMerkleProof(it.receipt, it.payload, m4.proofs.get(it.receipt), m4.root).valid), 'batch of 4 verifies');

// ── 6 · post-quantum (optional dep) ──────────────────────────────────────────
console.log('6 · post-quantum (skipped unless @noble/post-quantum installed)');
let pq = null;
try { pq = require('@noble/post-quantum/ml-dsa.js'); } catch (_) {}
if (pq) {
  const kpq = pq.ml_dsa65.keygen();
  const rq = sign({ verdict: 'DENY', risk: 0.9, requestId: 'pq', subject: null, passportId: null },
    { secretKey: kpq.secretKey, publicKey: kpq.publicKey }, { algorithm: 'dilithium3' });
  assert(rq.receipt.includes(':dilithium3:'), 'ML-DSA-65 receipt minted');
  assert(verify(rq.receipt, rq.payload, kpq.publicKey).valid === true, 'ML-DSA-65 receipt verifies');
  assert(verify(rq.receipt, rq.payload, pq.ml_dsa65.keygen().publicKey).valid === false, 'wrong PQ key rejected');
} else {
  console.log('  - @noble/post-quantum not installed; PQ paths untested here');
}

console.log(`\n${passed} passed · ${failed} failed`);
process.exit(failed ? 1 : 0);
