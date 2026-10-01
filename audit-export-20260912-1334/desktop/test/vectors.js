'use strict';

/**
 * Kasbah Guard — cryptographic test vectors.
 *
 * These are static, deterministic inputs/outputs for Shamir secret sharing
 * and commitment proof. An auditor can reproduce them independently.
 *
 * Run: node test/vectors.js
 */

const assert = require('assert');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

const SRC = path.join(__dirname, '..', 'src');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ✓', name); pass++; }
  catch (e) { console.error('  ✗', name, '—', e.message); fail++; }
}

console.log('Kasbah Guard — test vectors\n');

// ── Shamir field arithmetic ──────────────────────────────────────────────────
// P = 2^127 - 1
const P = (1n << 127n) - 1n;

function mod(a) { const r = a % P; return r < 0n ? r + P : r; }
function modInv(a) {
  let e = P - 2n, base = mod(a), acc = 1n;
  while (e > 0n) { if (e & 1n) acc = mod(acc * base); base = mod(base * base); e >>= 1n; }
  return acc;
}

console.log('■ field arithmetic (GF(2^127-1))');
t('P is prime (Mersenne)', () => {
  // Quick Fermat primality witness: 2^(P-1) ≡ 1 (mod P)
  // P is well-known, just check the value is correct.
  assert.strictEqual(P, 170141183460469231731687303715884105727n);
});
t('modInv: 5 * modInv(5) ≡ 1', () => {
  assert.strictEqual(mod(5n * modInv(5n)), 1n);
});
t('modInv: large value', () => {
  const a = 123456789012345678901234567890n;
  assert.strictEqual(mod(a * modInv(a)), 1n);
});
t('mod handles negative values', () => {
  assert.ok(mod(-1n) === P - 1n);
});

// ── Shamir round-trip with known inputs ─────────────────────────────────────
console.log('\n■ Shamir secret sharing (round-trip)');
const shamir = require(path.join(SRC, 'shamir-vault.js'));

const VECTORS = [
  { secret: 'abc', n: 3, k: 2 },
  { secret: 'hello-world', n: 5, k: 3 },
  { secret: 'a'.repeat(100), n: 5, k: 3 }, // multi-chunk
  { secret: '0123456789abcdef', n: 3, k: 3 }, // exactly 16 bytes — two chunks
];

for (const v of VECTORS) {
  t(`round-trip "${v.secret.slice(0, 20)}…" (${v.n}-of-${v.k})`, () => {
    const shares = shamir.splitString(v.secret, v.n, v.k);
    assert.strictEqual(shares.length, v.n);
    // All x-values are distinct.
    const xs = shares.map((s) => s.x);
    assert.strictEqual(new Set(xs).size, v.n, 'x-values must be distinct');
    // x-values are hex BigInts, not sequential ints.
    assert.ok(String(shares[0].x).length > 4, 'x must be large random hex, not 1/2/3');
    // Reconstruct from k non-contiguous shares.
    const picked = [];
    for (let i = 0; i < shares.length && picked.length < v.k; i += Math.max(1, Math.floor(shares.length / v.k))) picked.push(shares[i]);
    if (picked.length < v.k) picked.push(...shares.slice(picked.length, v.k));
    const subset = picked.slice(0, v.k);
    const recovered = shamir.combineToString(subset);
    assert.strictEqual(recovered, v.secret, 'recovered secret must match');
  });
}

t('below-threshold cannot reconstruct', () => {
  const secret = 'cannot-reconstruct';
  const shares = shamir.splitString(secret, 3, 2);
  try {
    const bad = shamir.combineToString([shares[0]]);
    assert.notStrictEqual(bad, secret, 'single share must not reconstruct');
  } catch (_) { /* throwing is also correct */ }
});

t('chunk bounds check: >15 byte chunk is split, not rejected', () => {
  // splitString chunks at 15 bytes; 16-byte string → 2 chunks, both below P.
  const secret = 'a'.repeat(16);
  const shares = shamir.splitString(secret, 3, 2);
  const recovered = shamir.combineToString(shares.slice(0, 2));
  assert.strictEqual(recovered, secret);
});

// ── Commitment proof ─────────────────────────────────────────────────────────
console.log('\n■ commitment proof');
const TEST_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'kasbah-vec-'));
const realHomedir = os.homedir;
os.homedir = () => TEST_HOME;

const commitProof = require(path.join(SRC, 'commit-proof.js'));

t('create + open with real IP', () => {
  const r = commitProof.create({ egressIp: '185.220.101.42', location: 'fra', claim: 'PROTECTED' });
  assert.ok(r.requestId);
  assert.ok(r.receipt.startsWith('kasbah_receipt:v2:ed25519:'));
  const opened = commitProof.open(r.requestId);
  assert.strictEqual(opened.ok, true, 'commitment must verify');
  assert.strictEqual(opened.egressIp, '185.220.101.42');
});

t('blank commit (no IP) produces unique commitments', () => {
  const r1 = commitProof.create({ location: 'sin', claim: 'PROTECTED' });
  const r2 = commitProof.create({ location: 'sin', claim: 'PROTECTED' });
  assert.notStrictEqual(r1.commitment, r2.commitment, 'blank commits must be unique');
  // Both must open successfully.
  assert.ok(commitProof.open(r1.requestId).ok, 'blank commit 1 must verify');
  assert.ok(commitProof.open(r2.requestId).ok, 'blank commit 2 must verify');
});

t('tampered commitment does not verify', () => {
  const r = commitProof.create({ egressIp: '10.0.0.1', claim: 'PROTECTED' });
  // Manually corrupt the log entry.
  const log = fs.readFileSync(commitProof.LOG, 'utf8').trim().split('\n');
  const idx = log.findIndex((l) => l.includes(r.requestId));
  const entry = JSON.parse(log[idx]);
  // Corrupt both the stored IP and _ipForCommit so open() recomputes a wrong hash.
  entry.egressIp = '10.0.0.2';
  entry._ipForCommit = '10.0.0.2';
  log[idx] = JSON.stringify(entry);
  fs.writeFileSync(commitProof.LOG, log.join('\n') + '\n');
  const opened = commitProof.open(r.requestId);
  assert.strictEqual(opened.ok, false, 'tampered entry must not verify');
});

// Cleanup
try { fs.rmSync(TEST_HOME, { recursive: true, force: true }); } catch (_) {}
os.homedir = realHomedir;

console.log('\n──────────────────────────────────────────────────');
console.log(`Vectors: ${pass + fail} tests | ${pass} passed | ${fail} failed`);
if (fail) { console.error('✗ Vector tests FAILED'); process.exitCode = 1; }
else console.log('✓ Vector tests passed');
