'use strict';

/**
 * @yobekasbah/receipts — signed, portable, offline-verifiable receipts for AI agent actions.
 *
 * Implements the Kasbah Receipt Spec (SPEC.md):
 *   - v2/v3 receipt strings:  kasbah_receipt:v3:<algorithm>:<keyId>:<base64url(sig)>
 *   - Ed25519 (RFC 8032) via Node crypto — zero dependencies
 *   - ML-DSA / Dilithium (FIPS 204) via optional @noble/post-quantum
 *   - Cross-receipt chaining (§6) and Merkle batch verification (§7)
 *
 * A receipt + payload pair verifies offline, forever, with only the issuer's
 * public key. Receipts are designed to outlive the company that issued them.
 */

const crypto = require('crypto');

const RECEIPT_RE = /^kasbah_receipt:v([23]):([a-z0-9-]+):([0-9a-f]{16}):([A-Za-z0-9_-]+)$/;

// ─── encoding ────────────────────────────────────────────────────────────────

/** Canonical JSON (SPEC §3): sorted keys, no whitespace, UTF-8, undefined dropped. */
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlDecode(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

// ─── keys ────────────────────────────────────────────────────────────────────

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function spkiToRaw(pubKey) {
  const der = pubKey.export({ type: 'spki', format: 'der' });
  return der.slice(der.length - 32);
}

/** Accept PEM string, raw 32-byte Buffer, or KeyObject → public KeyObject. */
function toPublicKey(key) {
  if (key instanceof crypto.KeyObject) return key.type === 'public' ? key : crypto.createPublicKey(key);
  if (typeof key === 'string') return crypto.createPublicKey(key);
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    const buf = Buffer.from(key);
    if (buf.length === 32) {
      return crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, buf]), format: 'der', type: 'spki' });
    }
    return crypto.createPublicKey({ key: buf, format: 'der', type: 'spki' });
  }
  throw new Error('unsupported public key format');
}

/** Accept PEM string, raw 32-byte seed Buffer, or KeyObject → private KeyObject. */
function toPrivateKey(key) {
  if (key instanceof crypto.KeyObject) return key;
  if (typeof key === 'string') return crypto.createPrivateKey(key);
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    const buf = Buffer.from(key);
    if (buf.length === 32) {
      return crypto.createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, buf]), format: 'der', type: 'pkcs8' });
    }
    return crypto.createPrivateKey({ key: buf, format: 'der', type: 'pkcs8' });
  }
  throw new Error('unsupported private key format');
}

/** keyId = first 16 hex chars of SHA-256(raw public key bytes). */
function keyIdOf(publicKey) {
  const raw = (Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array) && publicKey.length !== 32
    ? Buffer.from(publicKey) // PQ raw public key — hash as-is
    : (Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array)
      ? Buffer.from(publicKey)
      : spkiToRaw(toPublicKey(publicKey));
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

/** Generate a fresh Ed25519 keypair. Returns PEMs, raw public key, and keyId. */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw = spkiToRaw(publicKey);
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    publicKeyRaw: pubRaw,
    keyId: crypto.createHash('sha256').update(pubRaw).digest('hex').slice(0, 16),
  };
}

// ─── post-quantum (optional) ─────────────────────────────────────────────────

let _mldsa = null;
function mldsaFor(algorithm) {
  if (!_mldsa) {
    try { _mldsa = require('@noble/post-quantum/ml-dsa.js'); }
    catch (e) { throw new Error(`algorithm "${algorithm}" requires optional dependency @noble/post-quantum`); }
  }
  if (algorithm === 'dilithium2' || algorithm === 'ml-dsa-44') return _mldsa.ml_dsa44;
  if (algorithm === 'dilithium5' || algorithm === 'ml-dsa-87') return _mldsa.ml_dsa87;
  if (algorithm === 'dilithium3' || algorithm === 'ml-dsa-65') return _mldsa.ml_dsa65;
  throw new Error(`unknown post-quantum algorithm "${algorithm}"`);
}

// ─── sign ────────────────────────────────────────────────────────────────────

/**
 * Sign a payload into a receipt.
 *
 * @param {object} payload   Receipt payload (SPEC §2). `v`, `keyId`, `ts`, `id`
 *                           are filled in when absent.
 * @param {object} keys      { privateKey } for ed25519 (PEM | 32-byte seed | KeyObject),
 *                           or { secretKey, publicKey } (Uint8Array) for ML-DSA.
 * @param {object} [opts]    { algorithm = 'ed25519', attestationType, chainId,
 *                             parentReceipt, merkleRoot, merkleProof, engine }
 * @returns {{ receipt: string, payload: string, decoded: object, keyId: string }}
 */
function sign(payload, keys, opts = {}) {
  const algorithm = opts.algorithm || 'ed25519';
  const full = {
    ...payload,
    v: 3,
    id: payload.id || 'rcpt_' + crypto.randomBytes(10).toString('hex'),
    ts: payload.ts || Date.now(),
    engine: payload.engine || opts.engine || '@yobekasbah/receipts@1.0.0',
    attestationType: payload.attestationType || opts.attestationType || 'governance',
    chainId: payload.chainId ?? opts.chainId ?? null,
    parentReceipt: payload.parentReceipt ?? opts.parentReceipt ?? null,
    merkleRoot: payload.merkleRoot ?? opts.merkleRoot ?? null,
    merkleProof: payload.merkleProof ?? opts.merkleProof ?? null,
  };

  if (algorithm === 'ed25519') {
    const priv = toPrivateKey(keys.privateKey ?? keys);
    const pub = crypto.createPublicKey(priv);
    full.keyId = keyIdOf(spkiToRaw(pub));
    const canon = canonicalJSON(full);
    const sig = crypto.sign(null, Buffer.from(canon, 'utf8'), priv);
    return {
      receipt: `kasbah_receipt:v3:ed25519:${full.keyId}:${b64url(sig)}`,
      payload: b64url(Buffer.from(canon, 'utf8')),
      decoded: full,
      keyId: full.keyId,
    };
  }

  const dsa = mldsaFor(algorithm);
  if (!keys.secretKey || !keys.publicKey) throw new Error('ML-DSA signing requires { secretKey, publicKey }');
  full.keyId = crypto.createHash('sha256').update(Buffer.from(keys.publicKey)).digest('hex').slice(0, 16);
  const canon = canonicalJSON(full);
  const sig = dsa.sign(Buffer.from(canon, 'utf8'), keys.secretKey);
  return {
    receipt: `kasbah_receipt:v3:${algorithm}:${full.keyId}:${b64url(sig)}`,
    payload: b64url(Buffer.from(canon, 'utf8')),
    decoded: full,
    keyId: full.keyId,
  };
}

// ─── verify ──────────────────────────────────────────────────────────────────

/**
 * Verify a receipt (v2 or v3, any supported algorithm) against its payload.
 *
 * @param {string} receipt     kasbah_receipt:v…
 * @param {string} payloadB64  base64url(canonical payload)
 * @param {string|Buffer|crypto.KeyObject|Uint8Array} publicKey
 *                             PEM | raw 32-byte ed25519 key | KeyObject,
 *                             or raw ML-DSA public key bytes for PQ receipts.
 * @returns {{ valid: boolean, decoded?: object, keyId?: string, algorithm?: string, error?: string }}
 */
function verify(receipt, payloadB64, publicKey) {
  try {
    const m = RECEIPT_RE.exec(String(receipt || ''));
    if (!m) return { valid: false, error: 'not a kasbah receipt (v2/v3)' };
    const [, version, algorithm, keyId, sigB64] = m;
    const sig = b64urlDecode(sigB64);
    const canon = b64urlDecode(payloadB64);

    let ok, expectedKeyId;
    if (algorithm === 'ed25519') {
      const pub = toPublicKey(publicKey);
      expectedKeyId = keyIdOf(spkiToRaw(pub));
      if (expectedKeyId !== keyId) return { valid: false, error: 'public key does not match keyId', keyId };
      ok = crypto.verify(null, canon, pub, sig);
    } else {
      const dsa = mldsaFor(algorithm);
      const pk = Buffer.isBuffer(publicKey) || publicKey instanceof Uint8Array
        ? new Uint8Array(publicKey) : null;
      if (!pk) return { valid: false, error: 'ML-DSA verification requires raw public key bytes' };
      expectedKeyId = crypto.createHash('sha256').update(Buffer.from(pk)).digest('hex').slice(0, 16);
      if (expectedKeyId !== keyId) return { valid: false, error: 'public key does not match keyId', keyId };
      ok = dsa.verify(sig, canon, pk);
    }
    if (!ok) return { valid: false, error: 'signature mismatch', keyId, algorithm };

    let decoded = null;
    try { decoded = JSON.parse(canon.toString('utf8')); } catch (_) {}
    if (decoded && decoded.keyId !== keyId) {
      return { valid: false, error: 'payload keyId does not match receipt keyId', keyId, algorithm };
    }
    if (decoded && String(decoded.v) !== version) {
      return { valid: false, error: `payload v=${decoded.v} does not match receipt v${version}`, keyId, algorithm };
    }
    return { valid: true, decoded, keyId, algorithm };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

// ─── chaining (SPEC §6) ──────────────────────────────────────────────────────

/**
 * Verify a chain of receipts from leaf to root.
 *
 * @param {Array<{receipt: string, payload: string}>} chain  Leaf first, root last.
 * @param {*} publicKey  Same forms as verify().
 * @returns {{ valid: boolean, depth?: number, chainId?: string|null, error?: string, failedAt?: number }}
 */
function verifyChain(chain, publicKey) {
  if (!Array.isArray(chain) || chain.length === 0) return { valid: false, error: 'empty chain' };
  let chainId;
  for (let i = 0; i < chain.length; i++) {
    const r = verify(chain[i].receipt, chain[i].payload, publicKey);
    if (!r.valid) return { valid: false, error: `receipt ${i}: ${r.error}`, failedAt: i };
    const p = r.decoded || {};
    if (i === 0) chainId = p.chainId ?? null;
    else if ((p.chainId ?? null) !== chainId) {
      return { valid: false, error: `receipt ${i}: chainId mismatch`, failedAt: i };
    }
    const isLast = i === chain.length - 1;
    if (!isLast && p.parentReceipt !== chain[i + 1].receipt) {
      return { valid: false, error: `receipt ${i}: parentReceipt does not match receipt ${i + 1}`, failedAt: i };
    }
    if (isLast && p.parentReceipt) {
      return { valid: false, error: 'last receipt in chain is not a root (has parentReceipt)', failedAt: i };
    }
  }
  return { valid: true, depth: chain.length, chainId };
}

// ─── Merkle batching (SPEC §7) ───────────────────────────────────────────────

function receiptHash(receipt, payloadB64) {
  return crypto.createHash('sha256').update(receipt + '|' + payloadB64).digest('hex');
}

/**
 * Build a Merkle tree over a batch of receipts.
 *
 * Proof elements are self-describing — `{ hash, pos }` where `pos` is the
 * sibling's side — so verification needs no index bookkeeping and odd-sized
 * trees (where a node carries up a level without a sibling) verify correctly.
 *
 * @param {Array<{receipt: string, payload: string}>} batch
 * @returns {{ root: string, proofs: Map<string, Array<{hash: string, pos: 'left'|'right'}>> }}
 *          proofs keyed by receipt string.
 */
function merkleBatch(batch) {
  const entries = batch
    .map(b => ({ key: b.receipt, hash: receiptHash(b.receipt, b.payload) }))
    .sort((a, b) => (a.hash < b.hash ? -1 : 1));
  let level = entries.map(e => e.hash);
  const layers = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length
        ? crypto.createHash('sha256').update(level[i] + level[i + 1]).digest('hex')
        : level[i]); // odd node carries up
    }
    layers.push(next);
    level = next;
  }
  const root = level[0];
  const proofs = new Map();
  entries.forEach((e, idx) => {
    const proof = [];
    let i = idx;
    for (let d = 0; d < layers.length - 1; d++) {
      const sib = i % 2 === 0 ? i + 1 : i - 1;
      if (sib >= 0 && sib < layers[d].length) {
        proof.push({ hash: layers[d][sib], pos: sib > i ? 'right' : 'left' });
      }
      i = Math.floor(i / 2);
    }
    proofs.set(e.key, proof);
  });
  return { root, proofs };
}

/**
 * Verify one receipt's membership in a Merkle batch.
 * @param {Array<{hash: string, pos: 'left'|'right'}>} proof
 * @returns {{ valid: boolean, error?: string }}
 */
function verifyMerkleProof(receipt, payloadB64, proof, root) {
  let computed = receiptHash(receipt, payloadB64);
  for (const { hash, pos } of proof) {
    computed = pos === 'right'
      ? crypto.createHash('sha256').update(computed + hash).digest('hex')
      : crypto.createHash('sha256').update(hash + computed).digest('hex');
  }
  return computed === root ? { valid: true } : { valid: false, error: 'computed root does not match' };
}

// ─── key distribution (SPEC §9) ──────────────────────────────────────────────

/** Fetch issuer keys from /.well-known/kasbah-keys.json. Node ≥18 (global fetch). */
async function fetchPublicKeys(baseUrl) {
  const r = await fetch(`${String(baseUrl).replace(/\/$/, '')}/.well-known/kasbah-keys.json`);
  if (!r.ok) throw new Error('failed to fetch keys: ' + r.status);
  const data = await r.json();
  return data?.keys || [];
}

module.exports = {
  sign,
  verify,
  verifyChain,
  merkleBatch,
  verifyMerkleProof,
  receiptHash,
  canonicalJSON,
  generateKeyPair,
  keyIdOf,
  fetchPublicKeys,
  b64url,
  b64urlDecode,
};
