'use strict';

/**
 * Engine signing key — Ed25519 + Dilithium (post-quantum ready).
 *
 * Loaded once at boot, persisted to data/engine-key.{priv,pub}.json.
 * The PUBLIC key is what makes receipts world-proof: anyone with it can
 * verify a Kasbah receipt offline, forever, without contacting Kasbah.
 *
 * Receipt format (v3, RECEIPT-SPEC-v3):
 *
 *     kasbah_receipt:v3:<algorithm>:<keyId>:<base64sig>
 *
 *   - <algorithm> — ed25519 | dilithium2 | dilithium3
 *   - <keyId>     — first 16 hex chars of SHA-256(raw pubkey bytes)
 *   - <base64sig> — base64url(signature bytes)
 *
 * v3 payload adds: attestationType, chainId, parentReceipt, merkleRoot, merkleProof.
 * v2 receipts remain valid indefinitely. v3 is a superset.
 *
 * Canonical JSON: sorted keys, no whitespace, UTF-8. Defined in RECEIPT-SPEC.md.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const DATA_DIR = process.env.KASBAH_DATA_DIR
  ? path.resolve(process.env.KASBAH_DATA_DIR)
  : path.resolve(__dirname, '..', '..', '..', 'data');

const PRIV_PATH = path.join(DATA_DIR, 'engine-key.priv.pem');
const PUB_PATH  = path.join(DATA_DIR, 'engine-key.pub.pem');
const META_PATH = path.join(DATA_DIR, 'engine-key.meta.json');

// Post-quantum (ML-DSA / FIPS 204) key material — persisted as raw bytes.
const PQ_SK_PATH = path.join(DATA_DIR, 'engine-key.pq.sk.bin');
const PQ_PK_PATH = path.join(DATA_DIR, 'engine-key.pq.pk.bin');

let _priv = null;          // KeyObject
let _pub  = null;          // KeyObject
let _pubRaw = null;        // 32-byte Buffer
let _keyId = null;         // first 16 hex of sha256(_pubRaw)
let _createdAt = null;

// PQ state. ML-DSA-65 (dilithium3-equivalent) is the default level.
let _pqSk = null;          // Uint8Array secret key
let _pqPk = null;          // Uint8Array public key
let _pqKeyId = null;       // first 16 hex of sha256(_pqPk)
let _pqAlg = 'dilithium3'; // persisted level label
let _mldsa = null;         // lazy-loaded @noble/post-quantum ml-dsa module

// Map our algorithm labels → @noble ML-DSA parameter sets.
function _mldsaFor(algorithm) {
  if (!_mldsa) _mldsa = require('@noble/post-quantum/ml-dsa.js');
  // dilithium2≈ML-DSA-44, dilithium3≈ML-DSA-65, dilithium5≈ML-DSA-87
  if (algorithm === 'dilithium2') return _mldsa.ml_dsa44;
  if (algorithm === 'dilithium5') return _mldsa.ml_dsa87;
  return _mldsa.ml_dsa65; // dilithium3 default
}

function loadOrCreatePQ() {
  ensureDir();
  const dsa = _mldsaFor(_pqAlg);
  if (fs.existsSync(PQ_SK_PATH) && fs.existsSync(PQ_PK_PATH)) {
    _pqSk = new Uint8Array(fs.readFileSync(PQ_SK_PATH));
    _pqPk = new Uint8Array(fs.readFileSync(PQ_PK_PATH));
  } else {
    const kp = dsa.keygen();
    _pqSk = kp.secretKey;
    _pqPk = kp.publicKey;
    fs.writeFileSync(PQ_SK_PATH, Buffer.from(_pqSk), { mode: 0o600 });
    fs.writeFileSync(PQ_PK_PATH, Buffer.from(_pqPk));
  }
  _pqKeyId = crypto.createHash('sha256').update(Buffer.from(_pqPk)).digest('hex').slice(0, 16);
  return dsa;
}

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function spkiToRawEd25519(pubKey) {
  // SPKI for ed25519 is 44 bytes; last 32 are the raw public key.
  const der = pubKey.export({ type: 'spki', format: 'der' });
  return der.slice(der.length - 32);
}

function loadOrCreate() {
  ensureDir();
  if (fs.existsSync(PRIV_PATH) && fs.existsSync(PUB_PATH)) {
    _priv = crypto.createPrivateKey(fs.readFileSync(PRIV_PATH));
    _pub  = crypto.createPublicKey(fs.readFileSync(PUB_PATH));
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(PRIV_PATH, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(PUB_PATH,  publicKey.export({ type: 'spki',  format: 'pem' }));
    _priv = privateKey;
    _pub  = publicKey;
    _createdAt = new Date().toISOString();
    fs.writeFileSync(META_PATH, JSON.stringify({ createdAt: _createdAt, alg: 'ed25519' }, null, 2));
  }
  _pubRaw = spkiToRawEd25519(_pub);
  _keyId  = crypto.createHash('sha256').update(_pubRaw).digest('hex').slice(0, 16);
  if (!_createdAt && fs.existsSync(META_PATH)) {
    try { _createdAt = JSON.parse(fs.readFileSync(META_PATH, 'utf8')).createdAt; } catch (_) {}
  }
}

/** Sort keys recursively, drop undefined, stringify with no whitespace. */
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

/**
 * Sign a receipt payload.
 * @param {object} payload — must include v, id, ts, verdict, risk, requestId, subject.
 *                            engine + keyId are added automatically.
 * @returns {{ receipt: string, payload: string, decoded: object }}
 */
function sign(payload) {
  if (!_priv) loadOrCreate();
  const fullPayload = {
    ...payload,
    v: 2,
    engine: payload.engine || (process.env.KASBAH_VERSION || '1.0.0'),
    keyId: _keyId
  };
  const canon = canonicalJSON(fullPayload);
  const sig = crypto.sign(null, Buffer.from(canon, 'utf8'), _priv);
  return {
    receipt: `kasbah_receipt:v2:ed25519:${_keyId}:${b64url(sig)}`,
    payload: b64url(Buffer.from(canon, 'utf8')),
    decoded: fullPayload
  };
}

/**
 * Sign a v3 receipt payload (RECEIPT-SPEC-v3).
 *
 * Adds v3 fields: attestationType, chainId, parentReceipt, merkleRoot, merkleProof.
 * Defaults algorithm to ed25519. Dilithium support is architected but requires
 * a native Dilithium module (e.g. @openquantumsafe/dilithium) — graceful fallback.
 *
 * @param {object} payload — required: verdict, risk, requestId, subject
 * @param {object} opts
 * @param {string} opts.algorithm — 'ed25519' (default) | 'dilithium2' | 'dilithium3'
 * @param {string} opts.attestationType — 'governance' | 'silent_speech' | 'biometric' | 'kernel'
 * @param {string} opts.chainId — workflow chain id for cross-receipt linking
 * @param {string} opts.parentReceipt — parent receipt string
 * @param {string} opts.merkleRoot — Merkle root if batched
 * @param {string[]} opts.merkleProof — Merkle proof siblings
 * @returns {{ receipt: string, payload: string, decoded: object }}
 */
function signV3(payload, opts = {}) {
  if (!_priv) loadOrCreate();

  const algorithm = opts.algorithm || 'ed25519';

  // Dilithium: attempt native module, fall back with clear error
  if (algorithm.startsWith('dilithium')) {
    return _signDilithium(payload, algorithm, opts);
  }

  // Ed25519 (default v3 path)
  const fullPayload = {
    ...payload,
    v: 3,
    engine: payload.engine || (process.env.KASBAH_VERSION || '3.0.0'),
    keyId: _keyId,
    attestationType: opts.attestationType || 'governance',
    chainId: opts.chainId || null,
    parentReceipt: opts.parentReceipt || null,
    merkleRoot: opts.merkleRoot || null,
    merkleProof: opts.merkleProof || null,
  };

  const canon = canonicalJSON(fullPayload);
  const sig = crypto.sign(null, Buffer.from(canon, 'utf8'), _priv);
  return {
    receipt: `kasbah_receipt:v3:ed25519:${_keyId}:${b64url(sig)}`,
    payload: b64url(Buffer.from(canon, 'utf8')),
    decoded: fullPayload,
  };
}

/**
 * Post-quantum signing via @noble/post-quantum ML-DSA (FIPS 204).
 * dilithium2≈ML-DSA-44, dilithium3≈ML-DSA-65, dilithium5≈ML-DSA-87.
 * Keys are persisted (loadOrCreatePQ) so receipts verify across restarts.
 */
function _signDilithium(payload, algorithm, opts) {
  try {
    const dsa = loadOrCreatePQ();
    const fullPayload = {
      ...payload,
      v: 3,
      engine: payload.engine || (process.env.KASBAH_VERSION || '3.0.0'),
      keyId: _pqKeyId,
      attestationType: opts.attestationType || 'governance',
      chainId: opts.chainId || null,
      parentReceipt: opts.parentReceipt || null,
      merkleRoot: opts.merkleRoot || null,
      merkleProof: opts.merkleProof || null,
    };
    const canon = canonicalJSON(fullPayload);
    const sig = dsa.sign(Buffer.from(canon, 'utf8'), _pqSk);
    return {
      receipt: `kasbah_receipt:v3:${algorithm}:${_pqKeyId}:${b64url(sig)}`,
      payload: b64url(Buffer.from(canon, 'utf8')),
      decoded: fullPayload,
    };
  } catch (e) {
    // Graceful fallback: sign with Ed25519 but note the intended algorithm
    console.warn(`[engine-key] ML-DSA unavailable (${e.message}) — falling back to Ed25519`);
    const result = signV3(payload, { ...opts, algorithm: 'ed25519' });
    result._fallback = true;
    result._intendedAlgorithm = algorithm;
    return result;
  }
}

/**
 * Verify a receipt against a payload (offline-style — no DB lookup).
 * Caller must pass the same pubkey that signed it; in-process we use _pub.
 * For cross-process verification the standalone verifier loads the PEM.
 */
function verify(receipt, payloadB64) {
  if (!_pub) loadOrCreate();
  try {
    const parts = (receipt || '').split(':');
    if (parts.length < 5 || parts[0] !== 'kasbah_receipt') {
      return { valid: false, error: 'not a kasbah_receipt' };
    }

    const version = parts[1];  // v2 or v3
    const algorithm = parts[2];
    const keyId = parts[3];
    const sig = b64urlDecode(parts[4]);

    // Supported algorithms
    if (!['ed25519', 'dilithium2', 'dilithium3', 'dilithium5'].includes(algorithm)) {
      return { valid: false, error: `unsupported algorithm: ${algorithm}` };
    }

    // keyId binding: ed25519 binds to _keyId; dilithium binds to _pqKeyId.
    if (algorithm === 'ed25519' && keyId !== _keyId) {
      return { valid: false, error: 'unknown keyId', keyId };
    }

    const canon = b64urlDecode(payloadB64).toString('utf8');

    // Dilithium: attempt native, fall back
    if (algorithm.startsWith('dilithium')) {
      return _verifyDilithium(algorithm, canon, sig, keyId);
    }

    // Ed25519 (v2 + v3)
    const valid = crypto.verify(null, Buffer.from(canon, 'utf8'), _pub, sig);
    if (!valid) return { valid: false, error: 'signature mismatch' };

    let decoded = null;
    try { decoded = JSON.parse(canon); } catch (_) {}
    return { valid: true, decoded, keyId, version, algorithm };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

function _verifyDilithium(algorithm, canon, sig, keyId) {
  try {
    const dsa = loadOrCreatePQ();
    if (keyId !== _pqKeyId) {
      return { valid: false, error: 'unknown PQ keyId', keyId };
    }
    const valid = dsa.verify(sig, Buffer.from(canon, 'utf8'), _pqPk);
    if (!valid) return { valid: false, error: 'signature mismatch' };
    let decoded = null;
    try { decoded = JSON.parse(canon); } catch (_) {}
    return { valid: true, decoded, keyId, algorithm };
  } catch (e) {
    return { valid: false, error: `ML-DSA verification failed: ${e.message}` };
  }
}

function info() {
  if (!_pub) loadOrCreate();
  const pq = hasDilithium();
  let pqKeyId = null;
  if (pq) { try { loadOrCreatePQ(); pqKeyId = _pqKeyId; } catch (_) {} }
  return {
    alg: 'ed25519',
    keyId: _keyId,
    publicKeyPem: _pub.export({ type: 'spki', format: 'pem' }).toString(),
    publicKeyRawB64: b64url(_pubRaw),
    createdAt: _createdAt || null,
    spec: 'https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC-v3.md',
    specV3: 'https://github.com/Al-Adnane/Kasbah-Core/blob/main/docs/RECEIPT-SPEC-v3.md-v3',
    supportedAlgorithms: pq ? ['ed25519', 'dilithium2', 'dilithium3', 'dilithium5'] : ['ed25519'],
    dilithiumAvailable: pq,
    pqAlg: pq ? `${_pqAlg} (ML-DSA / FIPS 204)` : null,
    pqKeyId,
    pqPublicKeyB64: pq && _pqPk ? b64url(_pqPk) : null,
  };
}

function hasDilithium() {
  try {
    require('@noble/post-quantum/ml-dsa.js');
    return true;
  } catch (_) {
    return false;
  }
}

// Load eagerly so failure shows up at boot.
loadOrCreate();

module.exports = { sign, signV3, verify, info, hasDilithium, canonicalJSON, b64url, b64urlDecode };
