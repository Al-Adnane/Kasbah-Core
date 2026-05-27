'use strict';

/**
 * Engine signing key — Ed25519.
 *
 * Loaded once at boot, persisted to data/engine-key.{priv,pub}.json.
 * The PUBLIC key is what makes receipts world-proof: anyone with it can
 * verify a Kasbah receipt offline, forever, without contacting Kasbah.
 *
 * Receipt format (v2, public-key, world-proof):
 *
 *     kasbah_receipt:v2:ed25519:<keyId>:<base64sig>
 *
 *   - <keyId>     — first 16 hex chars of SHA-256(raw 32-byte pubkey)
 *   - <base64sig> — base64url(64-byte Ed25519 signature)
 *
 * Payload (separate, base64url):
 *
 *     canonical_json({
 *       v: 2,
 *       id: <receipt-id>,
 *       ts: <unix-ms>,
 *       engine: <version>,
 *       keyId: <keyId>,
 *       verdict: "ALLOW" | "WARN" | "DENY",
 *       risk: <0..1, 4dp>,
 *       requestId: <id>,
 *       subject: <opaque sha-256 of the input>,
 *       passportId: <id|null>
 *     })
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

let _priv = null;          // KeyObject
let _pub  = null;          // KeyObject
let _pubRaw = null;        // 32-byte Buffer
let _keyId = null;         // first 16 hex of sha256(_pubRaw)
let _createdAt = null;

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
 * Verify a receipt against a payload (offline-style — no DB lookup).
 * Caller must pass the same pubkey that signed it; in-process we use _pub.
 * For cross-process verification the standalone verifier loads the PEM.
 */
function verify(receipt, payloadB64) {
  if (!_pub) loadOrCreate();
  try {
    const parts = (receipt || '').split(':');
    if (parts.length !== 5 || parts[0] !== 'kasbah_receipt' || parts[1] !== 'v2' || parts[2] !== 'ed25519') {
      return { valid: false, error: 'not a v2 ed25519 receipt' };
    }
    const keyId = parts[3];
    const sig = b64urlDecode(parts[4]);
    if (keyId !== _keyId) return { valid: false, error: 'unknown keyId', keyId };
    const canon = b64urlDecode(payloadB64).toString('utf8');
    const valid = crypto.verify(null, Buffer.from(canon, 'utf8'), _pub, sig);
    if (!valid) return { valid: false, error: 'signature mismatch' };
    let decoded = null;
    try { decoded = JSON.parse(canon); } catch (_) {}
    return { valid: true, decoded, keyId };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

function info() {
  if (!_pub) loadOrCreate();
  return {
    alg: 'ed25519',
    keyId: _keyId,
    publicKeyPem: _pub.export({ type: 'spki', format: 'pem' }).toString(),
    publicKeyRawB64: b64url(_pubRaw),
    createdAt: _createdAt || null,
    spec: 'https://bekasbah.com/spec/receipt-v2'
  };
}

// Load eagerly so failure shows up at boot.
loadOrCreate();

module.exports = { sign, verify, info, canonicalJSON, b64url, b64urlDecode };
