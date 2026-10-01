'use strict';

/**
 * Kasbah Receipt v2 — sign & verify helpers (Node.js).
 *
 * Implements docs/RECEIPT-SPEC.md in pure Node crypto, no deps.
 * Works in any Node ≥ 16 runtime. For browsers, see the WebCrypto verifier
 * in apps/web/components/VerifierClient.tsx.
 */

const crypto = require('crypto');

// ─── canonical JSON (RECEIPT-SPEC §3) ──────────────────────────────────────
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

function b64url(buf)  { return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,''); }
function b64urlDec(s) {
  s = String(s).replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function spkiToRaw(pubKey) {
  const der = pubKey.export({ type: 'spki', format: 'der' });
  return der.slice(der.length - 32);
}

/**
 * Sign a payload into a v2 receipt.
 * @param {object} payload — must include verdict ("ALLOW"|"WARN"|"DENY") and id/ts/requestId.
 * @param {string|Buffer|crypto.KeyObject} privateKey — PEM, raw 32-byte buffer, or KeyObject.
 * @returns {{ receipt, payload, decoded, keyId }}
 */
function sign(payload, privateKey) {
  const priv = (privateKey instanceof crypto.KeyObject)
    ? privateKey
    : crypto.createPrivateKey(typeof privateKey === 'string' ? privateKey : { key: privateKey, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const keyId = crypto.createHash('sha256').update(spkiToRaw(pub)).digest('hex').slice(0, 16);
  const full = { ...payload, v: 2, engine: payload.engine || '1.0.0', keyId };
  const canon = canonicalJSON(full);
  const sig = crypto.sign(null, Buffer.from(canon, 'utf8'), priv);
  return {
    receipt: `kasbah_receipt:v2:ed25519:${keyId}:${b64url(sig)}`,
    payload: b64url(Buffer.from(canon, 'utf8')),
    decoded: full,
    keyId
  };
}

/**
 * Verify a v2 receipt.
 * @param {string} receipt — kasbah_receipt:v2:ed25519:…
 * @param {string} payloadB64
 * @param {string|Buffer|crypto.KeyObject} publicKey — PEM, raw 32-byte buffer, or KeyObject.
 * @returns {{ valid, decoded?, keyId?, error? }}
 */
function verify(receipt, payloadB64, publicKey) {
  try {
    const parts = String(receipt || '').split(':');
    if (parts.length !== 5 || parts[0] !== 'kasbah_receipt' || parts[1] !== 'v2' || parts[2] !== 'ed25519') {
      return { valid: false, error: 'not a v2 ed25519 receipt' };
    }
    const keyId = parts[3];
    const sig = b64urlDec(parts[4]);

    let pub;
    if (publicKey instanceof crypto.KeyObject) pub = publicKey;
    else if (typeof publicKey === 'string') pub = crypto.createPublicKey(publicKey);
    else if (publicKey && publicKey.length === 32) {
      // wrap raw 32-byte pubkey in SPKI
      const prefix = Buffer.from('302a300506032b6570032100', 'hex');
      pub = crypto.createPublicKey({ key: Buffer.concat([prefix, publicKey]), format: 'der', type: 'spki' });
    } else {
      return { valid: false, error: 'unsupported public key format' };
    }

    const expectedKeyId = crypto.createHash('sha256').update(spkiToRaw(pub)).digest('hex').slice(0, 16);
    if (expectedKeyId !== keyId) return { valid: false, error: 'public key does not match keyId', keyId };

    const canon = b64urlDec(payloadB64);
    const ok = crypto.verify(null, canon, pub, sig);
    if (!ok) return { valid: false, error: 'signature mismatch' };

    let decoded = null;
    try { decoded = JSON.parse(canon.toString('utf8')); } catch (_) {}
    if (decoded && decoded.keyId !== keyId) return { valid: false, error: 'payload keyId does not match receipt keyId' };

    return { valid: true, decoded, keyId };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

/**
 * Fetch the public key from a Kasbah well-known endpoint.
 * @param {string} baseUrl — e.g. 'https://bekasbah.com' or 'http://localhost:8788'
 * @returns {Promise<{ kid, x, pem }>}
 */
async function fetchPublicKey(baseUrl) {
  const r = await fetch(`${baseUrl.replace(/\/$/, '')}/.well-known/kasbah-keys.json`);
  if (!r.ok) throw new Error('failed to fetch keys: ' + r.status);
  const data = await r.json();
  return data?.keys?.[0];
}

module.exports = { sign, verify, canonicalJSON, fetchPublicKey };
