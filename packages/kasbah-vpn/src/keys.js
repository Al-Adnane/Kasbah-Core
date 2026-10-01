'use strict';

/**
 * WireGuard key material via Node's native X25519.
 *
 * WireGuard keys are raw 32-byte Curve25519 scalars/points, base64-encoded —
 * exactly what `wg genkey` / `wg pubkey` produce. Node ≥18 can generate and
 * transform them without shelling out, so key material never touches a
 * subprocess argv or an intermediate file.
 */

const crypto = require('crypto');

// DER prefixes for raw-key <-> KeyObject conversion (RFC 8410).
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

/** Raw 32 bytes of an X25519 public KeyObject. */
function pubRaw(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
}

/** Raw 32 bytes of an X25519 private KeyObject. */
function privRaw(privateKey) {
  const der = privateKey.export({ type: 'pkcs8', format: 'der' });
  return der.subarray(der.length - 32);
}

/** Generate a WireGuard keypair. Returns wg-format base64 strings. */
function generateWgKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    privateKey: privRaw(privateKey).toString('base64'),
    publicKey: pubRaw(publicKey).toString('base64'),
  };
}

/** Derive the wg public key for a wg-format base64 private key (like `wg pubkey`). */
function wgPublicKeyOf(privateKeyB64) {
  const raw = Buffer.from(String(privateKeyB64).trim(), 'base64');
  if (raw.length !== 32) throw new Error('WireGuard private key must be 32 bytes base64');
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
  return pubRaw(crypto.createPublicKey(priv)).toString('base64');
}

/** Validate a wg-format base64 key (private, public, or preshared — all 32 bytes). */
function isWgKey(b64) {
  try {
    return Buffer.from(String(b64).trim(), 'base64').length === 32;
  } catch {
    return false;
  }
}

module.exports = { generateWgKeypair, wgPublicKeyOf, isWgKey, X25519_SPKI_PREFIX };
