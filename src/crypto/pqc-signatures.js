'use strict';

/**
 * Post-quantum signatures backed by @noble/post-quantum (audited, pure-JS).
 *
 *   Dilithium  -> ML-DSA-65   (NIST FIPS 204, security level 3)
 *   SPHINCS+   -> SLH-DSA-SHA2-128f (NIST FIPS 205)
 *
 * noble API (v0.6):  sign(message, secretKey) -> sig
 *                    verify(sig, message, publicKey) -> bool
 *                    keygen() -> { publicKey, secretKey }
 *
 * All keys/signatures are returned/accepted as hex strings at this boundary so
 * the rest of Kasbah can treat them as opaque tokens.
 */

let mldsa = null;
let slhdsa = null;
let PQC_AVAILABLE = false;

try {
  mldsa = require('@noble/post-quantum/ml-dsa.js').ml_dsa65;
  slhdsa = require('@noble/post-quantum/slh-dsa.js').slh_dsa_sha2_128f;
  PQC_AVAILABLE = !!(mldsa && slhdsa);
} catch (e) {
  PQC_AVAILABLE = false;
}

const enc = (m) => (typeof m === 'string' ? new TextEncoder().encode(m) : m);
const toHex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

function assertAvailable() {
  if (!PQC_AVAILABLE) {
    throw new Error('post-quantum signatures unavailable: install @noble/post-quantum');
  }
}

// ---- Dilithium / ML-DSA-65 ----
function generateDilithiumKeypair() {
  assertAvailable();
  const { publicKey, secretKey } = mldsa.keygen();
  const sk = toHex(secretKey);
  return { publicKey: toHex(publicKey), secretKey: sk, privateKey: sk, algorithm: 'ML-DSA-65' };
}

function signDilithium(message, secretKeyHex) {
  assertAvailable();
  const sig = mldsa.sign(enc(message), fromHex(secretKeyHex));
  return { signature: toHex(sig), algorithm: 'ML-DSA-65', real: true };
}

function verifyDilithium(message, sigHex, publicKeyHex) {
  if (!PQC_AVAILABLE) return { valid: false };
  try {
    return { valid: mldsa.verify(fromHex(sigHex), enc(message), fromHex(publicKeyHex)) };
  } catch { return { valid: false }; }
}

// ---- SPHINCS+ / SLH-DSA-SHA2-128f ----
function generateSPHINCSKeypair() {
  assertAvailable();
  const { publicKey, secretKey } = slhdsa.keygen();
  const sk = toHex(secretKey);
  return { publicKey: toHex(publicKey), secretKey: sk, privateKey: sk, algorithm: 'SLH-DSA-SHA2-128f' };
}

function signSPHINCS(message, secretKeyHex) {
  assertAvailable();
  const sig = slhdsa.sign(enc(message), fromHex(secretKeyHex));
  return { signature: toHex(sig), algorithm: 'SLH-DSA-SHA2-128f', real: true };
}

function verifySPHINCS(message, sigHex, publicKeyHex) {
  if (!PQC_AVAILABLE) return { valid: false };
  try {
    return { valid: slhdsa.verify(fromHex(sigHex), enc(message), fromHex(publicKeyHex)) };
  } catch { return { valid: false }; }
}

module.exports = {
  PQC_AVAILABLE,
  generateDilithiumKeypair,
  signDilithium,
  verifyDilithium,
  generateSPHINCSKeypair,
  signSPHINCS,
  verifySPHINCS,
};
