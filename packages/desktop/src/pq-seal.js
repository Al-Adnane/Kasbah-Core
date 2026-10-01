'use strict';

/**
 * Hybrid PQ seal — ML-KEM-768 + AES-256-GCM.
 * Honest: this seals payloads for transport/storage. It is NOT a
 * post-quantum signature (co-sign remains Ed25519).
 */

const crypto = require('crypto');

let mlkem = null;
(function load() {
  const candidates = [
    '@noble/post-quantum/ml-kem.js',
    require('path').join(__dirname, '..', '..', '..', '..', 'node_modules', '@noble', 'post-quantum', 'ml-kem.js'),
    require('path').join(process.resourcesPath || '', 'app', 'node_modules', '@noble', 'post-quantum', 'ml-kem.js'),
    '/Users/mac/Desktop/KasbahFinal/node_modules/@noble/post-quantum/ml-kem.js',
  ];
  for (const c of candidates) {
    try { mlkem = require(c).ml_kem768; if (mlkem) return; } catch (_) {}
  }
})();

function available() { return !!mlkem; }

/** Generate recipient ML-KEM keypair. */
function keygen() {
  if (!mlkem) throw new Error('ml-kem768 unavailable');
  const { publicKey, secretKey } = mlkem.keygen();
  return {
    publicKey: Buffer.from(publicKey).toString('base64'),
    secretKey: Buffer.from(secretKey).toString('base64'),
  };
}

/**
 * Seal plaintext to a recipient ML-KEM public key.
 * Returns { v:1, kem:'ml-kem-768', ct, kct, iv, tag, aad? }
 */
function seal(plaintext, recipientPublicKeyB64, aad) {
  if (!mlkem) throw new Error('ml-kem768 unavailable');
  const pk = Buffer.from(recipientPublicKeyB64, 'base64');
  const { cipherText, sharedSecret } = mlkem.encapsulate(pk);
  const ss = Buffer.from(sharedSecret);
  const key = crypto.createHash('sha256').update(ss).digest(); // KDF
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(String(aad)));
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  ss.fill(0);
  return {
    v: 1,
    kem: 'ml-kem-768',
    kct: Buffer.from(cipherText).toString('base64'),
    ct: ct.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    aad: aad ? String(aad) : undefined,
  };
}

function open(sealed, secretKeyB64) {
  if (!mlkem) throw new Error('ml-kem768 unavailable');
  const sk = Buffer.from(secretKeyB64, 'base64');
  const ss = Buffer.from(mlkem.decapsulate(Buffer.from(sealed.kct, 'base64'), sk));
  const key = crypto.createHash('sha256').update(ss).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
  if (sealed.aad) decipher.setAAD(Buffer.from(String(sealed.aad)));
  decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
  const pt = Buffer.concat([decipher.update(Buffer.from(sealed.ct, 'base64')), decipher.final()]);
  ss.fill(0);
  return pt;
}

function selfTest() {
  if (!available()) return { ok: false, error: 'ml-kem768 unavailable' };
  const { publicKey, secretKey } = keygen();
  const msg = Buffer.from('pq-seal-test-' + Date.now());
  const sealed = seal(msg, publicKey, 'kasbah');
  const out = open(sealed, secretKey);
  if (!out.equals(msg)) throw new Error('pq seal roundtrip failed');
  // tamper
  const bad = { ...sealed, ct: Buffer.from(sealed.ct, 'base64') };
  const b = Buffer.from(sealed.ct, 'base64'); b[0] ^= 1; bad.ct = b.toString('base64');
  let rejected = false;
  try { open(bad, secretKey); } catch { rejected = true; }
  if (!rejected) throw new Error('tampered seal accepted');
  return { ok: true, kem: 'ml-kem-768', cases: ['roundtrip', 'tamper rejected'] };
}

module.exports = { available, keygen, seal, open, selfTest };
