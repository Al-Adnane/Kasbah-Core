'use strict';

/**
 * did:key (W3C) for Ed25519 — self-certifying DIDs.
 * Public key is encoded in the DID; verification needs no network.
 * Uses Node crypto Ed25519 (constant-time), not a pure-JS curve.
 */

const crypto = require('crypto');

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MULTICODEC_ED25519_PUB = Buffer.from([0xed, 0x01]);

function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = (n << 8n) + BigInt(b);
  let out = '';
  while (n > 0n) {
    const r = Number(n % 58n);
    n /= 58n;
    out = B58[r] + out;
  }
  for (const b of buf) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out || '1';
}

function b58decode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error('invalid base58 char');
    n = n * 58n + BigInt(i);
  }
  let leading = 0;
  for (const c of s) {
    if (c === '1') leading++;
    else break;
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  return Buffer.concat([Buffer.alloc(leading), Buffer.from(bytes)]);
}

/** Raw 32-byte Ed25519 public key → did:key:z... */
function didKeyFromPublicKey(pk) {
  if (!Buffer.isBuffer(pk) || pk.length !== 32) throw new Error('need 32-byte Ed25519 public key');
  return 'did:key:z' + b58encode(Buffer.concat([MULTICODEC_ED25519_PUB, pk]));
}

function publicKeyFromDidKey(did) {
  if (!String(did).startsWith('did:key:z')) throw new Error('expected did:key:z…');
  const raw = b58decode(String(did).slice('did:key:z'.length));
  if (raw.length < 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error('not ed25519-pub multicodec');
  return raw.subarray(2, 34);
}

/** Generate an issuer keypair. privateKey is a Node KeyObject. */
function generateIssuer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const did = didKeyFromPublicKey(pubRaw);
  return { did, publicKey, privateKey, publicKeyRaw: pubRaw };
}

function signRaw(privateKey, message) {
  return crypto.sign(null, Buffer.isBuffer(message) ? message : Buffer.from(message), privateKey);
}

function verifyRaw(publicKeyRaw, message, signature) {
  try {
    const der = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      publicKeyRaw,
    ]);
    const pub = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.isBuffer(message) ? message : Buffer.from(message), pub, signature);
  } catch {
    return false;
  }
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function b64urlDecode(s) {
  return Buffer.from(String(s), 'base64url');
}

function didDocument(did, publicKeyRaw) {
  const mb = 'z' + b58encode(Buffer.concat([MULTICODEC_ED25519_PUB, publicKeyRaw]));
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    verificationMethod: [{
      id: `${did}#${mb}`,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase: mb,
    }],
    authentication: [`${did}#${mb}`],
    assertionMethod: [`${did}#${mb}`],
  };
}

module.exports = {
  b58encode, b58decode, b64url, b64urlDecode,
  didKeyFromPublicKey, publicKeyFromDidKey,
  generateIssuer, signRaw, verifyRaw, didDocument,
};
