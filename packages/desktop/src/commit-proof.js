'use strict';

/**
 * Commitment proof — hide egress IP while proving it matches a claim.
 * C = SHA256(ip || salt); sign payload with C but not ip.
 * Pure Node Ed25519 (no hang on receipts package).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const KEY = path.join(DIR, 'protection-key.pem');
const PUB = path.join(DIR, 'protection-key.pub.pem');
const LOG = path.join(DIR, 'commit-proofs.jsonl');

function ensure() { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); }

function keys() {
  ensure();
  if (!fs.existsSync(KEY)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(KEY, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { mode: 0o600 });
    fs.writeFileSync(PUB, publicKey.export({ type: 'spki', format: 'pem' }).toString(), { mode: 0o644 });
  }
  return {
    privateKeyPem: fs.readFileSync(KEY, 'utf8'),
    publicKeyPem: fs.readFileSync(PUB, 'utf8'),
  };
}

function signPayload(obj, privateKeyPem) {
  const payload = Buffer.from(JSON.stringify(obj)).toString('base64url');
  const sig = crypto.sign(null, Buffer.from(payload), crypto.createPrivateKey(privateKeyPem));
  const der = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'der' });
  const keyId = crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
  return {
    receipt: `kasbah_receipt:v2:ed25519:${keyId}:${sig.toString('base64url')}`,
    payload,
  };
}

function verify(receipt, payloadB64, publicKeyPem) {
  try {
    const parts = String(receipt).split(':');
    const sig = Buffer.from(parts[parts.length - 1], 'base64url');
    const ok = crypto.verify(null, Buffer.from(payloadB64), crypto.createPublicKey(publicKeyPem), sig);
    return { valid: ok };
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

function create({ egressIp, location, colo, claim = 'PROTECTED' } = {}) {
  const salt = crypto.randomBytes(16).toString('hex');
  // When no real IP is known, use a random nonce so each blank commit is unique.
  const ipForCommit = egressIp || ('nonce:' + crypto.randomBytes(8).toString('hex'));
  const commitment = crypto.createHash('sha256')
    .update(ipForCommit + '|' + salt)
    .digest('hex');
  const { privateKeyPem, publicKeyPem } = keys();
  const payloadObj = {
    kind: 'commitment-proof',
    claim,
    commitment,
    location: location || null,
    colo: colo || null,
  };
  const { receipt, payload } = signPayload(payloadObj, privateKeyPem);
  const entry = {
    ...payloadObj,
    receipt,
    payload,
    salt,
    egressIp: egressIp || null,
    _ipForCommit: ipForCommit, // stored so open() can recompute; not exposed in list()
    publicKeyPem,
    createdAt: new Date().toISOString(),
    requestId: 'cp_' + Date.now().toString(36),
  };
  ensure();
  fs.appendFileSync(LOG, JSON.stringify(entry) + '\n');
  return {
    requestId: entry.requestId,
    claim,
    commitment,
    location,
    colo,
    receipt,
    payload,
    createdAt: entry.createdAt,
    note: 'IP not revealed. Open with salt to prove match.',
  };
}

function open(requestId) {
  const lines = fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const e = lines.find((x) => x.requestId === requestId);
  if (!e) return { ok: false, error: 'not found' };
  // Use _ipForCommit (stored at creation) to recompute — handles nonce-based blank commits.
  const ipForCommit = e._ipForCommit || (e.egressIp != null ? String(e.egressIp) : ('nonce:' + e.salt));
  const check = crypto.createHash('sha256').update(ipForCommit + '|' + e.salt).digest('hex');
  return { ok: check === e.commitment, egressIp: e.egressIp, salt: e.salt, commitment: e.commitment };
}

function list() {
  try {
    return fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => {
      const j = JSON.parse(l);
      return {
        requestId: j.requestId,
        claim: j.claim,
        commitment: (j.commitment || '').slice(0, 16) + '…',
        location: j.location,
        createdAt: j.createdAt,
      };
    }).reverse().slice(0, 30);
  } catch { return []; }
}

module.exports = { create, open, list, verify, keys, LOG };
