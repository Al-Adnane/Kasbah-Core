'use strict';

/**
 * Proof-of-Protection — signed, offline-verifiable attestation that the
 * VPN tunnel was up (and optionally which exit). Uses @yobekasbah/receipts
 * from the bundled kasbah-receipts package. No cloud.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

function loadReceiptsLib() {
  // Only try the packaged path first (fast). Monorepo paths can hang on a
  // stuck FS — never block startup on them. Native Ed25519 fallback always works.
  const packaged = path.join(process.resourcesPath || '', 'packages', 'kasbah-receipts', 'src', 'index.js');
  try {
    if (packaged && packaged.length > 10 && fs.existsSync(packaged)) {
      const lib = require(packaged);
      if (lib && typeof lib.sign === 'function') return lib;
    }
  } catch (_) {}
  return nativeReceipts();
}

function nativeReceipts() {
  return {
    generateKeyPair() {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      return {
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      };
    },
    sign(payloadObj, opts) {
      const privateKey = crypto.createPrivateKey(opts.privateKey);
      const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
      const sig = crypto.sign(null, Buffer.from(payload), privateKey);
      const der = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
      const keyId = crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
      return {
        receipt: `kasbah_receipt:v2:ed25519:${keyId}:${sig.toString('base64url')}`,
        payload,
      };
    },
    verify(receipt, payloadB64, publicKeyPem) {
      try {
        const parts = String(receipt).split(':');
        const sig = Buffer.from(parts[parts.length - 1], 'base64url');
        const publicKey = crypto.createPublicKey(publicKeyPem);
        const ok = crypto.verify(null, Buffer.from(payloadB64), publicKey, sig);
        let decoded = null;
        try { decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()); } catch (_) {}
        return { valid: ok, decoded };
      } catch (e) {
        return { valid: false, error: e.message };
      }
    },
  };
}

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const KEY = path.join(DIR, 'protection-key.pem');
const PUB = path.join(DIR, 'protection-key.pub.pem');
const LOG = path.join(DIR, 'proofs.jsonl');

function ensureDir() { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); }

function keys() {
  ensureDir();
  const lib = loadReceiptsLib();
  if (!fs.existsSync(KEY)) {
    const kp = lib.generateKeyPair();
    fs.writeFileSync(KEY, kp.privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(PUB, kp.publicKeyPem, { mode: 0o644 });
  }
  return {
    lib,
    privateKeyPem: fs.readFileSync(KEY, 'utf8'),
    publicKeyPem: fs.readFileSync(PUB, 'utf8'),
  };
}

function publicKeyHex() {
  const { publicKeyPem } = keys();
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * Mint a protection proof.
 * @param {object} o { location, egressIp, egressLoc, colo, vpnOn, note }
 */
function mint(o = {}) {
  const { lib, privateKeyPem } = keys();
  const payload = {
    kind: 'proof-of-protection',
    verdict: o.vpnOn !== false ? 'PROTECTED' : 'EXPOSED',
    risk: o.vpnOn !== false ? 0.05 : 0.95,
    location: o.location || null,
    egressIp: o.egressIp || null,
    egressLoc: o.egressLoc || null,
    colo: o.colo || null,
    note: o.note || 'Kasbah Privacy protection proof',
    subject: o.egressIp ? crypto.createHash('sha256').update(String(o.egressIp)).digest('hex') : null,
    action: 'vpn_session',
    surface: 'desktop',
    requestId: 'pop_' + Date.now().toString(36),
  };
  const { receipt, payload: b64 } = lib.sign(payload, { privateKey: privateKeyPem });
  const entry = { ...payload, receipt, payload: b64, keyId: publicKeyHex(), mintedAt: new Date().toISOString() };
  ensureDir();
  fs.appendFileSync(LOG, JSON.stringify(entry) + '\n');
  return entry;
}

function list() {
  try {
    return fs.readFileSync(LOG, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch { return []; }
}

function verifyEntry(entry) {
  try {
    const { lib, publicKeyPem } = keys();
    return lib.verify(entry.receipt, entry.payload, publicKeyPem);
  } catch (e) {
    return { valid: false, error: e.message };
  }
}

function verifyAll() {
  return list().map((e) => ({ id: e.requestId, valid: !!verifyEntry(e).valid, at: e.mintedAt }));
}

function exportAll(file) {
  const out = {
    exportedAt: new Date().toISOString(),
    app: 'Kasbah Privacy',
    keyId: publicKeyHex(),
    publicKeyPem: keys().publicKeyPem,
    count: list().length,
    proofs: list(),
  };
  const dest = file || path.join(os.homedir(), 'Downloads', `kasbah-protection-proofs-${Date.now()}.json`);
  fs.writeFileSync(dest, JSON.stringify(out, null, 2), { mode: 0o600 });
  return { ok: true, file: dest, count: out.count, keyId: out.keyId };
}

/** Minimal public verify CLI text for a single proof file. */
function verifyFile(filePath) {
  const j = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const pub = j.publicKeyPem;
  const lib = loadReceiptsLib();
  const results = (j.proofs || []).map((p) => ({
    id: p.requestId,
    valid: lib.verify(p.receipt, p.payload, pub).valid,
    verdict: p.verdict,
    location: p.location,
  }));
  return { ok: results.every((r) => r.valid), keyId: j.keyId, results };
}

module.exports = { mint, list, verifyEntry, verifyAll, exportAll, verifyFile, publicKeyHex, PUB, LOG };
