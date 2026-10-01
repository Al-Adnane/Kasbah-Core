'use strict';

/**
 * vc-export.js — Portable Verifiable Credential export (N9)
 *
 * Wraps Kasbah protect-proof receipts as W3C Verifiable Credentials (VC
 * Data Model 1.1 / JSON-LD flavour).  Any third party holding the issuer's
 * public key can verify compliance without installing Kasbah.
 *
 * FORMAT
 *   {
 *     "@context": ["https://www.w3.org/2018/credentials/v1"],
 *     "type": ["VerifiableCredential", "KasbahProtectProof"],
 *     "issuer": "did:kasbah:<machineId>",
 *     "issuanceDate": "...",
 *     "credentialSubject": { receiptId, vpnOn, egressIp, location, createdAt, ... },
 *     "proof": { type: "Ed25519Signature2020", verificationMethod, proofValue (base64url) }
 *   }
 *
 * HONEST SCOPE
 *   · `did:kasbah:<machineId>` is NOT registered in a DID registry. It is a
 *     self-issued identifier. A verifier must obtain the public key out-of-band
 *     (e.g. via `vc-export:public-key` IPC call) until a DID document endpoint
 *     is published.
 *   · The proof type is "Ed25519Signature2020" (informal; not the full
 *     Linked Data Proofs spec, which would require JSON-LD canonicalization).
 *     The signature covers SHA-256(issuer + issuanceDate + JSON(credentialSubject)).
 *   · Expiry is caller-controlled; default 90 days.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const DIR       = path.join(os.homedir(), '.kasbah-privacy');
const KEY_PATH  = path.join(DIR, 'vc-issuer-key.pem');
const PUB_PATH  = path.join(DIR, 'vc-issuer-key.pub.pem');
const STORE     = path.join(DIR, 'vc-issued.jsonl');

function ensure() { try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {} }

/* ── Issuer key ─────────────────────────────────────────────────────────── */

let _issuerKP = null;

function _loadOrCreateIssuerKey() {
  if (_issuerKP) return _issuerKP;
  ensure();
  try {
    const priv = fs.readFileSync(KEY_PATH, 'utf8');
    const pub  = fs.readFileSync(PUB_PATH, 'utf8');
    _issuerKP  = { privateKey: crypto.createPrivateKey(priv), publicKeyPem: pub };
    return _issuerKP;
  } catch (_) {}
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPem  = publicKey.export({ type: 'spki',  format: 'pem' });
  fs.writeFileSync(KEY_PATH, privPem, { mode: 0o600 });
  fs.writeFileSync(PUB_PATH, pubPem,  { mode: 0o644 });
  _issuerKP = { privateKey, publicKeyPem: pubPem };
  return _issuerKP;
}

function _machineId() {
  // Stable per-machine ID derived from a hash of the public key bytes
  const kp  = _loadOrCreateIssuerKey();
  const pub  = crypto.createPublicKey(kp.publicKeyPem);
  const raw  = pub.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

/* ── Core API ───────────────────────────────────────────────────────────── */

/**
 * Issue a VC from a protect-proof entry (as returned by pop.js).
 *
 * @param {object} popEntry  - { requestId, receipt, vpnOn, egressIp, location, createdAt, ... }
 * @param {{ expiryDays?: number, subjectDid?: string }} [opts]
 * @returns {object} W3C VC (JSON-LD, ready for export/share)
 */
function issue(popEntry, opts = {}) {
  if (!popEntry || !popEntry.requestId) throw new Error('popEntry.requestId required');

  const kp           = _loadOrCreateIssuerKey();
  const machineId    = _machineId();
  const issuer       = `did:kasbah:${machineId}`;
  const issuanceDate = new Date().toISOString();
  const expiryMs     = ((opts.expiryDays ?? 90) * 86400 * 1000);
  const expiryDate   = new Date(Date.now() + expiryMs).toISOString();

  const credentialSubject = {
    id:         opts.subjectDid || `did:kasbah:user:${machineId}`,
    receiptId:  popEntry.requestId,
    vpnOn:      !!popEntry.vpnOn,
    egressIp:   popEntry.egressIp    || null,
    location:   popEntry.location    || null,
    protection: popEntry.protection  || null,
    createdAt:  popEntry.createdAt   || popEntry.ts || issuanceDate,
    receipt:    popEntry.receipt     || null,
  };

  const vc = {
    '@context':          ['https://www.w3.org/2018/credentials/v1'],
    type:                ['VerifiableCredential', 'KasbahProtectProof'],
    id:                  `urn:kasbah:vc:${crypto.randomBytes(8).toString('hex')}`,
    issuer,
    issuanceDate,
    expirationDate:      expiryDate,
    credentialSubject,
  };

  // Proof: sign SHA-256(issuer + issuanceDate + stable JSON of credentialSubject)
  const toSign = Buffer.from(
    issuer + '|' + issuanceDate + '|' +
    JSON.stringify(credentialSubject, Object.keys(credentialSubject).sort()),
    'utf8',
  );
  const sigBytes = crypto.sign(null, toSign, kp.privateKey);

  vc.proof = {
    type:               'Ed25519Signature2020',
    created:            issuanceDate,
    verificationMethod: `${issuer}#key-1`,
    proofPurpose:       'assertionMethod',
    proofValue:         sigBytes.toString('base64url'),
    publicKey:          kp.publicKeyPem,
    // Note: publicKey inline for standalone verifiability; a real VC issuer
    // would publish via DID document and omit it from the VC itself.
  };

  ensure();
  fs.appendFileSync(STORE, JSON.stringify({ vcId: vc.id, receiptId: popEntry.requestId, issuedAt: issuanceDate }) + '\n', { mode: 0o600 });

  return vc;
}

/**
 * Verify a VC:
 *   1. Check structural fields
 *   2. Check expiry
 *   3. Verify Ed25519 proof signature
 *
 * @returns {{ ok, vcId, issuer, expired, sigValid, error? }}
 */
function verifyVC(vc) {
  if (!vc || !vc.proof || !vc.credentialSubject) {
    return { ok: false, error: 'missing vc, proof, or credentialSubject' };
  }

  // Expiry
  const expired = vc.expirationDate ? Date.now() > new Date(vc.expirationDate).getTime() : false;

  // Signature
  let sigValid = false;
  try {
    const { credentialSubject, issuer, issuanceDate, proof } = vc;
    const pub    = crypto.createPublicKey(proof.publicKey);
    const toSign = Buffer.from(
      issuer + '|' + issuanceDate + '|' +
      JSON.stringify(credentialSubject, Object.keys(credentialSubject).sort()),
      'utf8',
    );
    const sig = Buffer.from(proof.proofValue, 'base64url');
    sigValid = crypto.verify(null, toSign, pub, sig);
  } catch (e) {
    return { ok: false, vcId: vc.id, error: 'sig verify error: ' + e.message, sigValid: false, expired };
  }

  return {
    ok:       sigValid && !expired,
    vcId:     vc.id,
    issuer:   vc.issuer,
    subject:  vc.credentialSubject?.receiptId,
    expired,
    sigValid,
    issuanceDate: vc.issuanceDate,
    expirationDate: vc.expirationDate,
  };
}

/**
 * Export a VC to a file in ~/Downloads. Returns the file path.
 */
function exportToFile(vc, filename) {
  const dir  = path.join(os.homedir(), 'Downloads');
  const dest = filename
    ? path.join(dir, path.basename(String(filename)))
    : path.join(dir, `kasbah-vc-${Date.now()}.json`);
  fs.writeFileSync(dest, JSON.stringify(vc, null, 2), { mode: 0o600 });
  return dest;
}

/** Return the issuer public key PEM for out-of-band distribution. */
function issuerPublicKey() { return _loadOrCreateIssuerKey().publicKeyPem; }

/** Return the issuer DID. */
function issuerDid() { return `did:kasbah:${_machineId()}`; }

/**
 * Write a DID document for did:kasbah:<machineId> to disk so a verifier can
 * obtain the public key out-of-band without installing Kasbah.
 * Honest scope: this is a local file, not a registered DID registry entry.
 */
function writeDidDocument(destDir) {
  const dir = destDir || DIR;
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: issuerDid(),
    verificationMethod: [{
      id: `${issuerDid()}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: issuerDid(),
      publicKeyPem: issuerPublicKey(),
    }],
    assertionMethod: [`${issuerDid()}#key-1`],
    authentication: [`${issuerDid()}#key-1`],
    // Self-issued: not in a DID registry. Publish this file over HTTPS yourself.
    alsoKnownAs: [],
    service: [{
      id: `${issuerDid()}#kasbah`,
      type: 'KasbahProtectProofs',
      serviceEndpoint: 'local',
    }],
    note: 'Self-issued DID document. Verifier must trust this PEM out-of-band or after HTTPS publication.',
    generatedAt: new Date().toISOString(),
  };
  const p = path.join(dir, 'did-document.json');
  fs.writeFileSync(p, JSON.stringify(doc, null, 2), { mode: 0o644 });
  return { ok: true, path: p, did: doc.id, publicKeyPem: doc.verificationMethod[0].publicKeyPem };
}

/**
 * Issue a W3C VC with did:key + Node Ed25519 (self-verifying, no out-of-band key).
 * Prefer this over the legacy did:kasbah path for new credentials.
 */
function issueDidKey(popEntry = {}, opts = {}) {
  const didKey = require('./did-key.js');
  const issuer = didKey.generateIssuer();
  const subjectDid = opts.subjectDid || `did:key:z${didKey.b58encode(crypto.randomBytes(34)).slice(0, 40)}`;
  const issuanceDate = new Date().toISOString();
  const subject = {
    id: subjectDid,
    requestId: popEntry.requestId || 'req_' + crypto.randomBytes(6).toString('hex'),
    vpnOn: !!popEntry.vpnOn,
    egressIp: popEntry.egressIp || null,
    location: popEntry.location || null,
    claim: popEntry.claim || 'PROTECTED',
    createdAt: popEntry.createdAt || issuanceDate,
  };
  const doc = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    type: ['VerifiableCredential', 'KasbahProtectProof'],
    issuer: issuer.did,
    issuanceDate,
    credentialSubject: subject,
  };
  const proofConfig = {
    type: 'Ed25519Signature2020',
    created: issuanceDate,
    proofPurpose: 'assertionMethod',
    verificationMethod: `${issuer.did}#key-1`,
  };
  const msg = Buffer.concat([
    Buffer.from(jcsStripProof(doc)),
    Buffer.from([0]),
    Buffer.from(jcsStripProof(proofConfig)),
  ]);
  const sig = didKey.signRaw(issuer.privateKey, msg);
  doc.proof = { ...proofConfig, proofValue: sig.toString('base64url') };
  return { vc: doc, issuerDid: issuer.did, publicKeyRaw: issuer.publicKeyRaw };
}

function jcsStripProof(obj) {
  const o = { ...obj };
  delete o.proof;
  delete o.proofValue;
  const keys = Object.keys(o).sort();
  const j = (v) => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(j).join(',') + ']';
    const ks = Object.keys(v).sort();
    return '{' + ks.map((k) => JSON.stringify(k) + ':' + j(v[k])).join(',') + '}';
  };
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + j(o[k])).join(',') + '}';
}

function verifyDidKey(vc) {
  const didKey = require('./did-key.js');
  if (!vc || !vc.issuer || !vc.proof) return { valid: false, error: 'malformed VC' };
  const issuerDid = typeof vc.issuer === 'string' ? vc.issuer : vc.issuer.id;
  if (!String(issuerDid).startsWith('did:key:')) {
    return { valid: false, error: 'issuer must be did:key for self-verification' };
  }
  let pk;
  try { pk = didKey.publicKeyFromDidKey(issuerDid); }
  catch (e) { return { valid: false, error: e.message }; }
  const proof = vc.proof;
  if (proof.type !== 'Ed25519Signature2020') return { valid: false, error: 'unsupported proof type' };
  const msg = Buffer.concat([
    Buffer.from(jcsStripProof(vc)),
    Buffer.from([0]),
    Buffer.from(jcsStripProof(proof)),
  ]);
  const sig = didKey.b64urlDecode(proof.proofValue);
  const ok = didKey.verifyRaw(pk, msg, sig);
  return {
    valid: ok,
    error: ok ? null : 'signature invalid',
    issuer: issuerDid,
    subject: vc.credentialSubject?.id,
  };
}

/** List recently issued VCs. */
function listIssued(limit = 50) {
  try {
    return fs.readFileSync(STORE, 'utf8').trim().split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean).slice(-limit).reverse();
  } catch { return []; }
}

/* ── Self-test ──────────────────────────────────────────────────────────── */

function selfTest() {
  const fakeEntry = {
    requestId: 'req_test_' + crypto.randomBytes(4).toString('hex'),
    vpnOn: true, egressIp: '185.220.101.1', location: 'fra',
    protection: 'PROTECTED', createdAt: new Date().toISOString(),
    receipt: 'kasbah_receipt:v2:ed25519:test:sig',
  };
  const vc       = issue(fakeEntry, { expiryDays: 1 });
  const result   = verifyVC(vc);
  if (!result.ok)      throw new Error('self-test: VC verification failed: ' + result.error);
  if (result.expired)  throw new Error('self-test: VC should not be expired');
  if (!result.sigValid) throw new Error('self-test: sig should be valid');

  // Tamper test
  const tampered = JSON.parse(JSON.stringify(vc));
  tampered.credentialSubject.vpnOn = false;
  const bad = verifyVC(tampered);
  if (bad.sigValid) throw new Error('self-test: tampered VC should not verify');

  return { ok: true, vcId: vc.id, issuer: vc.issuer };
}

module.exports = {
  issue, verifyVC, exportToFile, issuerPublicKey, issuerDid, listIssued, selfTest, writeDidDocument,
  issueDidKey, verifyDidKey,
};
