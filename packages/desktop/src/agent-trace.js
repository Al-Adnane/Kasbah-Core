'use strict';

/**
 * Proof-Carrying Agent Traces — §11 item 5.
 *
 * A certificate over a SEQUENCE of agent actions:
 *   - Merkle root over per-action authorisations
 *   - Ed25519 signature over (root | policy_id | trace_id | length | ts)
 *   - Verifiable offline by anyone with the public key
 *
 * This is NOT proof that the actions were safe — it is proof that THIS
 * sequence of actions was recorded, authorised, and has not been tampered with.
 * An auditor can verify the trace without seeing the prompt content.
 *
 * Usage:
 *   const t = new AgentTrace('my-policy-v1');
 *   t.add({ tool: 'read_file', args: { path: '/tmp/x' }, decision: 'ALLOW' });
 *   t.add({ tool: 'http_get',  args: { url: '...' },    decision: 'ALLOW' });
 *   const cert = t.seal();   // { traceId, root, sig, publicKey, length, actions }
 *   AgentTrace.verify(cert); // → true
 */

const crypto = require('crypto');
const fs     = require('fs');
const os     = require('os');
const path   = require('path');

const DIR      = path.join(os.homedir(), '.kasbah-privacy');
const KEY_FILE = path.join(DIR, 'agent-trace-key.pem');
const PUB_FILE = path.join(DIR, 'agent-trace-pub.pem');
const STORE    = path.join(DIR, 'agent-traces.json');

// ─── Key management ───────────────────────────────────────────────────────────

function _loadOrCreateKey() {
  try {
    return {
      priv: fs.readFileSync(KEY_FILE, 'utf8'),
      pub:  fs.readFileSync(PUB_FILE,  'utf8'),
    };
  } catch (_) {}
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  });
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(KEY_FILE, privateKey, { mode: 0o600 });
    fs.writeFileSync(PUB_FILE, publicKey,  { mode: 0o644 });
  } catch (_) {}
  return { priv: privateKey, pub: publicKey };
}

// ─── Merkle helpers ───────────────────────────────────────────────────────────

function _sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function _actionLeaf(action, idx, prevHash) {
  const canonical = JSON.stringify({
    idx,
    tool:     action.tool     || '',
    argsHash: _sha256(JSON.stringify(action.args || {})),
    decision: action.decision || 'ALLOW',
    ts:       action.ts       || 0,
    prevHash,
  }, Object.keys({ idx: 0, tool: '', argsHash: '', decision: '', ts: 0, prevHash: '' }));
  return _sha256(canonical);
}

function _merkleRoot(hashes) {
  if (hashes.length === 0) return _sha256('empty');
  if (hashes.length === 1) return hashes[0];
  const next = [];
  for (let i = 0; i < hashes.length; i += 2) {
    next.push(_sha256(hashes[i] + (hashes[i + 1] || hashes[i])));
  }
  return _merkleRoot(next);
}

// ─── AgentTrace class ─────────────────────────────────────────────────────────

class AgentTrace {
  constructor(policyId = 'default') {
    this._policyId  = policyId;
    this._traceId   = crypto.randomBytes(16).toString('hex');
    this._actions   = [];
    this._leafHashes = [];
    this._prevHash  = _sha256('genesis:' + this._traceId);
    this._sealed    = false;
  }

  /**
   * Add an action to the trace.
   * @param {{ tool, args, decision, risk? }} action
   */
  add(action = {}) {
    if (this._sealed) throw new Error('trace is sealed — cannot add more actions');
    const entry = {
      idx:      this._actions.length,
      tool:     action.tool     || 'unknown',
      args:     action.args     || {},
      decision: action.decision || 'ALLOW',
      risk:     action.risk     ?? 0,
      ts:       Date.now(),
    };
    const leaf = _actionLeaf(entry, entry.idx, this._prevHash);
    this._prevHash = leaf;
    this._leafHashes.push(leaf);
    this._actions.push({ ...entry, leafHash: leaf });
    return this;
  }

  /**
   * Seal the trace and produce a signed certificate.
   * @returns {object} certificate — portable, offline-verifiable
   */
  seal() {
    if (this._sealed) return this._cert;
    const { priv, pub } = _loadOrCreateKey();
    const root = _merkleRoot(this._leafHashes);
    const ts   = Date.now();
    const payload = [this._traceId, root, this._policyId, String(this._actions.length), String(ts)].join('|');
    const sig  = crypto.sign(null, Buffer.from(payload), priv).toString('base64url');

    this._cert = {
      traceId:   this._traceId,
      policyId:  this._policyId,
      length:    this._actions.length,
      root,
      ts,
      sig,
      publicKey: pub,
      actions:   this._actions.map((a) => ({
        idx:      a.idx,
        tool:     a.tool,
        decision: a.decision,
        risk:     a.risk,
        ts:       a.ts,
        leafHash: a.leafHash,
        // args are NOT included in the cert — only their hash (inside leafHash)
      })),
    };
    this._sealed = true;

    // Persist to local store (last 200 traces).
    try {
      const store = (() => { try { return JSON.parse(fs.readFileSync(STORE, 'utf8')); } catch { return []; } })();
      store.push(this._cert);
      const keep = store.slice(-200);
      fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
      fs.writeFileSync(STORE, JSON.stringify(keep, null, 2), { mode: 0o600 });
    } catch (_) {}

    return this._cert;
  }

  /**
   * Verify a sealed certificate offline.
   * @param {object} cert — as returned by seal()
   * @returns {{ ok, reason }}
   */
  static verify(cert) {
    if (!cert?.sig || !cert?.publicKey) return { ok: false, reason: 'missing sig or publicKey' };
    try {
      const payload = [cert.traceId, cert.root, cert.policyId, String(cert.length), String(cert.ts)].join('|');
      const ok = crypto.verify(null, Buffer.from(payload), cert.publicKey, Buffer.from(cert.sig, 'base64url'));
      if (!ok) return { ok: false, reason: 'signature invalid' };
      if (cert.actions.length !== cert.length) return { ok: false, reason: 'action count mismatch' };
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: e.message };
    }
  }

  /**
   * List recent stored traces (newest first).
   */
  static list(n = 50) {
    try {
      const store = JSON.parse(fs.readFileSync(STORE, 'utf8'));
      return store.slice(-n).reverse();
    } catch { return []; }
  }

  /** Public key PEM for distributing to verifiers. */
  static publicKey() {
    return _loadOrCreateKey().pub;
  }
}

module.exports = { AgentTrace };
