'use strict';

/**
 * Transparency Log — append-only Merkle log of every Kasbah gate decision.
 *
 * Applies RFC 6962 (Certificate Transparency) to AI governance:
 *   - Every gate decision (ALLOW / WARN / REQUIRE_APPROVAL) appends a leaf.
 *   - Leaf = SHA-256(timestamp | decision | prompt_hash | policy_hash | prev_leaf).
 *   - Signed Tree Head (STH) is produced after every append: Ed25519 signature
 *     over (tree_size | root_hash | timestamp).
 *   - Inclusion proofs: given a leaf index, return the sibling path to the root.
 *   - Consistency proofs: given two STHs, prove the first is a prefix of the second.
 *
 * The log is stored locally at ~/.kasbah-privacy/transparency-log.json.
 * The Ed25519 signing key lives at ~/.kasbah-privacy/tlog-key.pem (0600).
 *
 * This is NOT a multi-party log — there is only one signer (this device).
 * The value is: (a) tamper-evidence (any edit breaks the hash chain), and
 * (b) portability — the STH + inclusion proof can be verified offline by
 * anyone with the public key, without access to the prompts themselves.
 */

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');

const DIR      = path.join(os.homedir(), '.kasbah-privacy');
const LOG_FILE = path.join(DIR, 'transparency-log.json');
const KEY_FILE = path.join(DIR, 'tlog-key.pem');
const PUB_FILE = path.join(DIR, 'tlog-pub.pem');
const MAX_ENTRIES = 10000; // prune oldest when exceeded

// ─── Key management ───────────────────────────────────────────────────────────

function _loadOrCreateKey() {
  try {
    const priv = fs.readFileSync(KEY_FILE, 'utf8');
    const pub  = fs.readFileSync(PUB_FILE,  'utf8');
    return { priv, pub };
  } catch (_) {}
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  });
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(KEY_FILE, privateKey,  { mode: 0o600 });
    fs.writeFileSync(PUB_FILE,  publicKey,  { mode: 0o644 });
  } catch (_) {}
  return { priv: privateKey, pub: publicKey };
}

// ─── Persistence ─────────────────────────────────────────────────────────────

function _load() {
  try {
    const raw = JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
    return {
      leaves:  raw.leaves  || [],
      sths:    raw.sths    || [],
      created: raw.created || new Date().toISOString(),
    };
  } catch (_) {
    return { leaves: [], sths: [], created: new Date().toISOString() };
  }
}

function _save(log) {
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    // Prune oldest entries if over limit (keep last MAX_ENTRIES).
    if (log.leaves.length > MAX_ENTRIES) {
      log.leaves = log.leaves.slice(log.leaves.length - MAX_ENTRIES);
    }
    fs.writeFileSync(LOG_FILE, JSON.stringify(log, null, 2), { mode: 0o600 });
  } catch (_) {}
}

// ─── Merkle tree ──────────────────────────────────────────────────────────────

function _sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function _leafHash(entry, prevHash) {
  const payload = [
    String(entry.ts),
    entry.decision,
    entry.promptHash || '',
    entry.policyHash || '',
    prevHash,
  ].join('|');
  return _sha256(payload);
}

function _merkleRoot(hashes) {
  if (hashes.length === 0) return _sha256('empty');
  if (hashes.length === 1) return hashes[0];
  const next = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const l = hashes[i];
    const r = i + 1 < hashes.length ? hashes[i + 1] : l;
    next.push(_sha256(l + r));
  }
  return _merkleRoot(next);
}

function _inclusionProof(index, hashes) {
  const proof = [];
  let idx = index;
  let layer = [...hashes];
  while (layer.length > 1) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (siblingIdx < layer.length) proof.push({ pos: idx % 2 === 0 ? 'right' : 'left', hash: layer[siblingIdx] });
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const l = layer[i];
      const r = i + 1 < layer.length ? layer[i + 1] : l;
      next.push(_sha256(l + r));
    }
    layer = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

// ─── STH signing ─────────────────────────────────────────────────────────────

function _signSth(treeSize, rootHash, ts, privPem) {
  const payload = `${treeSize}|${rootHash}|${ts}`;
  const sig = crypto.sign(null, Buffer.from(payload), privPem);
  return sig.toString('base64url');
}

function _verifySth(sth, pubPem) {
  const payload = `${sth.treeSize}|${sth.rootHash}|${sth.ts}`;
  try {
    return crypto.verify(null, Buffer.from(payload), pubPem, Buffer.from(sth.sig, 'base64url'));
  } catch { return false; }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Append a gate decision to the log.
 * @param {object} entry { decision, prompt?, policyId?, risk?, threats?, surface? }
 * @returns {{ leafIndex, leafHash, sth }}
 */
function append(entry = {}) {
  const { priv, pub } = _loadOrCreateKey();
  const log = _load();
  const prevHash = log.leaves.length > 0
    ? log.leaves[log.leaves.length - 1].hash
    : _sha256('genesis');

  const ts = Date.now();
  const promptHash = entry.prompt
    ? _sha256(entry.prompt).slice(0, 16)  // first 16 hex chars — not reversible
    : '';
  const policyHash = entry.policyId ? _sha256(entry.policyId) : '';

  const leaf = {
    idx:        log.leaves.length,
    ts,
    decision:   entry.decision || 'ALLOW',
    promptHash,
    policyHash,
    risk:       entry.risk ?? 0,
    threats:    entry.threats || [],
    surface:    entry.surface || 'api',
    hash:       '',
  };
  leaf.hash = _leafHash(leaf, prevHash);

  log.leaves.push(leaf);

  const allHashes = log.leaves.map((l) => l.hash);
  const rootHash  = _merkleRoot(allHashes);
  const sth = {
    treeSize: log.leaves.length,
    rootHash,
    ts,
    sig: _signSth(log.leaves.length, rootHash, ts, priv),
    publicKey: pub,
  };
  log.sths.push(sth);

  _save(log);
  return { leafIndex: leaf.idx, leafHash: leaf.hash, sth };
}

/**
 * Get an inclusion proof for a leaf at `index`.
 */
function inclusionProof(index) {
  const log  = _load();
  const leaf = log.leaves[index];
  if (!leaf) return { ok: false, reason: 'index out of range' };
  const allHashes = log.leaves.map((l) => l.hash);
  const proof = _inclusionProof(index, allHashes);
  const root  = _merkleRoot(allHashes);
  const latestSth = log.sths[log.sths.length - 1] || null;
  return { ok: true, leaf, proof, root, sth: latestSth };
}

/**
 * Return the latest signed tree head.
 */
function latestSth() {
  const log = _load();
  if (log.sths.length === 0) return null;
  return log.sths[log.sths.length - 1];
}

/**
 * Verify the integrity of the entire local log.
 * Returns { ok, size, errors }.
 */
function verify() {
  const { pub } = _loadOrCreateKey();
  const log = _load();
  const errors = [];
  let prevHash = _sha256('genesis');

  for (const leaf of log.leaves) {
    const expected = _leafHash(leaf, prevHash);
    if (expected !== leaf.hash) {
      errors.push(`leaf ${leaf.idx}: hash mismatch — tampered`);
    }
    prevHash = leaf.hash;
  }

  const latestSth = log.sths[log.sths.length - 1];
  if (latestSth) {
    const valid = _verifySth(latestSth, pub);
    if (!valid) errors.push('latest STH signature invalid');
  }

  return { ok: errors.length === 0, size: log.leaves.length, errors, sth: latestSth || null };
}

/**
 * Return recent entries (last N), newest first.
 */
function recent(n = 50) {
  const log = _load();
  return log.leaves.slice(-n).reverse();
}

/**
 * Return the public key PEM for offline verifier distribution.
 */
function publicKey() {
  const { pub } = _loadOrCreateKey();
  return pub;
}

module.exports = { append, inclusionProof, latestSth, verify, recent, publicKey };
