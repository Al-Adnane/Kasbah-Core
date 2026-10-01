'use strict';

/**
 * ForwardSecureAudit — tamper-evident append-only log with forward security.
 *
 * Idea (from the "Alice Moyo" synthesis, MSG 42; classic Bellare–Yee forward-
 * secure MAC / secure-logging construction):
 *
 *   - Each entry is authenticated with the CURRENT epoch key Kᵢ via HMAC.
 *   - The key then evolves one-way:  Kᵢ₊₁ = H("kasbah-fs-evolve" ‖ Kᵢ),
 *     and Kᵢ is zeroized.
 *   - Because H is preimage-resistant, an attacker who compromises the key at
 *     epoch e CANNOT recompute any earlier key, so they cannot forge or
 *     silently rewrite entries < e. They can only forge from e onward — and
 *     that is detectable by any verifier holding an earlier published key.
 *
 * This complements (does not replace) the Ed25519/PQC receipt signing in
 * engine-key.js: receipts give non-repudiation; this gives forward-secure
 * tamper-evidence of the *ordering and content* of the log itself.
 *
 * Honest scope: this is a forward-secure MAC chain, not a forward-secure
 * public-key signature. Verification requires a verifier that holds a key
 * commitment from some epoch j; it can then verify all entries ≥ j.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const EVOLVE_LABEL = Buffer.from('kasbah-fs-evolve');
const GENESIS_LABEL = Buffer.from('kasbah-fs-genesis');
const DEFAULT_PERSIST_PATH = path.join(os.homedir(), '.kasbah-privacy', 'fs-audit-chain.jsonl');

function sha256(...bufs) {
  const h = crypto.createHash('sha256');
  for (const b of bufs) h.update(b);
  return h.digest();
}

/** One-way key evolution: Kᵢ₊₁ = H(label ‖ Kᵢ). */
function evolveKey(key) {
  return sha256(EVOLVE_LABEL, key);
}

class ForwardSecureAudit {
  /**
   * @param {Buffer} [seed] — optional 32-byte seed (else CSPRNG). The seed is
   *   the epoch-0 key; callers may publish a commitment H(K₀) as the anchor.
   * @param {object} [opts]
   * @param {string|null} [opts.persistPath] — JSONL file to load/append
   *   entries from. Defaults to ~/.kasbah-privacy/fs-audit-chain.jsonl; pass
   *   null to run in-memory only (e.g. for tests).
   *
   * Restart behavior: entries (hash/tag/keyCommitment/payload — never the
   * raw epoch key, which is intentionally unrecoverable by design) are
   * persisted to disk. On construction, if a chain already exists on disk,
   * its hash-chain is continued (this.epoch / this._prevHash pick up where
   * it left off) rather than silently starting a fresh, disconnected chain
   * — a bare restart no longer erases audit history or breaks tamper
   * detection across the process boundary. The MAC key itself always starts
   * a fresh genesis per process (by design — a key that survived a restart
   * on disk would defeat the forward-secrecy this class exists to provide),
   * so `verify({key, fromEpoch})` continuity checks are scoped per-process;
   * the hash-chain check (the default `verify()` call) covers the full
   * persisted history.
   */
  constructor(seed, opts = {}) {
    this._key = seed && seed.length ? sha256(GENESIS_LABEL, seed) : crypto.randomBytes(32);
    this.genesisCommitment = sha256(this._key).toString('hex');
    this.entries = [];        // { epoch, ts, prevHash, hash, tag, keyCommitment, payload }
    this.epoch = 0;
    this._prevHash = '0'.repeat(64);
    this.persistPath = opts.persistPath === null ? null : (opts.persistPath || DEFAULT_PERSIST_PATH);
    if (this.persistPath) this._load();
  }

  _load() {
    try {
      const lines = fs.readFileSync(this.persistPath, 'utf8').trim().split('\n').filter(Boolean);
      const loaded = lines.map((l) => JSON.parse(l));
      if (!loaded.length) return;
      this.entries = loaded;
      const last = loaded[loaded.length - 1];
      this._prevHash = last.hash;
      this.epoch = last.epoch + 1;
    } catch (_) { /* no existing chain — start fresh */ }
  }

  _persist(entry) {
    if (!this.persistPath) return;
    try {
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true, mode: 0o700 });
      fs.appendFileSync(this.persistPath, JSON.stringify(entry) + '\n', { mode: 0o600 });
      this._maybeRotate();
    } catch (_) { /* best-effort — in-memory copy still holds the entry for this session */ }
  }

  /**
   * Rotate when the active log exceeds 5000 lines. Archives to
   * <basename>.epoch-<N>.jsonl.gz and starts a fresh active file.
   * The in-memory entries array is trimmed to the most recent 2000 entries.
   */
  _maybeRotate(limit = 5000) {
    try {
      const stat = fs.statSync(this.persistPath);
      // Rough heuristic: each entry ≈ 200 bytes; 5000 entries ≈ 1 MB
      if (stat.size < 1_000_000) return;
      const lines = fs.readFileSync(this.persistPath, 'utf8').trim().split('\n').filter(Boolean);
      if (lines.length < limit) return;
      const archivePath = this.persistPath.replace(/\.jsonl$/, '') + `.epoch-${this.epoch}.jsonl.gz`;
      const zlib = require('zlib');
      const gz = zlib.gzipSync(Buffer.from(lines.slice(0, -2000).join('\n') + '\n'));
      fs.writeFileSync(archivePath, gz, { mode: 0o600 });
      // Keep only the last 2000 entries in the active file
      fs.writeFileSync(this.persistPath, lines.slice(-2000).join('\n') + '\n', { mode: 0o600 });
      if (this.entries.length > 2000) this.entries = this.entries.slice(-2000);
    } catch (_) { /* rotation is best-effort; active log still works */ }
  }

  /** Canonical, stable serialization for hashing/MAC. */
  _canon(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map(x => this._canon(x)).join(',') + ']';
    const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + this._canon(obj[k])).join(',') + '}';
  }

  /**
   * Append a record. Authenticates with the current epoch key, then evolves
   * and zeroizes it (forward security).
   * @returns {object} the audit entry (without the secret key).
   */
  append(payload) {
    const ts = Date.now();
    const body = { epoch: this.epoch, ts, prevHash: this._prevHash, payload };
    const canon = Buffer.from(this._canon(body), 'utf8');
    const hash = sha256(canon).toString('hex');

    // Forward-secure MAC under the current epoch key.
    const tag = crypto.createHmac('sha256', this._key).update(canon).digest('hex');
    const keyCommitment = sha256(this._key).toString('hex');

    const entry = { epoch: this.epoch, ts, prevHash: this._prevHash, hash, tag, keyCommitment, payload };
    this.entries.push(entry);
    this._persist(entry);
    this._prevHash = hash;

    // Evolve key one-way and zeroize the old one.
    const next = evolveKey(this._key);
    this._key.fill(0);
    this._key = next;
    this.epoch += 1;

    return entry;
  }

  /**
   * Verify chain integrity (hash links) and, if a verifier key for some epoch
   * is supplied, the forward-secure MACs from that epoch onward.
   * @param {object} [opts] { fromEpoch, key } — a key known to a monitor.
   * @returns {{ok, brokenAt, macVerifiedFrom}}
   */
  verify(opts = {}) {
    let prev = '0'.repeat(64);
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      if (e.prevHash !== prev) return { ok: false, brokenAt: i, reason: 'prevHash mismatch' };
      const body = { epoch: e.epoch, ts: e.ts, prevHash: e.prevHash, payload: e.payload };
      const canon = Buffer.from(this._canon(body), 'utf8');
      if (sha256(canon).toString('hex') !== e.hash) return { ok: false, brokenAt: i, reason: 'hash mismatch' };
      prev = e.hash;
    }

    let macVerifiedFrom = null;
    if (opts.key && typeof opts.fromEpoch === 'number') {
      let k = Buffer.from(opts.key);
      for (let i = 0; i < this.entries.length; i++) {
        const e = this.entries[i];
        if (e.epoch < opts.fromEpoch) continue;
        const body = { epoch: e.epoch, ts: e.ts, prevHash: e.prevHash, payload: e.payload };
        const canon = Buffer.from(this._canon(body), 'utf8');
        const tag = crypto.createHmac('sha256', k).update(canon).digest('hex');
        if (tag !== e.tag) return { ok: false, brokenAt: i, reason: 'mac mismatch', macVerifiedFrom };
        if (macVerifiedFrom === null) macVerifiedFrom = e.epoch;
        k = evolveKey(k);
      }
    }
    return { ok: true, brokenAt: -1, macVerifiedFrom };
  }

  /** Public, non-secret snapshot for /health or export. */
  info() {
    return {
      epoch: this.epoch,
      entries: this.entries.length,
      genesisCommitment: this.genesisCommitment,
      headHash: this._prevHash,
      forwardSecure: true,
    };
  }
}

module.exports = { ForwardSecureAudit, evolveKey };
