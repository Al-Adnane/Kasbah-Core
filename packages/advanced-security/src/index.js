'use strict';

/**
 * advanced-security — consent ledger, EWMA dynamic thresholds, cross-modal
 * consistency, Shamir secret sharing, dead-man switch.
 *
 * Everything here is a working implementation:
 *   - ShamirSecretSharing is real GF(256) polynomial secret sharing
 *     (AES field 0x11b, generator 3) — k−1 shares reveal nothing.
 *   - CrossModalChecker compares modalities with real MiniLM sentence
 *     embeddings when the in-process model is warm (cosine similarity),
 *     falling back to lexical Jaccard/character-trigram cosine — the
 *     `method` field always discloses which one ran.
 *   - ConsentManager is an in-memory grant ledger with TTL and purpose/
 *     data-type scoping; DeadManSwitch is a real timer.
 */

const crypto = require('crypto');

// ── GF(256) arithmetic for Shamir ────────────────────────────────────────────

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x ^= (x << 1) ^ (x & 0x80 ? 0x11b : 0); // multiply by generator 3: x*2 ^ x
    x &= 0xff;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const gmul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];
const gdiv = (a, b) => {
  if (b === 0) throw new Error('GF division by zero');
  return a === 0 ? 0 : EXP[(LOG[a] - LOG[b] + 255) % 255];
};

class ShamirSecretSharing {
  constructor({ threshold = 3, totalShares = 5 } = {}) {
    this.threshold = threshold;
    this.totalShares = totalShares;
  }

  /**
   * Split hex-encoded secret into n shares, any k of which reconstruct it.
   * Share format: "x-hex" where x is the evaluation point (1..n).
   */
  static generate(secretHex, k = 3, n = 5) {
    if (!/^[0-9a-fA-F]+$/.test(secretHex) || secretHex.length % 2) throw new Error('secret must be even-length hex');
    if (k < 2 || n < k || n > 255) throw new Error('need 2 <= k <= n <= 255');
    const secret = Buffer.from(secretHex, 'hex');
    const shares = [];
    // One random polynomial of degree k-1 per byte; constant term = secret byte.
    const polys = Array.from(secret, (byte) => {
      const coeffs = [byte, ...crypto.randomBytes(k - 1)];
      return coeffs;
    });
    for (let x = 1; x <= n; x++) {
      const out = Buffer.alloc(secret.length);
      for (let i = 0; i < secret.length; i++) {
        // Horner evaluation at x in GF(256)
        let acc = 0;
        for (let j = polys[i].length - 1; j >= 0; j--) acc = gmul(acc, x) ^ polys[i][j];
        out[i] = acc;
      }
      shares.push(`${x}-${out.toString('hex')}`);
    }
    return { shares, threshold: k, totalShares: n, algorithm: 'shamir-gf256' };
  }

  /** Lagrange interpolation at x=0 over GF(256). */
  static combine(shares) {
    const pts = shares.map((s) => {
      const idx = s.indexOf('-');
      const x = parseInt(s.slice(0, idx), 10);
      const y = Buffer.from(s.slice(idx + 1), 'hex');
      if (!Number.isInteger(x) || x < 1 || x > 255) throw new Error(`bad share point: ${s.slice(0, 8)}…`);
      return { x, y };
    });
    const len = pts[0].y.length;
    if (pts.some((p) => p.y.length !== len)) throw new Error('shares have mismatched lengths');
    const out = Buffer.alloc(len);
    for (let b = 0; b < len; b++) {
      let secretByte = 0;
      for (let i = 0; i < pts.length; i++) {
        let num = 1, den = 1;
        for (let j = 0; j < pts.length; j++) {
          if (i === j) continue;
          num = gmul(num, pts[j].x);              // (0 - xj) = xj in GF(2^8)
          den = gmul(den, pts[i].x ^ pts[j].x);   // (xi - xj) = xi ^ xj
        }
        secretByte ^= gmul(pts[i].y[b], gdiv(num, den));
      }
      out[b] = secretByte;
    }
    return out.toString('hex');
  }
}

// ── ConsentManager ───────────────────────────────────────────────────────────

class ConsentManager {
  constructor() { this._grants = new Map(); }

  _key(subject, purpose) { return `${subject}::${purpose}`; }

  grant(dataSubject, purpose, { dataTypes = ['default'], ttlMs = 365 * 24 * 3600 * 1000, ...scope } = {}) {
    const g = {
      id: 'grant_' + crypto.randomBytes(8).toString('hex'),
      dataSubject, purpose,
      dataTypes: Array.isArray(dataTypes) && dataTypes.length ? dataTypes : ['default'],
      scope,
      granted: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      revoked: false,
    };
    this._grants.set(this._key(dataSubject, purpose), g);
    return g;
  }

  check(dataSubject, purpose, dataType = 'default') {
    const g = this._grants.get(this._key(dataSubject, purpose));
    if (!g) return { granted: false, reason: 'no grant on record for this subject+purpose' };
    if (g.revoked) return { granted: false, reason: 'grant was revoked', revokedAt: g.revokedAt };
    if (Date.now() > Date.parse(g.expiresAt)) return { granted: false, reason: 'grant expired', expiredAt: g.expiresAt };
    if (!g.dataTypes.includes(dataType) && !g.dataTypes.includes('*')) {
      return { granted: false, reason: `grant does not cover dataType "${dataType}"`, covered: g.dataTypes };
    }
    return { granted: true, grantId: g.id, expiresAt: g.expiresAt, dataTypes: g.dataTypes };
  }

  revoke(dataSubject, purpose) {
    const g = this._grants.get(this._key(dataSubject, purpose));
    if (!g) return { revoked: false, reason: 'no grant on record' };
    g.revoked = true; g.revokedAt = new Date().toISOString();
    return { revoked: true, grantId: g.id };
  }
}

// ── DynamicThreshold ─────────────────────────────────────────────────────────
// EWMA over the observed error mix: false positives push the threshold UP
// (be less trigger-happy), false negatives push it DOWN (be stricter).

class DynamicThreshold {
  constructor({ baseThreshold = 0.5, alpha = 0.05, min = 0.2, max = 0.9 } = {}) {
    this.base = baseThreshold;
    this.alpha = alpha;
    this.min = min; this.max = max;
    this.ewma = 0;          // signed error pressure in [-1, 1]
    this.events = 0;
  }

  record(_type, isFP /* true=false-positive, false=false-negative */) {
    const signal = isFP ? +1 : -1;
    this.ewma = (1 - this.alpha) * this.ewma + this.alpha * signal;
    this.events++;
  }

  getThreshold() {
    const threshold = Math.min(this.max, Math.max(this.min, this.base + this.ewma * 0.25));
    const threatLevel = this.ewma < -0.3 ? 'elevated' : this.ewma > 0.3 ? 'relaxed' : 'baseline';
    return { threshold: +threshold.toFixed(4), threatLevel, ewma: +this.ewma.toFixed(4), events: this.events };
  }
}

// ── CrossModalChecker ────────────────────────────────────────────────────────

let _embedder = null;
try { _embedder = require('../../api-server/src/ml/injection-js.js'); } catch (_) { /* lexical fallback */ }

function _trigramVec(text) {
  const m = new Map();
  const t = String(text).toLowerCase().replace(/\s+/g, ' ');
  for (let i = 0; i < t.length - 2; i++) {
    const g = t.slice(i, i + 3);
    m.set(g, (m.get(g) || 0) + 1);
  }
  return m;
}
function _trigramCosine(a, b) {
  const va = _trigramVec(a), vb = _trigramVec(b);
  let dot = 0, na = 0, nb = 0;
  for (const [g, c] of va) { na += c * c; if (vb.has(g)) dot += c * vb.get(g); }
  for (const c of vb.values()) nb += c * c;
  return na && nb ? dot / Math.sqrt(na * nb) : 0;
}
function _cos(a, b) {
  let d = 0; for (let i = 0; i < a.length; i++) d += a[i] * b[i];
  return d; // embeddings are already L2-normalized
}

class CrossModalChecker {
  /**
   * Compare textual representations of modalities (text output, image
   * caption/description, audio transcript). Returns pairwise similarity,
   * overall consistency (the weakest pair), and divergence flags.
   */
  async check(modalities = {}) {
    const present = Object.entries(modalities).filter(([, v]) => typeof v === 'string' && v.trim());
    if (present.length === 0) return { consistency: null, flags: ['no textual modalities supplied'], method: 'none' };
    if (present.length === 1) {
      return { consistency: 1, flags: [], method: 'single-modality (nothing to cross-check)', modality: present[0][0] };
    }

    let method = 'lexical-trigram-cosine';
    let vecs = null;
    if (_embedder && _embedder.isReady && _embedder.isReady()) {
      vecs = await Promise.all(present.map(([, v]) => _embedder.embed(v)));
      if (vecs.every(Boolean)) method = 'minilm-embedding-cosine';
      else vecs = null;
    }

    const pairs = [];
    for (let i = 0; i < present.length; i++) {
      for (let j = i + 1; j < present.length; j++) {
        const sim = vecs ? _cos(vecs[i], vecs[j]) : _trigramCosine(present[i][1], present[j][1]);
        pairs.push({ pair: `${present[i][0]}↔${present[j][0]}`, similarity: +sim.toFixed(4) });
      }
    }
    const consistency = +Math.min(...pairs.map((p) => p.similarity)).toFixed(4);
    const flags = pairs.filter((p) => p.similarity < 0.4)
      .map((p) => `${p.pair} diverge (similarity ${p.similarity}) — the modalities may not describe the same thing`);
    return { consistency, pairs, flags, method };
  }
}

// ── DeadManSwitch ────────────────────────────────────────────────────────────

class DeadManSwitch {
  constructor({ intervalMs = 60_000, onTrigger = null } = {}) {
    this.intervalMs = intervalMs;
    this.onTrigger = onTrigger;
    this._timer = null;
    this.armedAt = null;
    this.lastHeartbeat = null;
    this.triggered = false;
  }
  arm() {
    this.disarm();
    this.armedAt = Date.now();
    this.lastHeartbeat = Date.now();
    this.triggered = false;
    this._timer = setTimeout(() => {
      this.triggered = true;
      if (typeof this.onTrigger === 'function') { try { this.onTrigger(); } catch (_) {} }
    }, this.intervalMs);
    if (this._timer.unref) this._timer.unref();
    return { armed: true, fireAt: new Date(this.armedAt + this.intervalMs).toISOString() };
  }
  heartbeat() {
    if (!this._timer) return { armed: false };
    this.lastHeartbeat = Date.now();
    return this.arm(); // reset the clock
  }
  disarm() {
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
    return { armed: false };
  }
  status() {
    return { armed: !!this._timer, triggered: this.triggered, lastHeartbeat: this.lastHeartbeat, intervalMs: this.intervalMs };
  }
}

module.exports = { ConsentManager, DynamicThreshold, CrossModalChecker, ShamirSecretSharing, DeadManSwitch };
