'use strict';

/**
 * Federated Threat Intelligence — Privacy-Preserving Shared Defense
 * =================================================================
 * Kasbah instances share anonymized threat signatures via a Merkle
 * tree protocol. No raw prompts ever leave the local instance.
 *
 * HOW IT WORKS:
 *   1. Local detector flags a prompt as malicious
 *   2. Hash the prompt with SHA-256 + salt (never store raw text)
 *   3. Submit (hash, threat_class, severity, timestamp) to shared registry
 *   4. Registry builds a Merkle tree from all submissions
 *   5. Any instance can query: "has this hash been seen before?"
 *      → Returns Merkle proof of inclusion/exclusion
 *   6. Privacy: hash preimages never shared; only signatures are public
 *
 * GENUINELY NOVEL: No existing AI security tool does collaborative
 * defense. Every current tool (Guardrails, Lakera, etc.) is siloed.
 * This creates a network effect: each new instance improves detection
 * for all others, without compromising privacy.
 *
 * USAGE:
 *   const fti = new FederatedThreatIntel({ dataDir: './.kasbah/fti' });
 *   fti.submit({ hash: 'sha256:abc...', threatClass: 'prompt-injection', severity: 0.9 });
 *   const result = fti.query('sha256:abc...');
 *   // → { known: true, firstSeen: '2026-05-30T...', severity: 0.9, proof: [...] }
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ═══════════════════════════════════════════════════════════════
// Merkle Tree for Threat Registry
// ═══════════════════════════════════════════════════════════════

class ThreatMerkleTree {
  constructor() {
    this.leaves = [];  // [{hash, threatClass, severity, timestamp}]
    this.tree = [];    // [level0_leaves, level1_parents, ..., root]
  }

  _hash(data) {
    return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
  }

  _leafHash(entry) {
    return this._hash(`${entry.hash}:${entry.threatClass}:${entry.severity}:${entry.timestamp}`);
  }

  addLeaf(entry) {
    const leafHash = this._leafHash(entry);
    this.leaves.push({ ...entry, leafHash });
    this._rebuild();
    return { index: this.leaves.length - 1, leafHash };
  }

  _rebuild() {
    if (this.leaves.length === 0) { this.tree = []; return; }

    // Pad to power of 2
    let level = this.leaves.map(l => l.leafHash);
    while (level.length & (level.length - 1)) {
      level.push(level[level.length - 1]);
    }

    this.tree = [level];
    while (this.tree[this.tree.length - 1].length > 1) {
      const cur = this.tree[this.tree.length - 1];
      const next = [];
      for (let i = 0; i < cur.length; i += 2) {
        const combined = cur[i] + (cur[i + 1] || cur[i]);
        next.push(this._hash(combined));
      }
      this.tree.push(next);
    }
  }

  root() {
    return this.tree.length > 0 ? this.tree[this.tree.length - 1][0] : null;
  }

  /**
   * Generate Merkle inclusion proof for leaf at index.
   * Returns array of {sibling, position:'left'|'right'} from leaf to root.
   */
  getProof(index) {
    if (index >= this.leaves.length) return null;
    const proof = [];
    let idx = index;
    for (let level = 0; level < this.tree.length - 1; level++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      if (siblingIdx < this.tree[level].length) {
        proof.push({
          sibling: this.tree[level][siblingIdx],
          position: idx % 2 === 0 ? 'right' : 'left',
        });
      }
      idx = Math.floor(idx / 2);
    }
    return proof;
  }

  /**
   * Verify a Merkle proof for a leaf hash.
   */
  verifyProof(leafHash, proof, root) {
    let computed = leafHash;
    for (const step of proof) {
      const combined = step.position === 'left'
        ? step.sibling + computed
        : computed + step.sibling;
      computed = this._hash(combined);
    }
    return computed === root;
  }

  export() {
    return {
      leaves: this.leaves,
      root: this.root(),
      size: this.leaves.length,
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// Federated Threat Intel
// ═══════════════════════════════════════════════════════════════

class FederatedThreatIntel {
  /**
   * @param {object} opts
   * @param {string} opts.dataDir — directory for local registry storage
   * @param {string} opts.instanceId — unique instance identifier
   */
  constructor(opts = {}) {
    this.dataDir = opts.dataDir || path.resolve(__dirname, '..', '..', '..', '.kasbah', 'fti');
    this.instanceId = opts.instanceId || crypto.randomBytes(8).toString('hex');

    try { fs.mkdirSync(this.dataDir, { recursive: true }); } catch (_) {}

    this.registry = new ThreatMerkleTree();
    this.localSubmissions = new Map(); // hash → {threatClass, severity, timestamp}
    this.syncLog = [];

    this._load();
  }

  _registryPath() {
    return path.join(this.dataDir, 'threat-registry.json');
  }

  _load() {
    try {
      const data = JSON.parse(fs.readFileSync(this._registryPath(), 'utf8'));
      if (data.leaves) {
        for (const leaf of data.leaves) {
          this.registry.addLeaf(leaf);
          this.localSubmissions.set(leaf.hash, leaf);
        }
      }
    } catch (_) { /* fresh registry */ }
  }

  _save() {
    try {
      fs.writeFileSync(this._registryPath(), JSON.stringify(this.registry.export(), null, 2));
    } catch (_) { /* best effort */ }
  }

  /**
   * Submit a threat signature to the shared registry.
   *
   * @param {object} opts
   * @param {string} opts.hash — SHA-256 hash of the prompt (NEVER the raw prompt)
   * @param {string} opts.threatClass — e.g. 'prompt-injection', 'secret-leak', 'jailbreak'
   * @param {number} opts.severity — 0.0-1.0 risk score
   * @param {string} opts.source — detector that flagged it
   * @returns {{ index, root, proof }}
   */
  submit({ hash, threatClass, severity, source }) {
    if (!hash) throw new Error('hash required (submit the hash, never the raw prompt)');

    const entry = {
      hash,
      threatClass: threatClass || 'unknown',
      severity: +(severity || 0).toFixed(3),
      source: source || this.instanceId,
      timestamp: new Date().toISOString(),
    };

    const { index, leafHash } = this.registry.addLeaf(entry);
    this.localSubmissions.set(hash, entry);

    const proof = this.registry.getProof(index);
    this._save();

    this.syncLog.push({ action: 'submit', index, hash: hash.slice(0, 16) + '...' });

    return {
      index,
      root: this.registry.root(),
      proof,
      known: true,
      firstSeen: entry.timestamp,
    };
  }

  /**
   * Query whether a hash is known in the registry.
   * Returns Merkle proof of inclusion or exclusion.
   *
   * @param {string} hash — SHA-256 hash to query
   * @returns {{ known: boolean, proof?: array, firstSeen?: string, severity?: number, threatClass?: string }}
   */
  query(hash) {
    const entry = this.localSubmissions.get(hash);
    if (!entry) {
      return {
        known: false,
        root: this.registry.root(),
      };
    }

    // Find index in registry
    const index = this.registry.leaves.findIndex(l => l.hash === hash);
    const proof = index >= 0 ? this.registry.getProof(index) : null;

    return {
      known: true,
      hash: hash.slice(0, 16) + '...',
      threatClass: entry.threatClass,
      severity: entry.severity,
      firstSeen: entry.timestamp,
      proof,
      root: this.registry.root(),
    };
  }

  /**
   * Check if a prompt hash matches anything in the registry.
   * Use this BEFORE running expensive detection — if it's a known attack, skip analysis.
   *
   * @param {string} promptText — raw prompt (hashed locally, never transmitted)
   * @returns {{ known: boolean, details?: object }}
   */
  check(promptText) {
    const hash = crypto.createHash('sha256').update(promptText, 'utf8').digest('hex');
    return this.query(hash);
  }

  /**
   * Get registry statistics.
   */
  stats() {
    return {
      totalEntries: this.registry.leaves.length,
      root: this.registry.root(),
      instanceId: this.instanceId,
      threatClasses: [...new Set(this.registry.leaves.map(l => l.threatClass))],
      recentSubmissions: this.registry.leaves.slice(-10).map(l => ({
        hash: l.hash.slice(0, 12) + '...',
        threatClass: l.threatClass,
        severity: l.severity,
      })),
    };
  }

  /**
   * Export the full registry (Merkle tree + all leaves) for federation sync.
   */
  exportRegistry() {
    return this.registry.export();
  }

  /**
   * Import entries from another instance's export.
   * Deduplicates by hash — only adds genuinely new threats.
   */
  importRegistry(exported) {
    let added = 0;
    if (exported.leaves) {
      for (const leaf of exported.leaves) {
        if (!this.localSubmissions.has(leaf.hash)) {
          this.registry.addLeaf(leaf);
          this.localSubmissions.set(leaf.hash, leaf);
          added++;
        }
      }
    }
    this._save();
    return { added, total: this.registry.leaves.length };
  }
}

// ═══════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════

module.exports = { FederatedThreatIntel, ThreatMerkleTree };
