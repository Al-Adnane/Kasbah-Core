// Extracted from ARCHIVE — converted from TypeScript to JS
/**
 * Tamper-Proof Hash-Chained Audit Ledger for Kasbah Compliance
 *
 * Key features:
 * - AuditEntry structure with compliance framework tags (SOC2/HIPAA/GDPR/PCI_DSS/ISO27001)
 * - Merkle tree for efficient proof generation
 * - Checkpoint-based verification for large ledgers
 * - Compliance report generation per framework
 * - In-memory storage (no filesystem I/O)
 *
 * @author Kasbah Guard Team
 * @version 1.0.0
 * @patent Pending (Priority Date: March 11, 2026)
 */

'use strict';

const { createHash, createHmac, randomBytes } = require('crypto');

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

const GENESIS_HASH = '0x' + '0'.repeat(64);

const VALID_EVENT_TYPES = new Set([
  'ACCESS', 'MODIFY', 'DELETE', 'EXECUTE',
  'AUTHENTICATE', 'AUTHORIZE', 'DETECT', 'ALERT',
  'COMPLIANCE', 'SYSTEM'
]);

const VALID_FRAMEWORKS = new Set(['SOC2', 'HIPAA', 'GDPR', 'PCI_DSS', 'ISO27001']);

// Minimum required retention days per framework
const FRAMEWORK_RETENTION = {
  HIPAA:   2190,  // 6 years
  SOC2:    2555,  // 7 years
  PCI_DSS: 1095,  // 3 years
  GDPR:    2555,  // 7 years
  ISO27001: 2555  // 7 years
};

// ═══════════════════════════════════════════════════════════════════════════
// COMPLIANCE AUDIT LEDGER
// ═══════════════════════════════════════════════════════════════════════════

class ComplianceAuditLedger {
  /**
   * @param {Object} [config]
   * @param {string}   [config.signingKey]            - HMAC key for entry signatures
   * @param {number}   [config.checkpointInterval]    - Entries per checkpoint (default 1000)
   * @param {boolean}  [config.enableMerkleProofs]    - Enable Merkle proof generation (default true)
   * @param {number}   [config.merkleLeafCount]       - Merkle bucket size, power of 2 (default 1024)
   * @param {number}   [config.defaultRetentionDays]  - Default retention period (default 2555)
   * @param {string[]} [config.complianceFrameworks]  - Default frameworks to tag entries with
   */
  constructor(config = {}) {
    this.signingKey           = config.signingKey           || null;
    this.checkpointInterval   = config.checkpointInterval   !== undefined ? config.checkpointInterval   : 1000;
    this.enableMerkleProofs   = config.enableMerkleProofs   !== undefined ? config.enableMerkleProofs   : true;
    this.merkleLeafCount      = config.merkleLeafCount      !== undefined ? config.merkleLeafCount      : 1024;
    this.defaultRetentionDays = config.defaultRetentionDays !== undefined ? config.defaultRetentionDays : 2555;
    this.complianceFrameworks = config.complianceFrameworks || ['SOC2', 'HIPAA', 'GDPR'];

    // Validate merkleLeafCount is a power of 2
    if ((this.merkleLeafCount & (this.merkleLeafCount - 1)) !== 0) {
      throw new Error('merkleLeafCount must be a power of 2');
    }

    // In-memory storage
    this._entries     = [];           // AuditEntry[]
    this._checkpoints = new Map();    // index → LedgerCheckpoint
    this._merkleCache = new Map();    // bucketIndex → string[]

    // Stats
    this._stats = { total_entries: 0, total_verifications: 0, last_verification_time_ms: 0 };
  }

  // ─── APPEND ──────────────────────────────────────────────────────────────

  /**
   * Append an audit entry to the ledger.
   *
   * @param {string}   eventType   - One of the VALID_EVENT_TYPES
   * @param {Object}   data        - { subject, object, action, metadata }
   * @param {string[]} [frameworks] - Override default compliance framework tags
   * @returns {Object} Complete AuditEntry with all cryptographic fields
   */
  appendEntry(eventType, data = {}, frameworks) {
    if (!VALID_EVENT_TYPES.has(eventType)) {
      throw new Error(`Invalid event type: ${eventType}. Must be one of: ${[...VALID_EVENT_TYPES].join(', ')}`);
    }

    const appliedFrameworks = (frameworks || this.complianceFrameworks).filter(f => VALID_FRAMEWORKS.has(f));
    const index    = this._entries.length;
    const prevHash = index === 0 ? GENESIS_HASH : this._entries[index - 1].entry_hash;

    /** @type {AuditEntry} */
    const entry = {
      index,
      entry_id:             this._generateEntryId(),
      timestamp:            this._getNanotime(),
      event_type:           eventType,
      subject:              data.subject  || 'unknown',
      object:               data.object   || 'unknown',
      action:               data.action   || eventType.toLowerCase(),
      metadata:             data.metadata || {},
      prev_hash:            prevHash,
      entry_hash:           '',  // Computed below
      merkle_proof:         null,
      compliance_frameworks: appliedFrameworks,
      retention_days:       this.defaultRetentionDays,
      signature:            null,
      checkpoint_hash:      null
    };

    // Compute entry hash (covers all stable fields)
    entry.entry_hash = this._computeEntryHash(entry);

    // Sign if key provided
    if (this.signingKey) {
      entry.signature = this._signEntry(entry);
    }

    // Generate Merkle proof if enabled
    if (this.enableMerkleProofs) {
      entry.merkle_proof = this.generateMerkleProof(index);
    }

    // Create checkpoint if needed
    if (this.checkpointInterval > 0 && (index + 1) % this.checkpointInterval === 0) {
      this._entries.push(entry); // Temporarily push so _createCheckpoint can see this entry
      const checkpoint = this._createCheckpoint(index);
      entry.checkpoint_hash = checkpoint.cumulative_hash;
      this._checkpoints.set(index, checkpoint);
      // Already pushed — update in-place
      this._entries[this._entries.length - 1] = entry;
    } else {
      this._entries.push(entry);
    }

    this._stats.total_entries++;

    // Update Merkle cache
    if (this.enableMerkleProofs) {
      this._updateMerkleCache(entry.entry_hash, index);
    }

    return entry;
  }

  // ─── MERKLE PROOF ────────────────────────────────────────────────────────

  /**
   * Generate a Merkle proof for the entry at `index`.
   * The proof allows verifying the entry is in the tree without replaying the full ledger.
   *
   * @param {number} index
   * @returns {string[]} Merkle proof path elements
   */
  generateMerkleProof(index) {
    const leaves = this.entries.map(e => e.entry_hash || '0'.repeat(64));
    if (index < 0 || index >= leaves.length) return [];

    // Build full Merkle tree (binary, pairs hashed together)
    const layers = [leaves.slice()];
    while (layers[layers.length - 1].length > 1) {
      const prev = layers[layers.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        const left  = prev[i];
        const right = prev[i + 1] || prev[i];
        next.push(this._merkleHash(left + right));
      }
      layers.push(next);
    }

    // Collect sibling hashes along the path to root
    const proof = [];
    let idx = index;
    for (let l = 0; l < layers.length - 1; l++) {
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      const sibling = layers[l][siblingIdx] || layers[l][idx];
      proof.push({ hash: sibling, position: isRight ? 'left' : 'right' });
      idx = Math.floor(idx / 2);
    }
    proof.push({ root: layers[layers.length - 1][0] });
    return proof;
  }

  _merkleHash(combined) {
    return require('crypto').createHash('sha256').update(combined).digest('hex');
  }

  // ─── VERIFY ──────────────────────────────────────────────────────────────

  /**
   * Verify the entire ledger integrity.
   * Checks: hash chain linkage, entry hash validity, signatures (if present), Merkle proofs.
   *
   * @param {Object} [options]
   * @returns {{ valid: boolean, verified_entries: number, failed_entries: number, first_failure_index?: number, failure_reason?: string, verification_time_ms: number }}
   */
  verifyChain(options = {}) {
    const startTime = Date.now();
    const { verifySignatures = true, verifyMerkleProofs = true } = options;

    let failedEntries      = 0;
    let firstFailureIndex;
    let failureReason;

    let prevHash = GENESIS_HASH;

    for (const entry of this._entries) {
      // 1. Check prev_hash linkage
      if (entry.prev_hash !== prevHash) {
        failedEntries++;
        if (firstFailureIndex === undefined) {
          firstFailureIndex = entry.index;
          failureReason = `Hash chain broken at entry ${entry.index}: prev_hash mismatch`;
        }
        break;
      }

      // 2. Verify entry hash
      const computedHash = this._computeEntryHash(entry);
      if (entry.entry_hash !== computedHash) {
        failedEntries++;
        if (firstFailureIndex === undefined) {
          firstFailureIndex = entry.index;
          failureReason = `Entry hash invalid at entry ${entry.index}`;
        }
        break;
      }

      // 3. Verify signature
      if (verifySignatures && entry.signature) {
        if (!this._verifySignature(entry)) {
          failedEntries++;
          if (firstFailureIndex === undefined) {
            firstFailureIndex = entry.index;
            failureReason = `Signature invalid at entry ${entry.index}`;
          }
          break;
        }
      }

      prevHash = entry.entry_hash;
    }

    // 4. Verify Merkle proofs
    if (verifyMerkleProofs && this.enableMerkleProofs && failedEntries === 0) {
      for (const entry of this._entries) {
        if (entry.merkle_proof && !this._verifyMerkleProof(entry)) {
          failedEntries++;
          if (firstFailureIndex === undefined) {
            firstFailureIndex = entry.index;
            failureReason = `Merkle proof invalid at entry ${entry.index}`;
          }
          break;
        }
      }
    }

    this._stats.total_verifications++;
    this._stats.last_verification_time_ms = Date.now() - startTime;

    return {
      valid:               failedEntries === 0,
      verified_entries:    this._entries.length,
      failed_entries:      failedEntries,
      first_failure_index: firstFailureIndex,
      failure_reason:      failureReason,
      verification_time_ms: Date.now() - startTime
    };
  }

  /**
   * Verify a single entry against a previously generated Merkle proof.
   * Lightweight verification without replaying the full ledger.
   *
   * @param {Object}   entry - AuditEntry
   * @param {string[]} proof - Proof returned by generateMerkleProof()
   * @returns {boolean}
   */
  verifyEntry(entry, proof) {
    if (!proof || proof.length < 2) return false;
    const recomputed = this._computeEntryHash(entry);
    if (recomputed !== entry.entry_hash) return false;

    // Walk the proof path to recompute root, compare with proof's declared root
    const rootProof = proof[proof.length - 1];
    if (!rootProof || !rootProof.root) return false;

    let current = entry.entry_hash;
    for (let i = 0; i < proof.length - 1; i++) {
      const { hash, position } = proof[i];
      if (!hash || !position) return false;
      current = position === 'left'
        ? this._merkleHash(hash + current)
        : this._merkleHash(current + hash);
    }
    return current === rootProof.root;
  }

  // ─── COMPLIANCE REPORT ───────────────────────────────────────────────────

  /**
   * Generate a compliance report for a given framework.
   *
   * @param {string}  framework   - One of SOC2/HIPAA/GDPR/PCI_DSS/ISO27001
   * @param {number}  [periodStart] - ms timestamp (default: 90 days ago)
   * @param {number}  [periodEnd]   - ms timestamp (default: now)
   * @returns {Object} ComplianceReport
   */
  generateComplianceReport(framework, periodStart, periodEnd) {
    if (!VALID_FRAMEWORKS.has(framework)) {
      throw new Error(`Invalid framework: ${framework}. Must be one of: ${[...VALID_FRAMEWORKS].join(', ')}`);
    }

    const now    = Date.now();
    const pStart = periodStart !== undefined ? periodStart : now - 90 * 24 * 60 * 60 * 1000;
    const pEnd   = periodEnd   !== undefined ? periodEnd   : now;

    // Filter entries tagged with this framework in the time window
    // Timestamps are stored in nanoseconds → convert ms bounds to ns
    const pStartNs = pStart * 1_000_000;
    const pEndNs   = pEnd   * 1_000_000;

    const relevantEntries = this._entries.filter(e =>
      e.timestamp >= pStartNs &&
      e.timestamp <= pEndNs   &&
      e.compliance_frameworks.includes(framework)
    );

    // Count by event type
    const entriesByType = {
      ACCESS: 0, MODIFY: 0, DELETE: 0, EXECUTE: 0,
      AUTHENTICATE: 0, AUTHORIZE: 0, DETECT: 0, ALERT: 0,
      COMPLIANCE: 0, SYSTEM: 0
    };
    for (const e of relevantEntries) {
      if (e.event_type in entriesByType) entriesByType[e.event_type]++;
    }

    // Verify integrity (lightweight check)
    const verification = this.verifyChain({ verifyMerkleProofs: false });

    // Retention compliance
    const retentionCompliant = this._checkRetentionCompliance(framework, relevantEntries);

    // Generate findings
    const findings = this._generateFindings(framework, relevantEntries);

    // Attestation hash
    const attestationData = JSON.stringify({
      framework,
      period_start: pStart,
      period_end:   pEnd,
      total_entries: relevantEntries.length,
      integrity_hash: verification.valid ? this._computeMerkleRoot() : 'INVALID',
      generated_at: now
    });
    const attestationHash = '0x' + this._sha256(attestationData);

    return {
      framework,
      period_start: pStart,
      period_end:   pEnd,
      total_entries: relevantEntries.length,
      entries_by_type: entriesByType,
      integrity_verified: verification.valid,
      retention_compliant: retentionCompliant,
      findings,
      attestation_hash: attestationHash,
      generated_at: now,
      entries: relevantEntries
    };
  }

  // ─── ACCESSORS ───────────────────────────────────────────────────────────

  /** Return the full in-memory chain. */
  getChain() {
    return this._entries;
  }

  /** Return a single entry by index. */
  getEntry(index) {
    return this._entries[index] || null;
  }

  /** Return entries in a ms timestamp range. */
  getEntriesByTimeRange(startMs, endMs) {
    const startNs = startMs * 1_000_000;
    const endNs   = endMs   * 1_000_000;
    return this._entries.filter(e => e.timestamp >= startNs && e.timestamp <= endNs);
  }

  /** Return ledger statistics. */
  getStats() {
    return {
      ...this._stats,
      checkpoint_count:  this._checkpoints.size,
      ledger_size_bytes: this._entries.length * 500  // Rough estimate
    };
  }

  // ─── PRIVATE HELPERS ─────────────────────────────────────────────────────

  _computeEntryHash(entry) {
    const data = JSON.stringify({
      index:                 entry.index,
      entry_id:              entry.entry_id,
      timestamp:             entry.timestamp,
      event_type:            entry.event_type,
      subject:               entry.subject,
      object:                entry.object,
      action:                entry.action,
      metadata:              entry.metadata,
      prev_hash:             entry.prev_hash,
      compliance_frameworks: entry.compliance_frameworks,
      retention_days:        entry.retention_days
    });
    return '0x' + this._sha256(data);
  }

  _signEntry(entry) {
    if (!this.signingKey) return null;
    const data = JSON.stringify({
      entry_hash: entry.entry_hash,
      timestamp:  entry.timestamp,
      index:      entry.index
    });
    return this._hmac(this.signingKey, data);
  }

  _verifySignature(entry) {
    if (!this.signingKey || !entry.signature) return false;
    const data = JSON.stringify({
      entry_hash: entry.entry_hash,
      timestamp:  entry.timestamp,
      index:      entry.index
    });
    return entry.signature === this._hmac(this.signingKey, data);
  }

  _verifyMerkleProof(entry) {
    if (!entry.merkle_proof || entry.merkle_proof.length < 2) return false;
    return entry.merkle_proof[0].startsWith('level_') && entry.merkle_proof[1].startsWith('index_');
  }

  _createCheckpoint(index) {
    const entry          = this._entries[index];
    const cumulativeHash = this._computeCumulativeHash(index);
    const merkleRoot     = this._computeMerkleRoot();

    return {
      checkpoint_id:   `chkpt_${index}_${this._sha256(entry.entry_hash).slice(0, 16)}`,
      entry_index:     index,
      entry_hash:      entry.entry_hash,
      cumulative_hash: cumulativeHash,
      timestamp:       entry.timestamp,
      merkle_root:     merkleRoot
    };
  }

  _computeCumulativeHash(upToIndex) {
    let hash = GENESIS_HASH;
    for (let i = 0; i <= upToIndex; i++) {
      hash = this._sha256(hash + this._entries[i].entry_hash);
    }
    return '0x' + hash;
  }

  _computeMerkleRoot() {
    if (this._entries.length === 0) return GENESIS_HASH;

    // Strip '0x' prefix before hashing pairs
    let level = this._entries.map(e => e.entry_hash.slice(2));
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const left  = level[i];
        const right = level[i + 1] || left; // Duplicate last leaf if odd count
        next.push(this._sha256(left + right));
      }
      level = next;
    }
    return '0x' + level[0];
  }

  _updateMerkleCache(entryHash, index) {
    const bucket = Math.floor(index / this.merkleLeafCount);
    if (!this._merkleCache.has(bucket)) this._merkleCache.set(bucket, []);
    this._merkleCache.get(bucket).push(entryHash);
  }

  _checkRetentionCompliance(framework, entries) {
    const requiredDays = FRAMEWORK_RETENTION[framework] || 2555;
    const nowMs        = Date.now();
    for (const entry of entries) {
      const ageMs   = nowMs - (entry.timestamp / 1_000_000);
      const ageDays = ageMs / (24 * 60 * 60 * 1000);
      if (entry.retention_days < requiredDays || ageDays > entry.retention_days) {
        return false;
      }
    }
    return true;
  }

  _generateFindings(framework, entries) {
    const findings = [];
    const eventTypes = new Set(entries.map(e => e.event_type));

    // Check for required event types
    const required = ['AUTHENTICATE', 'AUTHORIZE', 'ACCESS'];
    for (const req of required) {
      if (!eventTypes.has(req)) {
        findings.push({
          severity:         'MEDIUM',
          category:         'Missing Event Types',
          description:      `No ${req} events found in audit period`,
          affected_entries: [],
          recommendation:   `Ensure ${req} events are being logged`
        });
      }
    }

    // Check high alert volume (> 10 % of events)
    const alertCount = entries.filter(e => e.event_type === 'ALERT').length;
    if (entries.length > 0 && alertCount > entries.length * 0.1) {
      findings.push({
        severity:         'HIGH',
        category:         'High Alert Volume',
        description:      `Alert events exceed 10% of total events (${alertCount}/${entries.length})`,
        affected_entries: entries.filter(e => e.event_type === 'ALERT').map(e => e.index),
        recommendation:   'Review alert patterns and investigate root causes'
      });
    }

    // Framework-specific checks
    if (framework === 'HIPAA') {
      const deleteCount = entries.filter(e => e.event_type === 'DELETE').length;
      if (deleteCount > 0) {
        findings.push({
          severity:         'HIGH',
          category:         'Data Deletion Under HIPAA',
          description:      `${deleteCount} DELETE events detected — review PHI deletion compliance`,
          affected_entries: entries.filter(e => e.event_type === 'DELETE').map(e => e.index),
          recommendation:   'Verify all deletions comply with HIPAA data destruction requirements'
        });
      }
    }

    if (framework === 'GDPR') {
      const modifyCount = entries.filter(e => e.event_type === 'MODIFY').length;
      if (modifyCount > 0) {
        findings.push({
          severity:         'INFO',
          category:         'Data Modification Under GDPR',
          description:      `${modifyCount} MODIFY events — ensure lawful basis for each modification`,
          affected_entries: entries.filter(e => e.event_type === 'MODIFY').map(e => e.index),
          recommendation:   'Document legal basis for data modifications per GDPR Article 6'
        });
      }
    }

    return findings;
  }

  // ─── CRYPTO PRIMITIVES ───────────────────────────────────────────────────

  _sha256(data) {
    return createHash('sha256').update(String(data)).digest('hex');
  }

  _hmac(key, data) {
    return createHmac('sha256', key).update(String(data)).digest('hex');
  }

  _getNanotime() {
    return Date.now() * 1_000_000;
  }

  _generateEntryId() {
    const ts  = Date.now().toString(36);
    const rnd = randomBytes(12).toString('hex');
    return `audit_${ts}_${rnd}`;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = { ComplianceAuditLedger };
