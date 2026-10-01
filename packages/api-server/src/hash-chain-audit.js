'use strict';

/**
 * hash-chain-audit.js — Tamper-Evident Audit Ledger (pure JS, zero external deps)
 *
 * Each audit entry is cryptographically chained to the previous one:
 *   hash = SHA-256(JSON.stringify(data) + prevHash + ts)
 *
 * Any modification or deletion of a past entry will break the chain and be
 * detected immediately by verifyChain().  This is the infrastructure moat:
 * "mathematically impossible to silently tamper with audit logs."
 *
 * Exports:
 *   appendEntry(data)  → { entryId, sequence, hash, prevHash, ts }
 *   getChain()         → Array of all chained entries (deep copy)
 *   verifyChain()      → { valid, entryCount, latestHash, brokenAt? }
 *   getLatestHash()    → string — tip hash or genesis hash
 *   reset()            → clears the chain (test use only)
 */

const crypto = require('crypto');

// Genesis hash — well-known zero value that anchors the chain
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// In-memory ledger (survives across requests within a process lifetime)
// Format: [{ entryId, sequence, data, prevHash, hash, ts }]
const _chain = [];

let _sequence = 0;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function _generateId() {
  return 'hca_' + Date.now().toString(36) + '_' + crypto.randomBytes(6).toString('hex');
}

// ---------------------------------------------------------------------------
// appendEntry(data) — add a new entry to the chain
// ---------------------------------------------------------------------------

/**
 * Append a new governance event to the hash chain.
 *
 * @param {object} data - Any JSON-serialisable object (audit event payload)
 * @returns {{ entryId, sequence, hash, prevHash, ts }}
 */
function appendEntry(data) {
  const entryId  = _generateId();
  const sequence = ++_sequence;
  const ts       = Date.now();
  const prevHash = _chain.length > 0
    ? _chain[_chain.length - 1].hash
    : GENESIS_HASH;

  // hash = SHA-256(data-json + prevHash + timestamp)
  const hash = _sha256(JSON.stringify(data) + prevHash + ts.toString());

  const record = { entryId, sequence, data, prevHash, hash, ts };
  _chain.push(record);

  return { entryId, sequence, hash, prevHash, ts };
}

// ---------------------------------------------------------------------------
// getChain() — return a deep copy of the full chain
// ---------------------------------------------------------------------------

/**
 * Return a deep-cloned snapshot of the full audit chain.
 * Mutations to the returned array cannot corrupt the internal ledger.
 *
 * @returns {Array}
 */
function getChain() {
  return JSON.parse(JSON.stringify(_chain));
}

// ---------------------------------------------------------------------------
// verifyChain() — cryptographically validate all entries
// ---------------------------------------------------------------------------

/**
 * Walk the full chain and verify:
 *   1. Each entry's prevHash matches the previous entry's hash (or GENESIS)
 *   2. Each entry's hash is correctly computed from its data + prevHash + ts
 *
 * @returns {{ valid: boolean, entryCount: number, latestHash: string, brokenAt?: string }}
 */
function verifyChain() {
  if (_chain.length === 0) {
    return { valid: true, entryCount: 0, latestHash: GENESIS_HASH };
  }

  let expectedPrev = GENESIS_HASH;

  for (let i = 0; i < _chain.length; i++) {
    const entry = _chain[i];

    // Verify prevHash linkage
    if (entry.prevHash !== expectedPrev) {
      return {
        valid:      false,
        entryCount: _chain.length,
        latestHash: expectedPrev,
        brokenAt:   entry.entryId,
        reason:     `prevHash mismatch at sequence ${entry.sequence}`,
      };
    }

    // Re-compute hash and compare
    const expectedHash = _sha256(JSON.stringify(entry.data) + entry.prevHash + entry.ts.toString());
    if (entry.hash !== expectedHash) {
      return {
        valid:      false,
        entryCount: _chain.length,
        latestHash: expectedPrev,
        brokenAt:   entry.entryId,
        reason:     `hash mismatch at sequence ${entry.sequence} — entry tampered`,
      };
    }

    expectedPrev = entry.hash;
  }

  const tip = _chain[_chain.length - 1];
  return {
    valid:      true,
    entryCount: _chain.length,
    latestHash: tip.hash,
  };
}

// ---------------------------------------------------------------------------
// getLatestHash() — get tip hash (or genesis if chain is empty)
// ---------------------------------------------------------------------------

/**
 * @returns {string} SHA-256 hex hash of the most recent entry, or GENESIS_HASH
 */
function getLatestHash() {
  if (_chain.length === 0) return GENESIS_HASH;
  return _chain[_chain.length - 1].hash;
}

// ---------------------------------------------------------------------------
// reset() — for testing only
// ---------------------------------------------------------------------------

function reset() {
  _chain.length = 0;
  _sequence = 0;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  appendEntry,
  getChain,
  verifyChain,
  getLatestHash,
  reset,
  GENESIS_HASH,
};
