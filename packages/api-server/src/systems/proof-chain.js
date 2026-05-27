// Extracted from ARCHIVE — converted from TypeScript to JS
/**
 * ProofChain - Cryptographic Receipt Engine
 *
 * Core engine for generating tamper-proof creation receipts.
 * Uses SHA-256 hash chain with proof-of-work (hash must start with '00').
 *
 * Adapted from archive for in-memory operation (no filesystem I/O).
 * Hardware attestation via hardware-enclave when available.
 */

'use strict';

const crypto = require('crypto');

// ── Hardware Enclave (optional) ───────────────────────────────────────────────
let _enclave = { isAvailable: () => false, getHardware: () => 'software' };
try {
  const enclaveModule = require('../../../hardware-enclave/index.js');
  if (enclaveModule && typeof enclaveModule.isAvailable === 'function') {
    _enclave = enclaveModule;
    if (_enclave.isAvailable()) {
      console.log('[proof-chain] Hardware enclave available:', _enclave.getHardware());
    }
  }
} catch (_) {
  // hardware-enclave native addon not available — software mode
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF LEDGER — In-memory blockchain-style hash chain
// ═══════════════════════════════════════════════════════════════════════════

class ProofLedger {
  constructor() {
    this.chain = [];
    this._createGenesisBlock();
  }

  // ─── GENESIS ─────────────────────────────────────────────────────────────

  _createGenesisBlock() {
    const timestamp = new Date().toISOString();
    let nonce = 0;
    let hash  = '';

    // Mine genesis block
    while (!hash.startsWith('00')) {
      nonce++;
      hash = this._calculateHash(0, timestamp, 'genesis', '0'.repeat(64), nonce);
    }

    this.chain = [{
      index:        0,
      timestamp,
      type:         'genesis',
      data:         null,
      previousHash: '0'.repeat(64),
      hash,
      nonce
    }];
  }

  // ─── CORE HASH ───────────────────────────────────────────────────────────

  _calculateHash(index, timestamp, data, previousHash, nonce) {
    return crypto
      .createHash('sha256')
      .update(`${index}${timestamp}${JSON.stringify(data)}${previousHash}${nonce}`)
      .digest('hex');
  }

  // ─── ADD RECEIPT ─────────────────────────────────────────────────────────

  /**
   * Append a new block to the chain containing receiptData.
   * Proof-of-work: mines until hash starts with '00'.
   * @param {*} data - Any serialisable data to record
   * @returns {Object} The newly appended block
   */
  addReceipt(data) {
    const previousBlock = this.chain[this.chain.length - 1];
    const timestamp     = new Date().toISOString();
    const index         = this.chain.length;
    let   nonce         = 0;
    let   hash          = '';

    // Proof-of-work: find hash starting with '00'
    while (!hash.startsWith('00')) {
      nonce++;
      hash = this._calculateHash(index, timestamp, data, previousBlock.hash, nonce);
    }

    const newBlock = {
      index,
      timestamp,
      data,
      previousHash: previousBlock.hash,
      hash,
      nonce
    };

    this.chain.push(newBlock);
    return newBlock;
  }

  // ─── VERIFY CHAIN ────────────────────────────────────────────────────────

  /**
   * Verify every block's hash and previousHash reference.
   * @returns {{ valid: boolean, brokenAt?: number, reason?: string }}
   */
  verifyChain() {
    for (let i = 1; i < this.chain.length; i++) {
      const current  = this.chain[i];
      const previous = this.chain[i - 1];

      // Verify the stored hash is correct
      const expectedHash = this._calculateHash(
        current.index,
        current.timestamp,
        current.data,
        current.previousHash,
        current.nonce
      );

      if (current.hash !== expectedHash) {
        return { valid: false, brokenAt: i, reason: 'Hash mismatch' };
      }

      // Verify the chain link
      if (current.previousHash !== previous.hash) {
        return { valid: false, brokenAt: i, reason: 'Chain broken' };
      }
    }
    return { valid: true };
  }

  // ─── ACCESSORS ───────────────────────────────────────────────────────────

  /** Return full chain (including genesis block). */
  getChain() {
    return this.chain;
  }

  /** Return the hash at the tip of the chain. */
  getLatestHash() {
    return this.chain[this.chain.length - 1].hash;
  }

  /** Look up a block by receiptId stored in block.data.receiptId */
  getReceipt(receiptId) {
    return this.chain.find(block => block.data && block.data.receiptId === receiptId) || null;
  }

  /** High-level statistics. */
  getStats() {
    return {
      totalReceipts: this.chain.length - 1, // Exclude genesis
      chainValid:    this.verifyChain().valid,
      lastBlock:     this.chain[this.chain.length - 1]
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RECEIPT GENERATOR — Builds structured receipts and commits them to ledger
// ═══════════════════════════════════════════════════════════════════════════

class ReceiptGenerator {
  /**
   * @param {ProofLedger} ledger
   */
  constructor(ledger) {
    if (!ledger) throw new Error('ReceiptGenerator requires a ProofLedger instance');
    this.ledger = ledger;
  }

  /**
   * Generate a tamper-proof receipt for arbitrary data.
   *
   * @param {string|Buffer} content    - Raw content to hash
   * @param {string}        name       - Human-readable name / filename
   * @param {Object}        [metadata] - Optional creator metadata
   * @returns {Object} Structured receipt with chain info
   */
  generate(content, name = 'unknown', metadata = {}) {
    const receiptId = this._generateReceiptId();
    const timestamp = new Date().toISOString();

    // Normalise content to Buffer for consistent hashing
    const buf      = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    const fileHash = crypto.createHash('sha256').update(buf).digest('hex');

    const receipt = {
      receiptId,
      version:   '1.0',
      timestamp,
      name,
      contentHash: fileHash,
      creator: {
        name:  metadata.creatorName  || 'Anonymous',
        email: metadata.creatorEmail || null,
        url:   metadata.creatorUrl   || null
      },
      chain: {
        blockIndex:   0,   // Set after addReceipt
        previousHash: '',  // Set after addReceipt
        blockHash:    ''   // Set after addReceipt
      },
      ...(_enclave.isAvailable() ? { hardware: _enclave.getHardware() } : {})
    };

    // Commit to ledger
    const block = this.ledger.addReceipt({
      receiptId,
      contentHash: fileHash,
      timestamp,
      creator: receipt.creator.name
    });

    receipt.chain.blockIndex   = block.index;
    receipt.chain.previousHash = block.previousHash;
    receipt.chain.blockHash    = block.hash;

    return receipt;
  }

  /**
   * Verify a receipt by looking it up in the ledger and checking chain integrity.
   */
  verify(receiptId) {
    const block = this.ledger.getReceipt(receiptId);
    if (!block) {
      return { valid: false, error: 'Receipt not found in ledger' };
    }

    const chainResult = this.ledger.verifyChain();

    return {
      valid:      chainResult.valid,
      receipt:    block.data,
      block: {
        index:        block.index,
        timestamp:    block.timestamp,
        hash:         block.hash,
        previousHash: block.previousHash
      },
      chainValid: chainResult.valid
    };
  }

  // ─── INTERNAL ────────────────────────────────────────────────────────────

  _generateReceiptId() {
    const ts  = Date.now().toString(36).toUpperCase();
    const rnd = crypto.randomBytes(6).toString('hex').toUpperCase();
    return `PC-${ts}-${rnd}`;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

module.exports = { ProofLedger, ReceiptGenerator, enclaveAvailable: _enclave.isAvailable() };
