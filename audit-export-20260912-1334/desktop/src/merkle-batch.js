'use strict';

/**
 * merkle-batch.js — Merkle-tree batch verification for Kasbah receipts
 *
 * Implements §7 of RECEIPT-SPEC-v3. Provides:
 *   - buildMerkleTree(receipts)      → { root, tree, proofs }
 *   - verifyMerkleProof(receiptStr, payloadB64, proof, root) → boolean
 *   - verifyBatch(receipts, root)     → { verified, count }  (batch validation)
 *
 * Construction:
 *   1. receipt_hash[i] = SHA-256(receipt_string + "|" + payloadB64)
 *   2. Sort receipt_hashes lexicographically.
 *   3. Build binary Merkle tree bottom-up.
 *   4. Return root + per-receipt proofs.
 *
 * Pure JS. Zero dependencies. Compatible with Node 18+.
 */

const crypto = require('crypto');

function sha256hex(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

/**
 * Build a Merkle tree from an array of receipt pairs.
 *
 * @param {Array<{ receipt: string, payload: string }>} receipts
 * @returns {{ root: string, proofs: Map<string, string[]>, leaves: string[] }}
 */
function buildMerkleTree(receipts) {
  if (!receipts || receipts.length === 0) {
    return { root: sha256hex(''), proofs: new Map(), leaves: [] };
  }

  // Step 1: Hash each receipt
  const leaves = receipts.map(r =>
    sha256hex(r.receipt + '|' + r.payload)
  );

  // Step 2: Sort lexicographically (deterministic tree)
  const sorted = [...leaves].sort();

  // Step 3: Build tree bottom-up
  // Standard Merkle: promote odd last node unchanged (no duplication).
  // This keeps proofs valid — the verifier reconstructs the same structure.
  let level = sorted;
  const tree = [level]; // tree[0] = leaves, tree[1] = level-1, etc.

  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : null;
      if (right !== null) {
        nextLevel.push(sha256hex(left + right));
      } else {
        nextLevel.push(left); // promote odd last node unchanged
      }
    }
    tree.push(nextLevel);
    level = nextLevel;
  }

  const root = level[0];

  // Step 4: Build proof for each leaf
  const proofs = new Map();
  for (let i = 0; i < sorted.length; i++) {
    const proof = [];
    let idx = i;
    for (let h = 0; h < tree.length - 1; h++) {
      const levelNodes = tree[h];
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      if (siblingIdx < levelNodes.length) {
        proof.push({
          hash: levelNodes[siblingIdx],
          position: idx % 2 === 0 ? 'right' : 'left' // sibling is to the right or left
        });
      }
      idx = Math.floor(idx / 2);
    }
    proofs.set(sorted[i], proof);
  }

  return { root, proofs, leaves: sorted };
}

/**
 * Verify a single receipt against a Merkle root using its proof.
 *
 * @param {string} receiptStr — full receipt string (e.g. "kasbah_receipt:v3:ed25519:...")
 * @param {string} payloadB64 — base64url-encoded canonical payload
 * @param {Array<{ hash: string, position: 'left'|'right' }>} proof — sibling hashes with position
 * @param {string} root — expected Merkle root
 * @returns {boolean}
 */
function verifyMerkleProof(receiptStr, payloadB64, proof, root) {
  let computed = sha256hex(receiptStr + '|' + payloadB64);

  for (const sibling of proof) {
    if (sibling.position === 'right') {
      computed = sha256hex(computed + sibling.hash);
    } else {
      computed = sha256hex(sibling.hash + computed);
    }
  }

  return computed === root;
}

/**
 * Batch-verify an array of receipts against a published Merkle root.
 *
 * @param {Array<{ receipt: string, payload: string, merkleProof?: Array }>} receipts
 * @param {string} expectedRoot — published Merkle root
 * @returns {{ verified: boolean, count: number, root: string, failures: string[] }}
 */
function verifyBatch(receipts, expectedRoot) {
  if (!receipts || receipts.length === 0) {
    return { verified: true, count: 0, root: expectedRoot, failures: [] };
  }

  // Rebuild tree from receipts
  const { root: computedRoot } = buildMerkleTree(receipts);

  if (computedRoot !== expectedRoot) {
    return {
      verified: false,
      count: receipts.length,
      root: computedRoot,
      failures: ['root_mismatch'],
      expectedRoot,
    };
  }

  // Verify individual proofs if provided
  const failures = [];
  for (const r of receipts) {
    if (r.merkleProof) {
      const valid = verifyMerkleProof(r.receipt, r.payload, r.merkleProof, expectedRoot);
      if (!valid) failures.push(r.receipt.slice(0, 64) + '...');
    }
  }

  return {
    verified: failures.length === 0,
    count: receipts.length,
    root: expectedRoot,
    failures,
  };
}

module.exports = {
  buildMerkleTree,
  verifyMerkleProof,
  verifyBatch,
  sha256hex,
};
