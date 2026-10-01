'use strict';

/**
 * Merkle batch for Protection Proofs (RECEIPT-SPEC-v3 §7 style).
 * Build a tree over proof hashes; verify membership against one root.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function sha256hex(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function leafOf(entry) {
  return sha256hex((entry.receipt || '') + '|' + (entry.payload || ''));
}

function buildTree(leaves) {
  if (!leaves.length) return { root: sha256hex(''), proofs: new Map() };
  let level = leaves.slice().sort(); // lexicographic like spec
  const layers = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = level[i + 1] || a;
      next.push(sha256hex(a + b));
    }
    level = next;
    layers.push(level);
  }
  // proofs: for each original leaf, sibling path
  const proofs = new Map();
  const sorted = leaves.slice().sort();
  for (const leaf of sorted) {
    const proof = [];
    let idx = layers[0].indexOf(leaf);
    for (let d = 0; d < layers.length - 1; d++) {
      const isRight = idx % 2 === 1;
      const pair = isRight ? idx - 1 : idx + 1;
      if (pair < layers[d].length) proof.push({ hash: layers[d][pair], side: isRight ? 'left' : 'right' });
      idx = Math.floor(idx / 2);
    }
    proofs.set(leaf, proof);
  }
  return { root: level[0], proofs, leaves: sorted };
}

function batch(entries) {
  const leaves = entries.map(leafOf);
  const { root, proofs } = buildTree(leaves);
  const items = entries.map((e, i) => {
    const leaf = leaves[i];
    return {
      requestId: e.requestId,
      leaf,
      proof: proofs.get(leaf) || [],
      receipt: e.receipt,
      payload: e.payload,
    };
  });
  return { root, count: items.length, items };
}

function verifyMembership(leaf, proof, root) {
  let h = leaf;
  for (const step of proof || []) {
    const sib = step.hash;
    h = step.side === 'left' ? sha256hex(sib + h) : sha256hex(h + sib);
  }
  return h === root;
}

function batchFromFile(file) {
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  const proofs = j.proofs || [];
  const b = batch(proofs);
  const out = {
    ...b,
    exportedAt: new Date().toISOString(),
    keyId: j.keyId || null,
    publicKeyPem: j.publicKeyPem || null,
  };
  const dest = file.replace(/\.json$/, '') + '-merkle.json';
  fs.writeFileSync(dest, JSON.stringify(out, null, 2), { mode: 0o600 });
  return { ok: true, root: b.root, count: b.count, file: dest };
}

module.exports = { batch, verifyMembership, leafOf, batchFromFile };
