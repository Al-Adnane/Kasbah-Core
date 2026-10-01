'use strict';

/**
 * Merkle Mountain Range for tamper-evident backup manifests.
 * Leaf = sha256(file bytes + name). Prove a file is in the published root.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }

function leafHash(name, data) {
  return sha256(Buffer.concat([Buffer.from(String(name), 'utf8'), Buffer.from([0]), data]));
}

/** Simple binary Merkle (not full MMR peaks — enough for one-shot manifests). */
function merkleRoot(leaves) {
  if (!leaves.length) return sha256(Buffer.alloc(0));
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = level[i + 1] || a;
      next.push(sha256(Buffer.concat([a, b])));
    }
    level = next;
  }
  return level[0];
}

function merkleProof(leaves, index) {
  const proof = [];
  let level = leaves.slice();
  let idx = index;
  while (level.length > 1) {
    const isRight = idx % 2 === 1;
    const pair = isRight ? idx - 1 : idx + 1;
    if (pair < level.length) proof.push({ hash: level[pair].toString('hex'), side: isRight ? 'left' : 'right' });
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i];
      const b = level[i + 1] || a;
      next.push(sha256(Buffer.concat([a, b])));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}

function verifyProof(leaf, proof, rootHex) {
  let h = leaf;
  for (const step of proof) {
    const sib = Buffer.from(step.hash, 'hex');
    h = step.side === 'left' ? sha256(Buffer.concat([sib, h])) : sha256(Buffer.concat([h, sib]));
  }
  return h.toString('hex') === rootHex;
}

/**
 * Build a manifest for a list of files.
 * @param {string[]} filePaths
 * @param {string} outPath — writes JSON { root, files: [{name, size, leaf, proof}] }
 */
function buildManifest(filePaths, outPath) {
  const leaves = [];
  const meta = [];
  for (const fp of filePaths) {
    const data = fs.readFileSync(fp);
    const name = path.basename(fp);
    const leaf = leafHash(name, data);
    leaves.push(leaf);
    meta.push({ name, size: data.length, path: fp, leaf: leaf.toString('hex') });
  }
  const root = merkleRoot(leaves);
  const files = meta.map((m, i) => ({
    ...m,
    proof: merkleProof(leaves, i).map((p) => ({ ...p, hash: p.hash })),
  }));
  const manifest = {
    createdAt: new Date().toISOString(),
    root: root.toString('hex'),
    count: files.length,
    files,
  };
  if (outPath) fs.writeFileSync(outPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  return manifest;
}

function verifyManifest(manifest, filePath) {
  const name = path.basename(filePath);
  const entry = (manifest.files || []).find((f) => f.name === name);
  if (!entry) return { valid: false, error: 'not in manifest' };
  const data = fs.readFileSync(filePath);
  const leaf = leafHash(name, data);
  const ok = verifyProof(leaf, entry.proof || [], manifest.root);
  return { valid: ok, root: manifest.root, name };
}

function backupDir() {
  return path.join(os.homedir(), '.kasbah-backup');
}

module.exports = { buildManifest, verifyManifest, merkleRoot, leafHash, backupDir };
