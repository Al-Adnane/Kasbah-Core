/**
 * Kasbah Crypto Advanced — VDF, MMR, Shamir Secret Sharing
 *
 * CommonJS port of:
 *   packages/crypto-utils/src/vdf.ts     — Verifiable Delay Function (sequential SHA-256)
 *   packages/crypto-utils/src/mmr.ts     — Merkle Mountain Range
 *   packages/crypto-utils/src/shamir.ts  — Shamir's Secret Sharing over GF(256)
 *
 * No external dependencies — Node.js built-in `crypto` only.
 */

'use strict';

const { createHash, randomBytes: nodeRandomBytes } = require('crypto');

// ════════════════════════════════════════════════════════════
// Shared hash helpers
// ════════════════════════════════════════════════════════════

function sha256(data) {
  return createHash('sha256').update(data).digest();
}

function hashPair(left, right) {
  return createHash('sha256').update(left).update(right).digest();
}

// ════════════════════════════════════════════════════════════
// VDF — Verifiable Delay Function (sequential SHA-256)
// From: packages/crypto-utils/src/vdf.ts
//
// Algorithm:
//   - Iterates SHA-256 sequentially N times (cannot be parallelised)
//   - Records a checkpoint hash every CHECKPOINT_INTERVAL iterations
//   - Builds a Merkle tree over checkpoints → proof = Merkle root
// ════════════════════════════════════════════════════════════

const CHECKPOINT_INTERVAL = 1000;

/** Build a 1-indexed Merkle tree (Bitcoin-style, padded to power-of-2). */
function buildMerkleTree(leaves) {
  if (leaves.length === 0) return [Buffer.alloc(32)];

  let n = 1;
  while (n < leaves.length) n <<= 1;

  const paddedLeaves = new Array(n);
  for (let i = 0; i < n; i++) {
    paddedLeaves[i] = i < leaves.length ? leaves[i] : leaves[leaves.length - 1];
  }

  const tree = new Array(2 * n).fill(null);
  for (let i = 0; i < n; i++) tree[n + i] = paddedLeaves[i];
  for (let i = n - 1; i >= 1; i--) tree[i] = hashPair(tree[2 * i], tree[2 * i + 1]);

  return tree;
}

function merkleRoot(tree) {
  return tree[1] || Buffer.alloc(32);
}

/**
 * vdfCompute(input, difficulty)
 *
 * `difficulty` maps to iteration count: difficulty * 1000 iterations.
 * Returns: { proof: hex string, value: hex string, iterations, time_ms, difficulty }
 *
 * @param {string|Buffer} input
 * @param {number} difficulty  — multiplied by 1000 to get iteration count
 * @returns {{ proof: string, value: string, iterations: number, time_ms: number, difficulty: number }}
 */
function vdfCompute(input, difficulty) {
  const iterations = Math.max(1, Math.floor(difficulty) * 1000);
  const inputBuf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');

  const checkpoints = [];
  const t0 = Date.now();

  let current = sha256(inputBuf); // iteration 0

  for (let i = 1; i < iterations; i++) {
    current = sha256(current);
    if (i % CHECKPOINT_INTERVAL === 0) {
      checkpoints.push(Buffer.from(current));
    }
  }

  if (iterations % CHECKPOINT_INTERVAL !== 0 || checkpoints.length === 0) {
    checkpoints.push(Buffer.from(current));
  }

  const tree  = buildMerkleTree(checkpoints);
  const proof = merkleRoot(tree);
  const time_ms = Date.now() - t0;

  return {
    proof:      proof.toString('hex'),
    value:      current.toString('hex'),
    iterations,
    time_ms,
    difficulty
  };
}

/**
 * vdfVerify(input, proof, difficulty)
 *
 * Re-runs the VDF and checks that the Merkle root matches.
 * Returns: { valid: boolean }
 *
 * @param {string|Buffer} input
 * @param {string} proof  — hex string from vdfCompute
 * @param {number} difficulty
 * @returns {{ valid: boolean }}
 */
function vdfVerify(input, proof, difficulty) {
  try {
    const result = vdfCompute(input, difficulty);
    return { valid: result.proof === proof };
  } catch (_) {
    return { valid: false };
  }
}

// ════════════════════════════════════════════════════════════
// MMR — Merkle Mountain Range
// From: packages/crypto-utils/src/mmr.ts
//
// Algorithm:
//   - Append-only authenticated structure of perfect binary trees ("mountains")
//   - Inserting a leaf propagates merges (carry-propagation on binary addition)
//   - Root = "bagging" all peak hashes (right-fold of hashPair)
//   - Proofs: Merkle path from leaf to mountain root + all peaks
// ════════════════════════════════════════════════════════════

// ── MMR Position Arithmetic ─────────────────────────────────

function peakPositions(n) {
  if (n === 0) return [];
  const peaks = [];
  let pos = 0;
  let remaining = n;
  while (remaining > 0) {
    const h = 31 - Math.clz32(remaining);
    const subTreeLeaves = 1 << h;
    const subTreeNodes  = 2 * subTreeLeaves - 1;
    pos += subTreeNodes;
    peaks.push(pos);
    remaining -= subTreeLeaves;
  }
  return peaks;
}

function localLeafPos(k, h) {
  if (h === 0) return 1;
  const leftLeaves = 1 << (h - 1);
  const leftNodes  = 2 * leftLeaves - 1;
  if (k < leftLeaves) {
    return localLeafPos(k, h - 1);
  } else {
    return leftNodes + localLeafPos(k - leftLeaves, h - 1);
  }
}

function pathSiblings(localPos, height) {
  const path = [];
  let pos = localPos;
  let h = height;
  while (h > 0) {
    const leftNodes = (1 << h) - 1;
    const inLeftSubtree = pos <= leftNodes;
    if (inLeftSubtree) {
      const rightSubtreeRoot = (1 << (h + 1)) - 2;
      path.push({ siblingLocalPos: rightSubtreeRoot, nodeIsLeftChild: true });
      h--;
    } else {
      const rightLocalPos = pos - leftNodes;
      path.push({ siblingLocalPos: leftNodes, nodeIsLeftChild: false });
      pos = rightLocalPos;
      h--;
    }
  }
  return path;
}

function bagPeaks(peaks) {
  if (peaks.length === 1) return peaks[0];
  let acc = peaks[peaks.length - 1];
  for (let i = peaks.length - 2; i >= 0; i--) {
    acc = hashPair(peaks[i], acc);
  }
  return acc;
}

// ── MMR State Object ─────────────────────────────────────────
// Instead of a class we use a plain state object so callers can
// serialise/deserialise the tree (suitable for the API layer).

/**
 * Create a fresh empty MMR state.
 * Internal shape: { nodes: [null, ...], leafCount, nodeCount }
 */
function _mmrCreate() {
  return { nodes: [null], leafCount: 0, nodeCount: 0 };
}

function _mmrShouldMerge(state, height) {
  const rightPos = state.nodeCount;
  const leftPos  = rightPos - (1 << (height + 1)) + 1;
  return leftPos >= 1 && state.nodes[leftPos] != null;
}

function _mmrAddNode(state, hash) {
  state.nodeCount++;
  state.nodes.push(hash);
  let height = 0;
  while (_mmrShouldMerge(state, height)) {
    const rightPos = state.nodeCount;
    const leftPos  = rightPos - (1 << (height + 1)) + 1;
    const left  = state.nodes[leftPos];
    const right = state.nodes[rightPos];
    const parent = hashPair(left, right);
    state.nodeCount++;
    state.nodes.push(parent);
    height++;
  }
}

function _mmrCurrentPeaks(state) {
  return peakPositions(state.leafCount).map(p => {
    const node = state.nodes[p];
    if (!node) throw new Error(`MMR peak at position ${p} is null`);
    return node;
  });
}

function _mmrLocateMountain(state, leafIndex) {
  let remaining   = leafIndex;
  let basePos     = 1;
  let n           = state.leafCount;
  let mountainIdx = 0;
  while (n > 0) {
    const h         = 31 - Math.clz32(n);
    const subLeaves = 1 << h;
    const subNodes  = 2 * subLeaves - 1;
    if (remaining < subLeaves) {
      return { mountainIndex: mountainIdx, leafOrdinalInMountain: remaining, basePos, height: h };
    }
    remaining   -= subLeaves;
    basePos     += subNodes;
    n           -= subLeaves;
    mountainIdx++;
  }
  throw new Error(`Leaf ${leafIndex} not found in MMR with ${state.leafCount} leaves`);
}

// ── Public MMR API ───────────────────────────────────────────

/**
 * mmrAppend(tree, leaf)
 *
 * Appends a leaf (string or Buffer) to the MMR and returns the updated state.
 * `tree` may be null/undefined to start a new MMR.
 *
 * @param {Object|null} tree  — MMR state from a prior call (or null)
 * @param {string|Buffer} leaf
 * @returns {Object} updated MMR state
 */
function _reviveBuffer(v) {
  if (!v) return v;
  // Node serialises Buffer as { type: 'Buffer', data: [...] }
  if (v.type === 'Buffer' && Array.isArray(v.data)) return Buffer.from(v.data);
  return v;
}

function mmrAppend(tree, leaf) {
  let state;
  if (!tree) {
    state = _mmrCreate();
  } else {
    // Deep-clone via JSON round-trip and revive Buffer entries in nodes[]
    const raw = JSON.parse(JSON.stringify(tree));
    state = {
      leafCount: raw.leafCount,
      nodeCount: raw.nodeCount,
      nodes: raw.nodes.map(n => (n === null || n === undefined) ? null : _reviveBuffer(n))
    };
  }

  // Ensure nodes[0] is null sentinel (may have been serialised away)
  if (state.nodes.length === 0) state.nodes = [null];
  if (state.nodes[0] !== null) state.nodes.unshift(null);

  const leafBuf = Buffer.isBuffer(leaf) ? leaf : Buffer.from(String(leaf), 'utf8');
  const leafHash = sha256(leafBuf);

  _mmrAddNode(state, leafHash);
  state.leafCount++;

  return state;
}

/**
 * mmrProve(tree, index)
 *
 * Generate a Merkle inclusion proof for the leaf at 0-based `index`.
 * Returns: { leafIndex, peaksHex: string[], siblingsHex: string[] }
 *
 * @param {Object} tree
 * @param {number} index
 * @returns {{ leafIndex: number, peaksHex: string[], siblingsHex: string[] }}
 */
function mmrProve(tree, index) {
  if (!tree || tree.leafCount === 0) throw new Error('MMR is empty');
  if (index < 0 || index >= tree.leafCount) {
    throw new RangeError(`Leaf index ${index} out of range [0, ${tree.leafCount - 1}]`);
  }

  // Revive buffers
  const nodes = tree.nodes.map(n => {
    if (!n) return null;
    if (Buffer.isBuffer(n)) return n;
    if (n.type === 'Buffer' && Array.isArray(n.data)) return Buffer.from(n.data);
    return n;
  });

  const peaks = peakPositions(tree.leafCount).map(p => {
    const node = nodes[p];
    if (!node) throw new Error(`Peak at MMR position ${p} is null`);
    return node;
  });

  const { leafOrdinalInMountain, basePos, height } = _mmrLocateMountain(tree, index);
  const localPos = localLeafPos(leafOrdinalInMountain, height);
  const pathInfo = pathSiblings(localPos, height);

  const siblings = pathInfo.map(({ siblingLocalPos }) => {
    const globalPos = basePos + siblingLocalPos - 1;
    const node = nodes[globalPos];
    if (!node) throw new Error(`MMR node at position ${globalPos} is null`);
    return node;
  });

  return {
    leafIndex:    index,
    peaksHex:     peaks.map(p => p.toString('hex')),
    siblingsHex:  siblings.map(s => s.toString('hex'))
  };
}

/**
 * mmrVerify(root, leaf, proof)
 *
 * Verify that `leaf` is included in an MMR whose root is `root`.
 * `proof` must be a value returned by mmrProve() — but we need the
 * original tree state to resolve mountain positions, so we also accept
 * the tree state.
 *
 * For a standalone call: pass the MMR state as `tree` alongside.
 * This function operates purely on the proof data itself:
 *   - Re-hashes the leaf
 *   - Walks up siblings to recompute the mountain peak
 *   - Bags all peaks and checks against root
 *
 * @param {string} root           — hex MMR root
 * @param {string|Buffer} leaf    — original leaf data
 * @param {{ leafIndex, peaksHex, siblingsHex, tree }} proof
 * @returns {{ valid: boolean }}
 */
function mmrVerify(root, leaf, proof) {
  try {
    if (!proof || !proof.peaksHex || !proof.siblingsHex) return { valid: false };

    const peaks    = proof.peaksHex.map(h => Buffer.from(h, 'hex'));
    const siblings = proof.siblingsHex.map(h => Buffer.from(h, 'hex'));

    // We need the mountain layout to know which direction each sibling goes.
    // Re-derive from leaf index and siblings.length (= mountain height).
    const height  = siblings.length;
    // Without the full tree we infer the leaf ordinal within the mountain from
    // peaksHex.length and leafIndex. Instead of requiring the full state here,
    // we use the pathSiblings helper: it gives direction info if we know height
    // and leafOrdinalInMountain. For standalone verification we accept the
    // tree state embedded in the proof object.
    if (!proof.tree) return { valid: false };

    const { leafOrdinalInMountain, mountainIndex } = _mmrLocateMountain(proof.tree, proof.leafIndex);
    const localPos = localLeafPos(leafOrdinalInMountain, height);
    const pathInfo = pathSiblings(localPos, height);

    const leafBuf = Buffer.isBuffer(leaf) ? leaf : Buffer.from(String(leaf), 'utf8');
    let current = sha256(leafBuf);

    for (let i = 0; i < pathInfo.length; i++) {
      const { nodeIsLeftChild } = pathInfo[i];
      const sibling = siblings[i];
      current = nodeIsLeftChild ? hashPair(current, sibling) : hashPair(sibling, current);
    }

    // current should equal the mountain's peak
    const expectedPeak = peaks[mountainIndex];
    if (!current.equals(expectedPeak)) return { valid: false };

    // Bag all peaks and compare to root
    const computedRoot = bagPeaks(peaks);
    return { valid: computedRoot.toString('hex') === root };
  } catch (_) {
    return { valid: false };
  }
}

// ════════════════════════════════════════════════════════════
// Shamir's Secret Sharing over GF(256)
// From: packages/crypto-utils/src/shamir.ts
//
// Algorithm:
//   - GF(256) with AES irreducible polynomial (0x11b)
//   - Per-byte degree-(k-1) polynomial; constant term = secret byte
//   - Split: evaluate at x=1..n
//   - Combine: Lagrange interpolation at x=0
// ════════════════════════════════════════════════════════════

// ── GF(256) arithmetic ───────────────────────────────────────

function gfMul(a, b) {
  let product = 0;
  let aa = a & 0xff;
  let bb = b & 0xff;
  while (bb > 0) {
    if (bb & 1) product ^= aa;
    const hiBitSet = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hiBitSet) aa ^= 0x1b;
    bb >>= 1;
  }
  return product & 0xff;
}

function gfAdd(a, b) { return (a ^ b) & 0xff; }

function gfInverse(a) {
  if (a === 0) throw new Error('GF(256) inverse of zero is undefined');
  let result = 1;
  let base = a & 0xff;
  let exp = 254;
  while (exp > 0) {
    if (exp & 1) result = gfMul(result, base);
    base = gfMul(base, base);
    exp >>= 1;
  }
  return result;
}

function polyEval(coefficients, x) {
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfAdd(gfMul(result, x), coefficients[i]);
  }
  return result;
}

/**
 * shamirSplit(secret, n, k)
 *
 * Splits `secret` into `n` shares; any `k` shares reconstruct it.
 * Accepts a string or Buffer. Returns array of n Buffer shares.
 *
 * Share format: byte 0 = 1-indexed share index, bytes 1..len = evaluations.
 *
 * @param {string|Buffer} secret
 * @param {number} n  total shares
 * @param {number} k  threshold
 * @returns {Buffer[]}
 */
function shamirSplit(secret, n, k) {
  const secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(String(secret), 'utf8');
  if (secretBuf.length === 0) throw new Error('Secret must not be empty');
  if (k < 1) throw new Error('Threshold must be >= 1');
  if (k > n) throw new Error('Threshold must be <= shares');
  if (n > 255) throw new Error('Shares must be <= 255');

  const secretLen    = secretBuf.length;
  const randomCoeffs = nodeRandomBytes(secretLen * (k - 1));

  const coefficients = new Array(secretLen);
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    const poly = new Array(k);
    poly[0] = secretBuf[byteIdx];
    for (let t = 1; t < k; t++) {
      poly[t] = randomCoeffs[(k - 1) * byteIdx + (t - 1)];
    }
    coefficients[byteIdx] = poly;
  }

  const result = new Array(n);
  for (let shareIdx = 0; shareIdx < n; shareIdx++) {
    const x = shareIdx + 1;
    const shareBuf = Buffer.allocUnsafe(1 + secretLen);
    shareBuf[0] = x;
    for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
      shareBuf[1 + byteIdx] = polyEval(coefficients[byteIdx], x);
    }
    result[shareIdx] = shareBuf;
  }

  return result;
}

/**
 * shamirCombine(shares)
 *
 * Reconstructs the secret from k or more shares via Lagrange interpolation
 * over GF(256). `shares` may be Buffers or hex strings.
 *
 * @param {Array<Buffer|string>} shares
 * @returns {string} reconstructed secret as UTF-8 string
 */
function shamirCombine(shares) {
  if (!shares || shares.length === 0) throw new Error('Must provide at least one share');

  const bufs = shares.map(s => Buffer.isBuffer(s) ? s : Buffer.from(s, 'hex'));

  const shareLen = bufs[0].length;
  if (shareLen < 2) throw new Error('Each share must be at least 2 bytes');
  for (const s of bufs) {
    if (s.length !== shareLen) throw new Error('All shares must have the same length');
  }

  const secretLen = shareLen - 1;
  const xs = bufs.map(s => s[0]);

  const seen = new Set();
  for (const x of xs) {
    if (x === 0) throw new Error('Share index 0 is reserved');
    if (seen.has(x)) throw new Error(`Duplicate share index ${x}`);
    seen.add(x);
  }

  const secret = Buffer.allocUnsafe(secretLen);

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    const ys = bufs.map(s => s[1 + byteIdx]);
    let value = 0;
    for (let i = 0; i < xs.length; i++) {
      let numerator   = 1;
      let denominator = 1;
      for (let j = 0; j < xs.length; j++) {
        if (i === j) continue;
        numerator   = gfMul(numerator,   xs[j]);
        denominator = gfMul(denominator, gfAdd(xs[i], xs[j]));
      }
      const lagrangeBasis = gfMul(numerator, gfInverse(denominator));
      value = gfAdd(value, gfMul(ys[i], lagrangeBasis));
    }
    secret[byteIdx] = value;
  }

  return secret.toString('utf8');
}

// ════════════════════════════════════════════════════════════
// Exports
// ════════════════════════════════════════════════════════════

module.exports = {
  // VDF
  vdfCompute,
  vdfVerify,
  // MMR
  mmrAppend,
  mmrProve,
  mmrVerify,
  // Shamir
  shamirSplit,
  shamirCombine
};
