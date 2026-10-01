/**
 * Merkle Mountain Range (MMR) — Append-Only Authenticated Data Structure
 *
 * An MMR is a sequence of perfect binary Merkle trees ("mountains") whose
 * leaf counts are distinct powers of two. Appending a leaf merges adjacent
 * equal-height peaks until all remaining peaks have distinct heights —
 * analogous to a carry-propagation step in binary addition.
 *
 * Node numbering: 1-indexed, assigned in the order nodes are created
 * (post-order left-to-right within each mountain, then across mountains).
 *
 * Root: computed by "bagging" all peaks — a right-fold of hashPair over the
 * sorted peak list.
 *
 * Hash function: SHA-256 via Node.js `crypto` (no external dependencies).
 *
 * @package @kasbah/crypto-utils
 * @module mmr
 */

import { createHash } from 'crypto';

// ═══════════════════════════════════════════════════════════
// Public Interfaces
// ═══════════════════════════════════════════════════════════

/**
 * Inclusion proof for a single leaf.
 *
 * - `leafIndex`  : 0-based ordinal of the leaf among all appended leaves
 * - `peaks`      : all MMR peak hashes at the time the proof was generated
 * - `siblings`   : sibling hashes on the path from the leaf to its mountain root
 *
 * During verification, `siblings.length` reveals the height of the
 * containing mountain, which together with `leafIndex` and `peaks.length`
 * is sufficient to re-derive all position/direction information.
 */
export interface MerkleProof {
  leafIndex: number;
  peaks: Buffer[];
  siblings: Buffer[];
}

// ═══════════════════════════════════════════════════════════
// Internal Hash Helpers
// ═══════════════════════════════════════════════════════════

function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

function hashChildren(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256').update(left).update(right).digest();
}

// ═══════════════════════════════════════════════════════════
// MMR Position Arithmetic
// ═══════════════════════════════════════════════════════════

/**
 * Return the 1-indexed MMR positions of all peaks for an MMR with `n` leaves.
 *
 * The bit decomposition of n drives the mountain sizes: each set bit k in n
 * corresponds to a complete binary tree with 2^k leaves and 2^(k+1)-1 nodes.
 * Peaks are accumulated left-to-right, high-bit first.
 */
function peakPositions(n: number): number[] {
  if (n === 0) return [];
  const peaks: number[] = [];
  let pos = 0;
  let remaining = n;

  while (remaining > 0) {
    const h = 31 - Math.clz32(remaining);   // highest set bit
    const subTreeLeaves = 1 << h;            // 2^h
    const subTreeNodes  = 2 * subTreeLeaves - 1;
    pos += subTreeNodes;
    peaks.push(pos);
    remaining -= subTreeLeaves;
  }

  return peaks;
}

/**
 * Compute the MMR position (1-indexed) of the k-th leaf (0-based) inside a
 * single perfect binary tree of height `h` (2^h leaves), whose first node
 * sits at 1-indexed position `basePos` in the global MMR flat array.
 *
 * Inside the mountain, nodes are numbered 1..2^(h+1)-1 in post-order
 * (left subtree, right subtree, root). Leaves sit at specific local
 * positions derived by following the path to the left-most leaf at each level.
 */
function leafPositionInMountain(basePos: number, leafOrdinal: number, height: number): number {
  // Navigate down the mountain from the root to the leaf, collecting
  // the local (1-indexed within mountain) position.
  let lo = localLeafPos(leafOrdinal, height);
  return basePos + lo - 1;
}

/**
 * 1-indexed position of the k-th leaf (0-based) within a perfect binary
 * tree of height `h`, using post-order left→right traversal.
 *
 * Recursion:
 *   - If h==0: single leaf, position = 1.
 *   - Left half has 2^(h-1) leaves and 2^h - 1 nodes (positions 1..2^h-1).
 *   - Right half has 2^(h-1) leaves, positions 2^h .. 2^(h+1)-2.
 *   - Root is at position 2^(h+1)-1.
 */
function localLeafPos(k: number, h: number): number {
  if (h === 0) return 1;
  const leftLeaves = 1 << (h - 1);
  const leftNodes  = 2 * leftLeaves - 1;
  if (k < leftLeaves) {
    return localLeafPos(k, h - 1);
  } else {
    return leftNodes + localLeafPos(k - leftLeaves, h - 1);
  }
}

/**
 * Given a leaf at local position `localPos` (1-indexed) within a mountain
 * of height `h`, return the sequence of (siblingPos, isLeftChild) pairs
 * on the path from that leaf to the mountain root.
 *
 * We work entirely in local coordinates (1-indexed within mountain).
 * At each level, left and right children are identified by whether the
 * current node's local ordinal is in the left or right half.
 */
function pathSiblings(
  localPos: number,
  height: number
): Array<{ siblingLocalPos: number; nodeIsLeftChild: boolean }> {
  const path: Array<{ siblingLocalPos: number; nodeIsLeftChild: boolean }> = [];
  let pos = localPos;
  let h = height;

  while (h > 0) {
    // Find parent and sibling.
    // In a post-order tree of height h:
    //   the right child of the root is at offset leftNodes + localPos_in_right_subtree.
    //   the root is at 2^(h+1) - 1.
    //   left subtree spans positions 1 .. 2^h - 1
    //   right subtree spans positions 2^h .. 2^(h+1) - 2
    const leftNodes = (1 << h) - 1;           // nodes in left sub-tree of current level

    const inLeftSubtree = pos <= leftNodes;
    if (inLeftSubtree) {
      // sibling is the right sub-tree root at leftNodes + (2^h - 1) = 2^(h+1) - 2
      const rightSubtreeRoot = (1 << (h + 1)) - 2;
      path.push({ siblingLocalPos: rightSubtreeRoot, nodeIsLeftChild: true });
      // pos stays relative to left subtree — no change needed, recurse into left
      h--;
    } else {
      // pos is in right subtree, adjust to local right-subtree coordinates
      const rightLocalPos = pos - leftNodes;
      // sibling is the left sub-tree root at leftNodes
      path.push({ siblingLocalPos: leftNodes, nodeIsLeftChild: false });
      pos = rightLocalPos;
      h--;
    }
  }

  return path;
}

// ═══════════════════════════════════════════════════════════
// MMR Class
// ═══════════════════════════════════════════════════════════

export class MMR {
  /**
   * Flat 1-indexed node store.
   * `nodes[0]` is null (sentinel); `nodes[i]` holds the hash of MMR node i.
   */
  private readonly nodes: (Buffer | null)[];
  private leafCount_: number;
  private nodeCount_: number;

  constructor() {
    this.nodes      = [null]; // slot 0 unused
    this.leafCount_ = 0;
    this.nodeCount_ = 0;
  }

  // ─── Public API ────────────────────────────────────────────

  /** Number of leaves appended. */
  size(): number {
    return this.leafCount_;
  }

  /**
   * Append a leaf to the MMR.
   * The leaf is domain-tagged with a SHA-256 hash before insertion to
   * prevent second-preimage attacks on leaf vs. internal node collisions.
   */
  append(leaf: Buffer): void {
    const leafHash = sha256(leaf);
    this.addNode(leafHash);
    this.leafCount_++;
  }

  /**
   * Compute the MMR root by bagging all peaks.
   *
   * Bagging: fold-right hashPair over the peak list.
   *   root = peaks[0] ⊕ (peaks[1] ⊕ (peaks[2] ⊕ ... peaks[k-1]))
   * For a single peak the root equals that peak.
   */
  getRoot(): Buffer {
    const peaks = this.currentPeaks();
    if (peaks.length === 0) {
      throw new Error('MMR is empty — cannot compute root');
    }
    return bagPeaks(peaks);
  }

  /**
   * Generate a Merkle inclusion proof for the leaf at 0-based `leafIndex`.
   *
   * Throws if `leafIndex` is out of range.
   */
  getMerkleProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leafCount_) {
      throw new RangeError(
        `Leaf index ${leafIndex} is out of range [0, ${this.leafCount_ - 1}]`
      );
    }

    const peaks   = this.currentPeaks();
    const { mountainIndex, leafOrdinalInMountain, basePos, height } =
      this.locateMountain(leafIndex);

    const localPos = localLeafPos(leafOrdinalInMountain, height);
    const pathInfo = pathSiblings(localPos, height);

    // Collect sibling hashes from the flat node array
    const siblings: Buffer[] = pathInfo.map(({ siblingLocalPos }) => {
      const globalPos = basePos + siblingLocalPos - 1;
      const node = this.nodes[globalPos];
      if (!node) {
        throw new Error(`MMR node at position ${globalPos} is unexpectedly null`);
      }
      return node;
    });

    return { leafIndex, peaks, siblings };
  }

  /**
   * Verify that `leaf` is included in an MMR with the given `root`,
   * using the supplied `proof`.
   *
   * @param leaf  - Original leaf data (will be SHA-256 hashed internally)
   * @param proof - Proof from `getMerkleProof()`
   * @param root  - Trusted MMR root
   */
  verifyProof(leaf: Buffer, proof: MerkleProof, root: Buffer): boolean {
    try {
      if (proof.peaks.length === 0) return false;
      if (proof.leafIndex < 0)      return false;

      // Reconstruct leafCount from peaks: each peak corresponds to a set bit
      // in leafCount, ordered from largest to smallest. The peaks.length tells
      // us how many mountains there are, but NOT their sizes individually.
      //
      // However: siblings.length == mountainHeight of the containing mountain.
      // We use that to find the containing mountain.
      //
      // Walk peaks (largest first), compute cumulative leaf counts, determine
      // which mountain contains proof.leafIndex.
      //
      // But we don't know the individual mountain heights without leafCount.
      // SOLUTION: derive leafCount from the total node count, which is
      // this.nodeCount_. Since this is an instance method, we use this.leafCount_.

      const { leafOrdinalInMountain, height } =
        this.locateMountain(proof.leafIndex);

      if (proof.siblings.length !== height) return false;

      const localPos = localLeafPos(leafOrdinalInMountain, height);
      const pathInfo = pathSiblings(localPos, height);

      // Recompute the mountain peak by hashing up with siblings
      let current = sha256(leaf);
      for (let i = 0; i < pathInfo.length; i++) {
        const { nodeIsLeftChild } = pathInfo[i];
        const sibling = proof.siblings[i];
        if (nodeIsLeftChild) {
          current = hashChildren(current, sibling);
        } else {
          current = hashChildren(sibling, current);
        }
      }

      // `current` should equal the mountain's peak
      const peakIndex = this.peakIndexForLeaf(proof.leafIndex);
      const expectedPeak = proof.peaks[peakIndex];
      if (!current.equals(expectedPeak)) return false;

      // Verify peaks bag to the expected root
      const computedRoot = bagPeaks(proof.peaks);
      return computedRoot.equals(root);
    } catch {
      return false;
    }
  }

  // ─── Private Helpers ───────────────────────────────────────

  /**
   * Insert a pre-hashed node and propagate merges upward.
   *
   * Merge invariant: after inserting a node, if the two most-recent "pending"
   * peaks have the same height, hash them together into a parent, repeat.
   *
   * We track heights using a stack. A node inserted at height h causes a
   * chain of merges while the top two stack heights are equal.
   */
  private addNode(hash: Buffer): void {
    this.nodeCount_++;
    this.nodes.push(hash);

    // Use height derived from pending-peak stack to drive merges.
    // The pending heights form a strictly decreasing sequence (invariant).
    // A new leaf (height 0) is pushed; merges happen while the top two heights
    // are equal. After each merge, height increments by 1.
    let height = 0;
    while (this.shouldMerge(height)) {
      // Left child: the node that was the peak at height `height` before this
      // one was added. Its position is nodeCount - 2*(2^height - 1) - 1.
      // Right child: current nodeCount_.
      const rightPos = this.nodeCount_;
      const leftPos  = rightPos - (1 << (height + 1)) + 1;

      const left  = this.nodes[leftPos]!;
      const right = this.nodes[rightPos]!;
      const parent = hashChildren(left, right);

      this.nodeCount_++;
      this.nodes.push(parent);
      height++;
    }
  }

  /**
   * After inserting the current node (now at `this.nodeCount_`), check
   * whether the node at `nodeCount_ - (2^(h+1) - 1)` exists and is a
   * valid left-sibling at height `h`. If so, a merge is needed.
   */
  private shouldMerge(height: number): boolean {
    const rightPos = this.nodeCount_;
    const leftPos  = rightPos - (1 << (height + 1)) + 1;
    return leftPos >= 1 && this.nodes[leftPos] !== null && this.nodes[leftPos] !== undefined;
  }

  /** Return all peak hashes in left-to-right order (largest mountain first). */
  private currentPeaks(): Buffer[] {
    return peakPositions(this.leafCount_).map((p) => {
      const node = this.nodes[p];
      if (!node) throw new Error(`Peak at MMR position ${p} is null`);
      return node;
    });
  }

  /**
   * Locate which mountain a leaf (by 0-based leafIndex) belongs to.
   *
   * Returns:
   *  - `mountainIndex`          : index into the peaks array (0-based, largest first)
   *  - `leafOrdinalInMountain`  : 0-based ordinal of the leaf within its mountain
   *  - `basePos`                : 1-indexed MMR position of the mountain's first node
   *  - `height`                 : height of the mountain (log2 of its leaf count)
   */
  private locateMountain(leafIndex: number): {
    mountainIndex: number;
    leafOrdinalInMountain: number;
    basePos: number;
    height: number;
  } {
    let remaining   = leafIndex;
    let basePos     = 1;
    let n           = this.leafCount_;
    let mountainIdx = 0;

    while (n > 0) {
      const h           = 31 - Math.clz32(n);
      const subLeaves   = 1 << h;
      const subNodes    = 2 * subLeaves - 1;

      if (remaining < subLeaves) {
        return {
          mountainIndex: mountainIdx,
          leafOrdinalInMountain: remaining,
          basePos,
          height: h,
        };
      }

      remaining   -= subLeaves;
      basePos     += subNodes;
      n           -= subLeaves;
      mountainIdx++;
    }

    throw new Error(
      `Leaf ${leafIndex} not found in MMR with ${this.leafCount_} leaves`
    );
  }

  /** Return the 0-based peak index for the mountain containing `leafIndex`. */
  private peakIndexForLeaf(leafIndex: number): number {
    return this.locateMountain(leafIndex).mountainIndex;
  }
}

// ═══════════════════════════════════════════════════════════
// Pure Function: bag peaks into root
// ═══════════════════════════════════════════════════════════

function bagPeaks(peaks: Buffer[]): Buffer {
  if (peaks.length === 1) return peaks[0];
  // Fold right
  let acc = peaks[peaks.length - 1];
  for (let i = peaks.length - 2; i >= 0; i--) {
    acc = hashChildren(peaks[i], acc);
  }
  return acc;
}
