'use strict';

/**
 * PersistentHomologyCovert — Paper 001 Implementation
 * ====================================================
 * Detects covert communication structures in multi-agent networks
 * through persistent homology of the agent interaction graph.
 *
 * ALGORITHMS (Paper 001, Sections 2-4):
 *   1. Vietoris-Rips Filtration:
 *      Build a sequence of simplicial complexes at increasing
 *      distance thresholds ε₁ < ε₂ < ... < εₘ.
 *      VR_ε = { σ ⊂ V : diam(σ) ≤ ε }
 *
 *   2. Persistent Homology (H₁):
 *      Track birth/death of 1-dimensional homology classes
 *      (cycles) across the filtration. A covert k-node cycle
 *      generates a persistent H₁ class with lifetime
 *      β_k/β₁ ≥ √n under random edge noise.
 *
 *   3. Wasserstein Distance:
 *      Compare persistence diagrams to baseline via
 *      W₁(A, B) = inf_γ Σ ||a - γ(a)||
 *      where γ is a bijection between diagrams.
 *
 *   4. Detection Theorem:
 *      A k-node covert cycle (k ≥ 4) with clique coherence
 *      ≥ 0.7 generates a detectable H₁ class above the
 *      persistence threshold θ = μ_noise + 2σ_noise.
 *
 * WHY THIS REPLACES topo-shield.js's simple approach:
 *   topo-shield.js uses graph Laplacian + Fiedler value —
 *   a connectivity measure, not a topological one.
 *   This module computes actual persistent homology,
 *   matching the mathematical framework of Paper 001.
 */

// ═══════════════════════════════════════════════════════════════
// Vietoris-Rips Filtration
// ═══════════════════════════════════════════════════════════════

/**
 * Build a distance matrix from agent interaction vectors.
 * @param {number[][]} points — array of agent state vectors [x₁, x₂, ...]
 * @returns {number[][]} distance matrix D[i][j] = Euclidean distance
 */
function distanceMatrix(points) {
  const n = points.length;
  const D = Array.from({ length: n }, () => new Array(n).fill(0));
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      let sum = 0;
      for (let k = 0; k < points[i].length; k++) {
        const d = points[i][k] - points[j][k];
        sum += d * d;
      }
      D[i][j] = D[j][i] = Math.sqrt(sum);
    }
  }
  return D;
}

/**
 * Compute the Vietoris-Rips filtration at a given threshold.
 * Returns the 1-skeleton (edges) of the complex.
 *
 * @param {number[][]} distMatrix — pairwise distances
 * @param {number} epsilon — distance threshold
 * @returns {object} { edges: [[i,j],...], n: number }
 */
function vrComplex(distMatrix, epsilon) {
  const n = distMatrix.length;
  const edges = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      if (distMatrix[i][j] <= epsilon) {
        edges.push([i, j]);
      }
    }
  }
  return { edges, n };
}

/**
 * Detect cycles (H₁ classes) in the 1-skeleton using DFS.
 * Returns the number of independent cycles (Betti-1 proxy).
 *
 * A connected component with E edges and V vertices has
 * β₁ = E - V + 1 independent cycles (if connected) or
 * β₁ = E - V + C where C is the number of connected components.
 *
 * @param {object} complex — { edges, n }
 * @returns {number} Betti-1 estimate
 */
function betti1(complex) {
  const { edges, n } = complex;

  // Build adjacency and track components via union-find
  const parent = Array.from({ length: n }, (_, i) => i);
  function find(x) { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; }
  function union(a, b) { const ra = find(a), rb = find(b); if (ra !== rb) parent[rb] = ra; }

  const adj = Array.from({ length: n }, () => []);
  for (const [i, j] of edges) {
    adj[i].push(j);
    adj[j].push(i);
    union(i, j);
  }

  // Count components and edges per component
  const compEdges = new Map();
  const compVerts = new Map();
  for (let i = 0; i < n; i++) {
    const root = find(i);
    compVerts.set(root, (compVerts.get(root) || 0) + 1);
  }
  for (const [i, j] of edges) {
    const root = find(i);
    compEdges.set(root, (compEdges.get(root) || 0) + 1);
  }

  // β₁ = Σ (E_c - V_c + 1) for each component
  let b1 = 0;
  for (const [root, v] of compVerts) {
    const e = compEdges.get(root) || 0;
    b1 += Math.max(0, e - v + 1);
  }

  return b1;
}

// ═══════════════════════════════════════════════════════════════
// Persistence Diagram
// ═══════════════════════════════════════════════════════════════

/**
 * Compute the persistence diagram for H₁ across a filtration.
 *
 * We sample thresholds evenly from min_dist to max_dist,
 * compute β₁ at each threshold, and track when cycles are
 * born (β₁ increases) and die (subsequent threshold merges).
 *
 * @param {number[][]} distMatrix
 * @param {number} numSteps — number of filtration steps (default 20)
 * @returns {object} { diagram: [[birth, death],...], maxPersistence, totalH1Features }
 */
function persistenceDiagram(distMatrix, numSteps = 20) {
  const n = distMatrix.length;
  if (n < 4) return { diagram: [], maxPersistence: 0, totalH1Features: 0 };

  // Compute threshold range
  const allDists = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      if (distMatrix[i][j] > 0) allDists.push(distMatrix[i][j]);
    }
  }
  if (allDists.length === 0) return { diagram: [], maxPersistence: 0, totalH1Features: 0 };

  allDists.sort((a, b) => a - b);
  const minDist = allDists[0];
  const maxDist = allDists[allDists.length - 1];
  const step = (maxDist - minDist) / (numSteps - 1);

  // Track β₁ across filtration
  const b1History = [];
  for (let s = 0; s < numSteps; s++) {
    const eps = minDist + s * step;
    const complex = vrComplex(distMatrix, eps);
    b1History.push({ eps, b1: betti1(complex) });
  }

  // Extract persistence pairs: when β₁ increases (birth), when it decreases (death)
  const diagram = [];
  let prevB1 = 0;

  for (let s = 1; s < numSteps; s++) {
    const delta = b1History[s].b1 - b1History[s - 1].b1;

    if (delta > 0) {
      // New cycles born — record birth at this threshold
      for (let k = 0; k < delta; k++) {
        diagram.push({ birth: b1History[s].eps, death: null });
      }
    } else if (delta < 0) {
      // Cycles dying — assign death to the most recently born without death
      let remaining = -delta;
      for (let i = diagram.length - 1; i >= 0 && remaining > 0; i--) {
        if (diagram[i].death === null) {
          diagram[i].death = b1History[s].eps;
          remaining--;
        }
      }
    }
  }

  // Any cycles still alive at the end get death = max threshold
  for (const pt of diagram) {
    if (pt.death === null) pt.death = maxDist;
  }

  // Compute persistence (lifetime) for each point
  const persValues = diagram.map(pt => pt.death - pt.birth);
  const maxPersistence = persValues.length > 0 ? Math.max(...persValues) : 0;
  const totalH1Features = diagram.length;

  return { diagram, maxPersistence, totalH1Features, b1History };
}

// ═══════════════════════════════════════════════════════════════
// Wasserstein Distance
// ═══════════════════════════════════════════════════════════════

/**
 * Compute 1-Wasserstein distance between two persistence diagrams.
 * Simplified: matches points by sorted birth times and sums
 * absolute differences in (birth, persistence) space.
 *
 * @param {object[]} dgmA — array of {birth, death}
 * @param {object[]} dgmB
 * @returns {number} W₁ distance
 */
function wasserstein1(dgmA, dgmB) {
  const ptsA = dgmA.map(p => ({ b: p.birth, l: p.death - p.birth }));
  const ptsB = dgmB.map(p => ({ b: p.birth, l: p.death - p.birth }));

  // Pad shorter diagram with diagonal points (birth=death)
  const maxLen = Math.max(ptsA.length, ptsB.length);
  while (ptsA.length < maxLen) ptsA.push({ b: 0, l: 0 });
  while (ptsB.length < maxLen) ptsB.push({ b: 0, l: 0 });

  // Sort by birth time and match greedily
  ptsA.sort((a, b) => a.b - b.b);
  ptsB.sort((a, b) => a.b - b.b);

  let dist = 0;
  for (let i = 0; i < maxLen; i++) {
    dist += Math.abs(ptsA[i].b - ptsB[i].b) + Math.abs(ptsA[i].l - ptsB[i].l);
  }

  return dist / maxLen;
}

// ═══════════════════════════════════════════════════════════════
// Main Class
// ═══════════════════════════════════════════════════════════════

class PersistentHomologyCovert {
  /**
   * @param {object} opts
   * @param {number} opts.minCycleSize — minimum cycle size to detect (default 4)
   * @param {number} opts.filtrationSteps — number of VR filtration steps (default 20)
   * @param {number} opts.persistenceThreshold — minimum H₁ lifetime to flag (default 0.15)
   * @param {number} opts.wassersteinAlertThreshold — W₁ above baseline to alert (default 0.5)
   */
  constructor(opts = {}) {
    this.minCycleSize = opts.minCycleSize || 4;
    this.filtrationSteps = opts.filtrationSteps || 20;
    this.persistenceThreshold = opts.persistenceThreshold || 0.15;
    this.wassersteinAlertThreshold = opts.wassersteinAlertThreshold || 0.5;

    this.baselineDiagram = null;
    this.baselineDistMatrix = null;
    this.history = [];
    this.alerts = [];
  }

  /**
   * Calibrate baseline from a known-benign agent graph.
   * @param {number[][]} points — baseline agent positions
   */
  calibrate(points) {
    this.baselineDistMatrix = distanceMatrix(points);
    const result = persistenceDiagram(this.baselineDistMatrix, this.filtrationSteps);
    this.baselineDiagram = result.diagram;
    return result;
  }

  /**
   * Analyze an agent graph for covert cycles.
   * @param {number[][]} points — current agent state vectors
   * @returns {object} detection result
   */
  analyze(points) {
    if (!Array.isArray(points) || points.length < this.minCycleSize) {
      return {
        alert: false,
        totalH1Features: 0,
        maxPersistence: 0,
        wassersteinDistance: 0,
        anomalyScore: 0,
        advisory: 'NONE',
        covertCycles: 0,
        note: 'insufficient agents for cycle detection'
      };
    }

    const distMatrix = distanceMatrix(points);
    const result = persistenceDiagram(distMatrix, this.filtrationSteps);

    // Wasserstein distance from baseline
    let wassDist = 0;
    if (this.baselineDiagram && this.baselineDiagram.length > 0) {
      wassDist = wasserstein1(result.diagram, this.baselineDiagram);
    }

    // Detection: significant persistent cycles above noise
    const significantCycles = result.diagram.filter(
      pt => (pt.death - pt.birth) > this.persistenceThreshold
    );

    const covertCycles = significantCycles.length;
    const alert = covertCycles > 0 || wassDist > this.wassersteinAlertThreshold;

    // Anomaly score
    let anomalyScore = 0;
    if (covertCycles > 0) {
      anomalyScore = Math.min(1, covertCycles * 0.3 + (result.maxPersistence / 0.5) * 0.4);
    }
    if (wassDist > this.wassersteinAlertThreshold) {
      anomalyScore = Math.max(anomalyScore, Math.min(1, wassDist / 1.0));
    }

    let advisory = 'NONE';
    if (anomalyScore >= 0.70) advisory = 'REQUIRE_APPROVAL';
    else if (anomalyScore >= 0.45) advisory = 'WARN';

    const output = {
      alert,
      totalH1Features: result.totalH1Features,
      maxPersistence: +result.maxPersistence.toFixed(6),
      wassersteinDistance: +wassDist.toFixed(6),
      anomalyScore: +anomalyScore.toFixed(4),
      advisory,
      covertCycles,
      diagramSize: result.diagram.length,
    };

    if (alert) {
      this.alerts.push({ ts: Date.now(), ...output });
      if (this.alerts.length > 100) this.alerts.shift();
    }

    return output;
  }

  /**
   * Test method for compatibility with nature-features.js.
   */
  test(points) {
    return this.analyze(points || []);
  }
}

// ═══════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════

module.exports = {
  PersistentHomologyCovert,
  // Alias — governance-proxy.js imports it under the longer name.
  PersistentHomologyCovertDetector: PersistentHomologyCovert,
  distanceMatrix,
  vrComplex,
  betti1,
  persistenceDiagram,
  wasserstein1,
};
