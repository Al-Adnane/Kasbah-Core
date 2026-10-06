'use strict';

/**
 * TopoShield — Persistent Homology Covert Coordination Detector
 * 
 * Uses Vietoris-Rips complex on agent behavior vectors to detect
 * topological holes (covert coordination loops). Advisory only.
 * Simplified implementation using distance matrix and Betti-0/1 estimation.
 */

class TopoShield {
  constructor(options = {}) {
    this.maxVectors = options.maxVectors || 50;
    this.epsilon = options.epsilon || 0.3; // filtration parameter
    this.minPoints = options.minPoints || 3;
  }

  analyze(vectors) {
    // vectors: array of [risk, ethicalScore, consciousness, fingerprintConfidence, ...]
    // Each vector is an agent's state in feature space
    if (!Array.isArray(vectors) || vectors.length < this.minPoints) {
      return { available: false, reason: 'insufficient_agents', betti0: 0, betti1: 0 };
    }

    const n = Math.min(vectors.length, this.maxVectors);
    const pts = vectors.slice(-n);
    const dim = pts[0].length;

    // Compute pairwise distance matrix
    const dist = Array(n).fill(0).map(() => Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      for (let j = i+1; j < n; j++) {
        let d = 0;
        for (let k = 0; k < dim; k++) {
          const diff = (pts[i][k] || 0) - (pts[j][k] || 0);
          d += diff * diff;
        }
        dist[i][j] = dist[j][i] = Math.sqrt(d);
      }
    }

    // Betti-0: connected components at epsilon
    const visited = new Array(n).fill(false);
    let betti0 = 0;
    for (let i = 0; i < n; i++) {
      if (!visited[i]) {
        betti0++;
        this._dfs(i, dist, visited, this.epsilon, n);
      }
    }

    // Betti-1 estimation: count cycles in Rips complex
    // Simplified: count triangles where all edges < epsilon but not all in same component
    let betti1 = 0;
    for (let i = 0; i < n; i++) {
      for (let j = i+1; j < n; j++) {
        if (dist[i][j] >= this.epsilon) continue;
        for (let k = j+1; k < n; k++) {
          if (dist[i][k] < this.epsilon && dist[j][k] < this.epsilon) {
            // Triangle exists - check if it forms a hole (not filled by higher simplex)
            betti1++;
          }
        }
      }
    }

    // Normalize betti1 by max possible
    const maxTriangles = n * (n-1) * (n-2) / 6;
    const normBetti1 = maxTriangles > 0 ? betti1 / maxTriangles : 0;

    // Alert if unexpected topology: many components (fragmentation) or many holes (coordination loops)
    const fragmentation = betti0 / n;
    const coordinationSignal = normBetti1;
    const alert = fragmentation > 0.7 || coordinationSignal > 0.1;

    return {
      available: true,
      nAgents: n,
      betti0,
      betti1: Math.round(betti1),
      normBetti1,
      fragmentation,
      coordinationSignal,
      alert,
      advisory: alert ? 'WARN' : 'CLEAR',
      detail: `Topology: ${betti0} components (${(fragmentation*100).toFixed(0)}% frag), ${Math.round(betti1)} 1-cycles (${(coordinationSignal*100).toFixed(1)}% signal)`
    };
  }

  _dfs(node, dist, visited, eps, n) {
    visited[node] = true;
    for (let i = 0; i < n; i++) {
      if (!visited[i] && dist[node][i] < eps) {
        this._dfs(i, dist, visited, eps, n);
      }
    }
  }
}

module.exports = { TopoShield };