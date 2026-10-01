/**
 * TopoShield — Persistent Homology for Agent Topology Fingerprinting
 *
 * Uses Topological Data Analysis (TDA) to detect multi-agent collusion
 * through structural changes in the agent communication manifold.
 *
 * While SwarmCollusionDetector uses flat correlation (>0.85 threshold),
 * TopoShield detects "holes" in agent interaction topology — structural
 * voids that indicate covert coordination channels invisible to
 * correlation-based detectors.
 *
 * No security tool uses persistent homology for agent security.
 * This is a pure JS implementation of Vietoris-Rips persistence.
 */

'use strict';

/**
 * Compute Euclidean distance between two vectors.
 */
function euclidean(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

/**
 * Compute pairwise distance matrix for a point cloud.
 */
function distanceMatrix(points) {
  const n = points.length;
  const D = Array.from({ length: n }, () => new Float64Array(n));
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const d = euclidean(points[i], points[j]);
      D[i][j] = d;
      D[j][i] = d;
    }
  }
  return D;
}

/**
 * Union-Find (Disjoint Set) for connected components.
 */
class UnionFind {
  constructor(n) {
    this.parent = Array.from({ length: n }, (_, i) => i);
    this.rank = new Uint8Array(n);
    this.components = n;
  }

  find(x) {
    while (this.parent[x] !== x) {
      this.parent[x] = this.parent[this.parent[x]]; // path compression
      x = this.parent[x];
    }
    return x;
  }

  union(x, y) {
    const rx = this.find(x), ry = this.find(y);
    if (rx === ry) return false;
    if (this.rank[rx] < this.rank[ry]) { this.parent[rx] = ry; }
    else if (this.rank[rx] > this.rank[ry]) { this.parent[ry] = rx; }
    else { this.parent[ry] = rx; this.rank[rx]++; }
    this.components--;
    return true;
  }
}

/**
 * Compute 0-dimensional persistent homology (connected components)
 * using the Vietoris-Rips filtration.
 *
 * Returns persistence diagram: array of { birth, death } pairs.
 * Components that never die have death = Infinity.
 */
function persistence0(D, n) {
  // Collect all edges sorted by distance
  const edges = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      edges.push({ i, j, dist: D[i][j] });
    }
  }
  edges.sort((a, b) => a.dist - b.dist);

  const uf = new UnionFind(n);
  const birth = new Float64Array(n); // all born at 0
  const diagram = [];

  for (const edge of edges) {
    const ri = uf.find(edge.i), rj = uf.find(edge.j);
    if (ri !== rj) {
      // The younger component dies (higher birth time, but all birth=0 here)
      // Convention: the component with higher index dies
      const dying = Math.max(ri, rj);
      diagram.push({ birth: 0, death: edge.dist });
      uf.union(edge.i, edge.j);
    }
  }

  // The last surviving component has death = Infinity
  diagram.push({ birth: 0, death: Infinity });

  return diagram;
}

/**
 * Compute 1-dimensional persistent homology (loops/cycles)
 * using a simplified Vietoris-Rips approach.
 *
 * For each triple (i,j,k), the triangle "fills in" a 1-cycle
 * at radius = max(d(i,j), d(j,k), d(i,k)).
 * A 1-cycle is born when an edge completes a loop without filling a triangle.
 *
 * This is a simplified O(n³) approach suitable for small agent swarms (n < 50).
 */
function persistence1(D, n) {
  if (n < 3) return [];

  // Collect all edges sorted by distance
  const edges = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      edges.push({ i, j, dist: D[i][j] });
    }
  }
  edges.sort((a, b) => a.dist - b.dist);

  // Track which edges exist at each filtration step
  const edgeSet = new Set();
  const adjacency = Array.from({ length: n }, () => new Set());
  const diagram = [];

  for (const edge of edges) {
    const { i, j, dist } = edge;

    // Check if adding this edge creates a cycle (common neighbor exists)
    const commonNeighbors = [];
    for (const k of adjacency[i]) {
      if (adjacency[j].has(k)) {
        commonNeighbors.push(k);
      }
    }

    if (commonNeighbors.length === 0 && adjacency[i].size > 0 && adjacency[j].size > 0) {
      // Check if i and j are already connected via some path
      // If yes, this edge creates a genuine 1-cycle
      if (isConnected(adjacency, i, j, n)) {
        // 1-cycle born at this distance
        diagram.push({ birth: dist, death: Infinity }); // will be killed by triangles
      }
    }

    // If common neighbors exist, a triangle forms → kills the youngest 1-cycle
    if (commonNeighbors.length > 0 && diagram.length > 0) {
      // Find the youngest unkilled cycle and kill it
      for (let k = diagram.length - 1; k >= 0; k--) {
        if (diagram[k].death === Infinity) {
          diagram[k].death = dist;
          break;
        }
      }
    }

    edgeSet.add(`${i}-${j}`);
    adjacency[i].add(j);
    adjacency[j].add(i);
  }

  return diagram.filter(d => d.death - d.birth > 1e-10); // filter trivial
}

/**
 * BFS connectivity check.
 */
function isConnected(adjacency, start, end, n) {
  const visited = new Uint8Array(n);
  const queue = [start];
  visited[start] = 1;
  while (queue.length > 0) {
    const curr = queue.shift();
    if (curr === end) return true;
    for (const next of adjacency[curr]) {
      if (!visited[next]) {
        visited[next] = 1;
        queue.push(next);
      }
    }
  }
  return false;
}

/**
 * Compute Betti numbers from persistence diagrams at a given scale.
 */
function bettiNumbers(diagram0, diagram1, scale) {
  const beta0 = diagram0.filter(d => d.birth <= scale && d.death > scale).length;
  const beta1 = diagram1.filter(d => d.birth <= scale && d.death > scale).length;
  return { beta0, beta1 };
}

class TopoShield {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 30;
    this.changeThreshold = options.changeThreshold || 0.20; // 20% Betti change = alert
    this.scaleParameter = options.scaleParameter || null;   // auto-computed if null
    this.prevBetti = null;
    this.history = [];       // array of { timestamp, betti, diagram0, diagram1 }
    this.alerts = [];
  }

  /**
   * Analyze a set of agent interaction traces.
   * @param {number[][]} agentTraces — array of state vectors, one per agent
   *   Each vector represents the agent's recent behavior embedding.
   * @returns {object} topology analysis result
   */
  analyze(agentTraces) {
    const start = Date.now();
    const n = agentTraces.length;

    if (n < 2) {
      return { alert: false, reason: 'too_few_agents', agents: n };
    }

    // Compute pairwise distances
    const D = distanceMatrix(agentTraces);

    // Auto-compute scale as median pairwise distance
    const allDists = [];
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        allDists.push(D[i][j]);
      }
    }
    allDists.sort((a, b) => a - b);
    const scale = this.scaleParameter || allDists[Math.floor(allDists.length / 2)];

    // Compute persistent homology
    const diagram0 = persistence0(D, n);
    const diagram1 = persistence1(D, n);

    // Extract Betti numbers at chosen scale
    const betti = bettiNumbers(diagram0, diagram1, scale);

    // Compare with previous topology
    let topologyChanged = false;
    let bettiChange = { beta0: 0, beta1: 0 };

    if (this.prevBetti) {
      const db0 = Math.abs(betti.beta0 - this.prevBetti.beta0);
      const db1 = Math.abs(betti.beta1 - this.prevBetti.beta1);
      const maxPrev = Math.max(this.prevBetti.beta0, this.prevBetti.beta1, 1);

      bettiChange = {
        beta0: db0,
        beta1: db1,
        relativeChange: Math.max(db0, db1) / maxPrev,
      };

      topologyChanged = bettiChange.relativeChange > this.changeThreshold;
    }

    this.prevBetti = { ...betti };

    // Persistence statistics
    const persistences0 = diagram0
      .filter(d => isFinite(d.death))
      .map(d => d.death - d.birth);
    const persistences1 = diagram1
      .filter(d => isFinite(d.death))
      .map(d => d.death - d.birth);

    const maxPersistence1 = persistences1.length > 0
      ? Math.max(...persistences1) : 0;

    // A large 1-cycle persistence = stable covert communication loop
    const covertChannelDetected = maxPersistence1 > scale * 0.5;

    const latencyMs = Date.now() - start;

    const result = {
      alert: topologyChanged || covertChannelDetected,
      topologyChanged,
      covertChannelDetected,
      betti,
      bettiChange,
      scale: +scale.toFixed(4),
      persistence: {
        dim0: persistences0.map(v => +v.toFixed(4)),
        dim1: persistences1.map(v => +v.toFixed(4)),
        maxPersistence1: +maxPersistence1.toFixed(4),
      },
      agents: n,
      latencyMs,
    };

    if (result.alert) {
      this.alerts.push({ ...result, timestamp: Date.now() });
    }

    this.history.push({
      timestamp: Date.now(),
      betti,
      agents: n,
    });
    if (this.history.length > this.windowSize) {
      this.history.shift();
    }

    return result;
  }

  /**
   * Get alert history.
   */
  getAlerts() {
    return this.alerts;
  }

  /**
   * Reset state.
   */
  reset() {
    this.prevBetti = null;
    this.history = [];
    this.alerts = [];
  }
}

module.exports = { TopoShield, persistence0, persistence1, bettiNumbers, distanceMatrix };
