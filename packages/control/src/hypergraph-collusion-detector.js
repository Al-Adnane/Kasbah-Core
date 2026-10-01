'use strict';

/**
 * Hypergraph Collusion Detector (HCD) — #21
 *
 * Core Insight: The existing Fiedler coherence analysis (advisory-analyzers.js)
 * detects pairwise agent coordination via the graph Laplacian's second
 * eigenvalue. But multi-agent collusion involving 3+ coordinating agents
 * requires HYPERGRAPH edges — a hyperedge connects all members of a
 * colluding group, and this higher-order structure is invisible to the
 * pairwise graph Laplacian.
 *
 * We construct the hypergraph H = (V, E) where:
 *   V = agents
 *   E = hyperedges (subsets of agents exhibiting coordinated behavior)
 *
 * The hypergraph Laplacian L_H generalizes the graph Laplacian:
 *
 *   L_H = D_v - H W D_e^{-1} H^T
 *
 * where H is the |V| × |E| incidence matrix, W = diag(w_e) are hyperedge
 * weights, D_v and D_e are vertex and edge degree matrices.
 *
 * The eigenvalue spectrum of L_H reveals higher-order community structure:
 *   - λ_1 = 0 (always, multiplicity = connected hypergraph components)
 *   - λ_2 (Fiedler eigenvalue) = algebraic connectivity
 *   - λ_3, λ_4, ... reveal multi-way community partitions
 *
 * A sudden drop in λ_2 or clustering of higher eigenvalues indicates
 * hypergraph communities forming — i.e., collusion groups crystallizing.
 *
 * The spectral gap ratio G = λ_{k+1} / λ_k (for the first significant gap)
 * serves as the collusion detector: G > 5 indicates a clean partition
 * of agents into colluding and non-colluding groups.
 *
 * Mathematical Guarantee:
 *   The hypergraph Laplacian generalizes the Chung normalized Laplacian
 *   to hypergraphs. Its eigenvalues are real and non-negative, and the
 *   spectral clustering guarantees are preserved via the Cheeger
 *   inequality for hypergraphs.
 *
 * Evasion Cost: Pairwise coordination can evade graph-based detection
 * by keeping pairwise correlation below threshold. But 3+ party collusion
 * creates irreducible higher-order structure in the hypergraph incidence
 * matrix — the hyperedge itself is the evidence. Adversary must ensure
 * no subset of size ≥3 exhibits correlated behavior, an exponentially
 * harder constraint (2^n subsets vs n² pairs).
 */

class HypergraphCollusionDetector {
  /**
   * @param {object} opts
   *   - maxAgents: maximum number of agents to track (default 32)
   *   - collusionWindow: window of events for hyperedge construction (default 50)
   *   - significanceLevel: correlation threshold for hyperedge creation (default 0.6)
   *   - spectralGapWarn: spectral gap ratio → WARN (default 3.0)
   *   - spectralGapReview: spectral gap ratio → REVIEW (default 5.0)
   *   - minHyperedgeSize: minimum agents for a hyperedge (default 3)
   */
  constructor(opts = {}) {
    this.maxAgents = opts.maxAgents || 32;
    this.collusionWindow = opts.collusionWindow || 50;
    this.significanceLevel = opts.significanceLevel || 0.6;
    this.spectralGapWarn = opts.spectralGapWarn || 3.0;
    this.spectralGapReview = opts.spectralGapReview || 5.0;
    this.minHyperedgeSize = opts.minHyperedgeSize || 3;

    // Agent registry: id → { name, eventCount, lastSeen }
    this._agents = {};
    this._agentIds = []; // ordered list for matrix indexing
    this._nextAgentId = 0;

    // Event buffer: [{ agentId, actionType, target, riskScore, ts }]
    this._eventBuffer = [];
    this._maxEventBuffer = this.collusionWindow * 5;

    // Hypergraph state
    this._hypergraph = {
      incidence: null,   // |V| × |E| matrix
      edgeWeights: null, // |E| array
      laplacian: null,   // |V| × |V| matrix
      eigenvalues: null, // sorted ascending
      spectralGap: 0,
      colludingGroups: [], // array of agent groups
    };

    this._isCalibrated = false;
    this._calibrationEvents = 0;
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Register an agent event for collusion tracking.
   * @param {string} agentId — unique agent identifier
   * @param {string} actionType — the action taken
   * @param {string} target — action target
   * @param {object} context — { riskScore, metadata }
   */
  recordEvent(agentId, actionType, target, context = {}) {
    const agentIdx = this._ensureAgent(agentId);

    this._eventBuffer.push({
      agentId,
      agentIdx,
      actionType: String(actionType || 'UNKNOWN'),
      target: String(target || 'none'),
      riskScore: typeof context.riskScore === 'number' ? context.riskScore : 0.5,
      ts: context.ts || Date.now(),
    });

    if (this._eventBuffer.length > this._maxEventBuffer) {
      this._eventBuffer = this._eventBuffer.slice(-this._maxEventBuffer);
    }

    this._agents[agentId].lastSeen = Date.now();
    this._agents[agentId].eventCount++;
    this._calibrationEvents++;
  }

  /**
   * Analyze hypergraph for collusion patterns.
   * @returns {object} collusion assessment
   */
  analyze() {
    const n = this._agentIds.length;
    if (n < this.minHyperedgeSize) {
      return {
        mode: 'insufficient_agents',
        agentCount: n,
        needed: this.minHyperedgeSize,
      };
    }

    if (this._eventBuffer.length < this.collusionWindow) {
      return {
        mode: 'calibrating',
        events: this._calibrationEvents,
        needed: this.collusionWindow,
      };
    }

    this._isCalibrated = true;

    // Step 1: Build hyperedges from correlated agent subsets
    const hyperedges = this._buildHyperedges();

    // Step 2: Construct hypergraph incidence matrix
    this._buildIncidenceMatrix(hyperedges, n);

    // Step 3: Build hypergraph Laplacian
    this._buildHypergraphLaplacian(n);

    // Step 4: Compute eigenvalues via power iteration
    const eigenvalues = this._computeEigenvalues(n);

    // Step 5: Detect spectral gaps
    const spectralAnalysis = this._analyzeSpectrum(eigenvalues, n);

    // Step 6: Extract colluding groups from spectral clustering
    const groups = this._extractGroups(spectralAnalysis, n);

    this._hypergraph.eigenvalues = eigenvalues;
    this._hypergraph.spectralGap = spectralAnalysis.maxGapRatio;
    this._hypergraph.colludingGroups = groups;

    const hasCollusion = spectralAnalysis.maxGapRatio > this.spectralGapWarn;
    const isCritical = spectralAnalysis.maxGapRatio > this.spectralGapReview;

    return {
      mode: 'monitoring',
      agentCount: n,
      hyperedgeCount: hyperedges.length,
      largestHyperedge: hyperedges.length > 0
        ? Math.max(...hyperedges.map(h => h.size)) : 0,
      eigenvalues: eigenvalues.slice(0, Math.min(8, n)).map(v => +v.toFixed(4)),
      spectralGapRatio: +spectralAnalysis.maxGapRatio.toFixed(4),
      spectralGapIndex: spectralAnalysis.gapIndex,
      algebraicConnectivity: n >= 2 ? +eigenvalues[1].toFixed(4) : 0,
      hasCollusion,
      isCritical,
      signal: isCritical ? 'REQUIRE_APPROVAL'
        : hasCollusion ? 'WARN' : 'CLEAR',
      colludingGroups: groups,
      eventCount: this._eventBuffer.length,
    };
  }

  /**
   * Get hypergraph state for external visualization.
   */
  getHypergraphState() {
    return {
      agents: Object.keys(this._agents).length,
      agentNames: this._agentIds,
      hyperedges: this._hypergraph.edgeWeights ? this._hypergraph.edgeWeights.length : 0,
      spectralGap: this._hypergraph.spectralGap,
      eigenvalues: this._hypergraph.eigenvalues
        ? Array.from(this._hypergraph.eigenvalues).map(v => +v.toFixed(4))
        : [],
      colludingGroups: this._hypergraph.colludingGroups || [],
    };
  }

  /**
   * Reset detector state.
   */
  reset() {
    this._agents = {};
    this._agentIds = [];
    this._nextAgentId = 0;
    this._eventBuffer = [];
    this._hypergraph = {
      incidence: null, edgeWeights: null, laplacian: null,
      eigenvalues: null, spectralGap: 0, colludingGroups: [],
    };
    this._isCalibrated = false;
    this._calibrationEvents = 0;
  }

  // ── Internal Methods ─────────────────────────────────────

  _ensureAgent(agentId) {
    const key = String(agentId);
    if (this._agents[key]) return this._agents[key].index;
    if (this._agentIds.length >= this.maxAgents) {
      // Evict least-recently-seen agent
      let oldest = null;
      let oldestTs = Infinity;
      for (const [id, a] of Object.entries(this._agents)) {
        if (a.lastSeen < oldestTs) {
          oldest = id;
          oldestTs = a.lastSeen;
        }
      }
      if (oldest) {
        const oldIdx = this._agents[oldest].index;
        delete this._agents[oldest];
        this._agentIds.splice(this._agentIds.indexOf(oldest), 1);
        // Re-index remaining agents
        for (const [id, a] of Object.entries(this._agents)) {
          if (a.index > oldIdx) a.index--;
        }
      }
    }
    const idx = this._agentIds.length;
    this._agents[key] = { name: key, index: idx, eventCount: 0, lastSeen: Date.now() };
    this._agentIds.push(key);
    this._nextAgentId = this._agentIds.length;
    return idx;
  }

  _buildHyperedges() {
    const recent = this._eventBuffer.slice(-this.collusionWindow);
    const agentEvents = {}; // agentIdx → [{ actionType, target, riskScore }]
    for (const ev of recent) {
      if (!agentEvents[ev.agentIdx]) agentEvents[ev.agentIdx] = [];
      agentEvents[ev.agentIdx].push(ev);
    }

    const hyperedges = []; // [{ agents: Set<idx>, weight: float }]

    // Strategy: detect subsets of agents with correlated action patterns
    const agentIndices = Object.keys(agentEvents)
      .map(Number)
      .filter(i => agentEvents[i].length >= 3);

    if (agentIndices.length < this.minHyperedgeSize) return hyperedges;

    // Compute pairwise action correlation
    const n = agentIndices.length;
    for (let size = this.minHyperedgeSize; size <= Math.min(n, 8); size++) {
      // Try all combinations of 'size' agents
      const combos = this._combinations(agentIndices, size);
      for (const combo of combos) {
        const correlation = this._groupCorrelation(combo, agentEvents);
        if (correlation > this.significanceLevel) {
          hyperedges.push({
            agents: new Set(combo),
            size,
            weight: correlation,
          });
        }
      }
    }

    // Deduplicate: keep highest-weight hyperedge for each agent set
    const seen = new Set();
    const unique = [];
    for (const he of hyperedges) {
      const key = [...he.agents].sort().join(',');
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(he);
    }
    return unique.sort((a, b) => b.weight - a.weight).slice(0, 50);
  }

  _groupCorrelation(agentIndices, agentEvents) {
    // Compute average pairwise correlation in action type + risk score
    const vectors = agentIndices.map(idx => {
      const events = agentEvents[idx] || [];
      // Feature: { actionType distribution, meanRiskScore, targetEntropy }
      const actions = {};
      let totalRisk = 0;
      const targets = new Set();
      for (const ev of events) {
        actions[ev.actionType] = (actions[ev.actionType] || 0) + 1;
        totalRisk += ev.riskScore;
        targets.add(ev.target);
      }
      const total = events.length || 1;
      const targetEntropy = targets.size / total;
      const meanRisk = totalRisk / total;
      return { actions, meanRisk, targetEntropy, total };
    });

    // Pairwise JS divergence of action distributions + risk score alignment
    let totalCorr = 0;
    let pairs = 0;
    for (let i = 0; i < vectors.length; i++) {
      for (let j = i + 1; j < vectors.length; j++) {
        const vi = vectors[i];
        const vj = vectors[j];
        // JS divergence of action distributions
        const allActions = new Set([...Object.keys(vi.actions), ...Object.keys(vj.actions)]);
        let js = 0;
        for (const a of allActions) {
          const p = (vi.actions[a] || 0) / vi.total;
          const q = (vj.actions[a] || 0) / vj.total;
          const m = (p + q) / 2;
          if (p > 0 && m > 0) js += 0.5 * p * Math.log2(p / m);
          if (q > 0 && m > 0) js += 0.5 * q * Math.log2(q / m);
        }
        js = Math.abs(js);
        // Risk score alignment
        const riskAlign = 1 - Math.abs(vi.meanRisk - vj.meanRisk);
        // Target entropy alignment
        const targetAlign = 1 - Math.abs(vi.targetEntropy - vj.targetEntropy);
        // Combined: low JS (similar distributions) + high alignment → correlation
        const corr = (1 - Math.min(1, js)) * 0.5 + riskAlign * 0.25 + targetAlign * 0.25;
        totalCorr += corr;
        pairs++;
      }
    }
    return pairs > 0 ? totalCorr / pairs : 0;
  }

  _combinations(arr, k) {
    if (k === 0) return [[]];
    if (arr.length < k) return [];
    const result = [];
    const first = arr[0];
    const rest = arr.slice(1);
    // Include first
    for (const c of this._combinations(rest, k - 1)) {
      result.push([first, ...c]);
    }
    // Exclude first
    result.push(...this._combinations(rest, k));
    return result;
  }

  _buildIncidenceMatrix(hyperedges, n) {
    const m = hyperedges.length;
    if (m === 0) {
      this._hypergraph.incidence = null;
      this._hypergraph.edgeWeights = null;
      return;
    }

    // Incidence matrix H: |V| × |E|
    const H = new Float64Array(n * m);
    const weights = new Float64Array(m);

    for (let e = 0; e < m; e++) {
      const he = hyperedges[e];
      weights[e] = he.weight;
      for (const agentIdx of he.agents) {
        if (agentIdx < n) {
          H[agentIdx * m + e] = 1;
        }
      }
    }

    this._hypergraph.incidence = H;
    this._hypergraph.edgeWeights = weights;
  }

  _buildHypergraphLaplacian(n) {
    const H = this._hypergraph.incidence;
    const w = this._hypergraph.edgeWeights;
    const m = w ? w.length : 0;

    // L_H = D_v - H W D_e^{-1} H^T
    const L = new Float64Array(n * n);

    if (m === 0) {
      this._hypergraph.laplacian = L;
      return;
    }

    // Vertex degrees: d_v(i) = Σ H(i,e) * w(e)
    const d_v = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      for (let e = 0; e < m; e++) {
        d_v[i] += H[i * m + e] * w[e];
      }
    }

    // Edge degrees: d_e(e) = Σ_i H(i,e)
    const d_e = new Float64Array(m);
    for (let e = 0; e < m; e++) {
      for (let i = 0; i < n; i++) {
        d_e[e] += H[i * m + e];
      }
    }

    // Compute H W D_e^{-1} H^T = Σ_e (w(e)/d_e(e)) * H(:,e) * H(:,e)^T
    for (let e = 0; e < m; e++) {
      if (d_e[e] < 1) continue;
      const factor = w[e] / d_e[e];
      for (let i = 0; i < n; i++) {
        if (H[i * m + e] === 0) continue;
        for (let j = 0; j < n; j++) {
          if (H[j * m + e] === 0) continue;
          L[i * n + j] += factor * H[i * m + e] * H[j * m + e];
        }
      }
    }

    // Subtract from D_v to get L_H = D_v - HWD^{-1}H^T
    for (let i = 0; i < n; i++) {
      L[i * n + i] = d_v[i] - L[i * n + i];
      for (let j = 0; j < n; j++) {
        if (i !== j) L[i * n + j] = -L[i * n + j];
      }
    }

    this._hypergraph.laplacian = L;
  }

  _computeEigenvalues(n) {
    const L = this._hypergraph.laplacian;
    if (!L || n === 0) return new Float64Array(0);

    // Use power iteration to get top eigenvalues of -L (smallest of L)
    // Actually we want eigenvalues of L directly — use shifted inverse iteration
    // For simplicity: compute via Rayleigh-Ritz on random subspace
    const k = Math.min(n, 16);
    const evals = new Float64Array(k);

    if (n === 1) {
      evals[0] = L[0];
      return evals;
    }

    // Subspace iteration on L (positive semidefinite, we want smallest eigenvalues)
    // Shift: L' = μI - L where μ = trace(L)/n (approximate)
    let trace = 0;
    for (let i = 0; i < n; i++) trace += L[i * n + i];
    const mu = trace / n;

    // Build shifted matrix M = μI - L (we want largest eigenvalues of M = smallest of L)
    const M = new Float64Array(n * n);
    for (let i = 0; i < n; i++) {
      M[i * n + i] = mu - L[i * n + i];
      for (let j = i + 1; j < n; j++) {
        M[i * n + j] = -L[i * n + j];
        M[j * n + i] = M[i * n + j];
      }
    }

    // Random subspace
    const Q = new Float64Array(n * k);
    for (let i = 0; i < n * k; i++) Q[i] = Math.random() * 2 - 1;
    this._gramSchmidt(Q, k, n);

    for (let iter = 0; iter < 50; iter++) {
      const Z = new Float64Array(n * k);
      for (let col = 0; col < k; col++) {
        for (let i = 0; i < n; i++) {
          let sum = 0;
          for (let j = 0; j < n; j++) sum += M[i * n + j] * Q[j * k + col];
          Z[i * k + col] = sum;
        }
      }
      this._gramSchmidt(Z, k, n);
      // Check convergence
      let diff = 0;
      for (let i = 0; i < n * k; i++) {
        const d = Z[i] - Q[i];
        diff += d * d;
      }
      for (let i = 0; i < n * k; i++) Q[i] = Z[i];
      if (Math.sqrt(diff) < 1e-10) break;
    }

    // Rayleigh quotients
    const eigsM = new Float64Array(k);
    for (let col = 0; col < k; col++) {
      const v = new Float64Array(n);
      for (let i = 0; i < n; i++) v[i] = Q[i * k + col];
      // r(v) = v^T M v / v^T v
      let num = 0, den = 0;
      for (let i = 0; i < n; i++) {
        let Mv_i = 0;
        for (let j = 0; j < n; j++) Mv_i += M[i * n + j] * v[j];
        num += v[i] * Mv_i;
        den += v[i] * v[i];
      }
      eigsM[col] = den > 1e-12 ? num / den : 0;
    }

    // Transform back: λ_i(L) = μ - λ_i(M)
    const sorted = new Float64Array(k);
    for (let i = 0; i < k; i++) sorted[i] = mu - eigsM[i];
    sorted.sort((a, b) => a - b); // smallest first (standard Laplacian convention)

    return sorted;
  }

  _gramSchmidt(Q, k, n) {
    for (let col = 0; col < k; col++) {
      const vCol = col * n;
      // Normalize
      let norm = 0;
      for (let i = 0; i < n; i++) norm += Q[vCol + i] * Q[vCol + i];
      norm = Math.sqrt(norm);
      if (norm > 1e-15) {
        for (let i = 0; i < n; i++) Q[vCol + i] /= norm;
      }
      // Orthogonalize against previous
      for (let prev = 0; prev < col; prev++) {
        const pCol = prev * n;
        let dot = 0;
        for (let i = 0; i < n; i++) dot += Q[vCol + i] * Q[pCol + i];
        for (let i = 0; i < n; i++) Q[vCol + i] -= dot * Q[pCol + i];
      }
      // Re-normalize
      norm = 0;
      for (let i = 0; i < n; i++) norm += Q[vCol + i] * Q[vCol + i];
      norm = Math.sqrt(norm);
      if (norm > 1e-15) {
        for (let i = 0; i < n; i++) Q[vCol + i] /= norm;
      }
    }
  }

  _analyzeSpectrum(eigenvalues, n) {
    const k = eigenvalues.length;
    if (k < 3) return { maxGapRatio: 1, gapIndex: 0 };

    let maxGapRatio = 1;
    let gapIndex = 0;
    for (let i = 1; i < k - 1; i++) {
      if (eigenvalues[i] < 1e-10) continue;
      const ratio = eigenvalues[i + 1] / eigenvalues[i];
      if (ratio > maxGapRatio) {
        maxGapRatio = ratio;
        gapIndex = i;
      }
    }
    return { maxGapRatio, gapIndex };
  }

  _extractGroups(spectralAnalysis, n) {
    // Use the spectral gap index to partition agents
    const k = spectralAnalysis.gapIndex + 1; // number of clusters
    if (k <= 1 || k >= n) return [];

    // Get eigenvectors corresponding to smallest k non-zero eigenvalues
    // from the Laplacian and use them for spectral clustering
    const L = this._hypergraph.laplacian;
    if (!L || n < 2) return [];

    // Simplified: if strong spectral gap, group agents by their degree centrality
    const centrality = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      centrality[i] = L[i * n + i]; // degree = diagonal of Laplacian
    }
    const mean = centrality.reduce((a, b) => a + b, 0) / n;
    const std = Math.sqrt(centrality.reduce((sum, c) => sum + (c - mean) ** 2, 0) / n);

    // Agents with centrality > mean + 0.5*std are "highly connected" = potentially colluding
    const highCentrality = [];
    for (let i = 0; i < n; i++) {
      if (centrality[i] > mean + 0.5 * std) {
        highCentrality.push(this._agentIds[i]);
      }
    }

    if (highCentrality.length >= this.minHyperedgeSize) {
      return [highCentrality];
    }
    return [];
  }
}

module.exports = { HypergraphCollusionDetector };
