'use strict';

/**
 * Semantic Tool Drift Detector (STDD) — #20
 *
 * Core Insight: LLM agent tool-use semantics can drift over time. A "READ"
 * operation gradually acquires "WRITE" semantics; a "SEARCH" becomes a
 * "SCRAPE"; an "APPROVE" becomes a "BY DEFAULT APPROVE." This is not a
 * discrete permission escalation — it's a continuous semantic trajectory
 * that existing binary or threshold-based detectors miss entirely.
 *
 * We model the semantics of each tool as a vector in a high-dimensional
 * semantic space M. The tool's meaning at time t is v(t) ∈ M. Semantic
 * drift is the directional derivative of v(t) along the time axis —
 * the Lie derivative ℒ_∂/∂t (v) in the tangent bundle TM.
 *
 * Mathematical Foundation:
 *   Let M be a differentiable manifold with metric g (cosine similarity).
 *   Let v_i: ℝ → M be the semantic trajectory of tool i.
 *   The Lie derivative along the time vector field is:
 *
 *     ℒ_∂/∂t (v_i) = lim_{Δt→0} (v_i(t+Δt) - v_i(t)) / Δt
 *
 *   We estimate this as the discrete derivative:
 *
 *     drift_i(t) = ||v_i(t) - v_i(t-1)|| / ||v_i(t-1)||
 *
 *   And the directional component toward dangerous tool semantics:
 *
 *     danger_component_i(t) = drift_i(t) · cos(θ_i)
 *
 *   where θ_i = angle between drift vector and "danger" direction
 *   (the vector from safe semantics to dangerous tool semantics).
 *
 *   The Lie bracket [drift, danger] measures commutativity — if non-zero,
 *   the drift is expanding into new semantic territory.
 *
 * Evasion Cost: To evade, an adversary must control the continuous
 * semantic trajectory of tool use — a smooth manifold control problem
 * with N! constraints (all pairwise tool-to-tool drift comparisons).
 * This is fundamentally harder than evading threshold detectors because
 * the drift signature emerges from the GEOMETRY of the trajectory, not
 * any single discrete event.
 */

class SemanticToolDriftDetector {
  /**
   * @param {object} opts
   *   - semanticDim: dimension of semantic embedding space (default 32)
   *   - driftWarn: drift magnitude threshold for WARN (default 0.15)
   *   - driftReview: drift magnitude threshold for REVIEW (default 0.30)
   *   - windowSize: sliding window for trajectory smoothing (default 30)
   *   - tools: predefined tool set with embeddings (default SAFE/DANGER pairs)
   */
  constructor(opts = {}) {
    this.semanticDim = opts.semanticDim || 32;
    this.driftWarn = opts.driftWarn || 0.15;
    this.driftReview = opts.driftReview || 0.30;
    this.windowSize = opts.windowSize || 30;

    // Tool registry: toolName → { safeEmbedding, dangerEmbedding, trajectory[] }
    this._tools = {};

    // Initialize predefined tool embeddings if provided
    if (opts.tools) {
      for (const [name, embeddings] of Object.entries(opts.tools)) {
        this.registerTool(name, embeddings.safe, embeddings.danger);
      }
    }

    // Default tools with synthetic safe/danger embeddings
    this._initDefaultTools();

    // Cross-tool Lie bracket tracking
    this._lieBrackets = {}; // "toolA→toolB" → bracket value
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Register a tool with its safe and danger semantic embeddings.
   */
  registerTool(name, safeEmbedding, dangerEmbedding) {
    this._tools[name] = {
      safe: this._ensureVector(safeEmbedding),
      danger: this._ensureVector(dangerEmbedding),
      trajectory: [], // [{ embedding, tag, ts }]
      driftHistory: [], // rolling drift magnitudes
    };
  }

  /**
   * Observe a tool use event and return drift assessment.
   * @param {string} toolName — the tool being used
   * @param {Float64Array|number[]} semanticEmbedding — the current semantics
   * @param {object} context — { tag, parameters, ts }
   * @returns {object} drift assessment
   */
  observe(toolName, semanticEmbedding, context = {}) {
    const tool = this._resolveTool(toolName);
    const emb = this._ensureVector(semanticEmbedding);
    if (!emb) return { mode: 'no_data', tool: toolName };

    if (!tool) {
      // Auto-register unknown tool
      const safe = new Float64Array(this.semanticDim);
      const danger = new Float64Array(this.semanticDim);
      for (let i = 0; i < this.semanticDim; i++) {
        safe[i] = emb[i] * 0.5;
        danger[i] = emb[i] * 1.5 - (Math.random() * 0.5);
      }
      this.registerTool(toolName, safe, danger);
      return {
        mode: 'new_tool',
        tool: toolName,
        message: 'Auto-registered new tool for drift tracking',
      };
    }

    const t = this._tools[toolName];
    t.trajectory.push({ embedding: emb, tag: context.tag || 'use', ts: context.ts || Date.now() });
    if (t.trajectory.length > this.windowSize * 10) {
      t.trajectory = t.trajectory.slice(-this.windowSize * 10);
    }

    // Need at least 2 points for drift
    if (t.trajectory.length < 2) {
      return { mode: 'priming', tool: toolName, points: t.trajectory.length };
    }

    // Compute drift: semantic velocity between consecutive positions
    const prev = t.trajectory[t.trajectory.length - 2].embedding;
    const driftVec = new Float64Array(this.semanticDim);
    for (let i = 0; i < this.semanticDim; i++) driftVec[i] = emb[i] - prev[i];

    const driftMagnitude = Math.sqrt(this._dot(driftVec, driftVec));

    // Directional analysis: cosine similarity to danger direction
    const safeVec = t.safe;
    const dangerVec = t.danger;
    const safeToDanger = new Float64Array(this.semanticDim);
    for (let i = 0; i < this.semanticDim; i++) safeToDanger[i] = dangerVec[i] - safeVec[i];
    const dangerNorm = Math.sqrt(this._dot(safeToDanger, safeToDanger));

    let dangerAlignment = 0;
    if (dangerNorm > 1e-12 && driftMagnitude > 1e-12) {
      dangerAlignment = this._dot(driftVec, safeToDanger) / (driftMagnitude * dangerNorm);
    }

    // Moving from safe toward danger: positive alignment = concerning
    const dangerComponent = driftMagnitude * Math.max(0, dangerAlignment);

    // Current position: distance from safe anchor
    const fromSafe = new Float64Array(this.semanticDim);
    for (let i = 0; i < this.semanticDim; i++) fromSafe[i] = emb[i] - safeVec[i];
    const safeDistance = Math.sqrt(this._dot(fromSafe, fromSafe));

    // Update drift history
    t.driftHistory.push(driftMagnitude);
    if (t.driftHistory.length > this.windowSize * 5) {
      t.driftHistory = t.driftHistory.slice(-this.windowSize * 5);
    }

    // Rolling statistics
    const recentDrifts = t.driftHistory.slice(-this.windowSize);
    const meanDrift = recentDrifts.length > 0
      ? recentDrifts.reduce((a, b) => a + b, 0) / recentDrifts.length : 0;
    const driftTrend = this._linearTrend(recentDrifts);

    // Cross-tool Lie bracket analysis
    const lieBrackets = this._computeLieBrackets(toolName, emb);

    // Combined drift score
    const driftScore = driftMagnitude * 0.4 + dangerComponent * 0.4 + driftTrend * 0.2;
    const isDrifting = driftMagnitude > this.driftWarn || dangerComponent > this.driftWarn * 0.5;
    const isCritical = driftMagnitude > this.driftReview || dangerComponent > this.driftReview * 0.5;

    return {
      mode: 'monitoring',
      tool: toolName,
      driftMagnitude: +driftMagnitude.toFixed(4),
      dangerAlignment: +dangerAlignment.toFixed(4),
      dangerComponent: +dangerComponent.toFixed(4),
      safeDistance: +safeDistance.toFixed(4),
      driftScore: +driftScore.toFixed(4),
      meanDrift: +meanDrift.toFixed(4),
      driftTrend: +driftTrend.toFixed(4),
      isDrifting,
      isCritical,
      signal: isCritical ? 'REQUIRE_APPROVAL'
        : isDrifting ? 'WARN' : 'CLEAR',
      trajectoryLength: t.trajectory.length,
      lieBrackets: lieBrackets.filter(b => Math.abs(b.value) > 0.1)
        .map(b => ({ pair: b.pair, value: +b.value.toFixed(4) })),
    };
  }

  /**
   * Get all tool drift states for external visualization.
   */
  getDriftState() {
    const state = {};
    for (const [name, tool] of Object.entries(this._tools)) {
      const recent = tool.driftHistory.slice(-10);
      state[name] = {
        trajectoryPoints: tool.trajectory.length,
        recentDriftMean: recent.length > 0
          ? +(recent.reduce((a, b) => a + b, 0) / recent.length).toFixed(4) : 0,
        recentDriftMax: recent.length > 0
          ? +Math.max(...recent).toFixed(4) : 0,
        safeAnchor: Array.from(tool.safe).map(v => +v.toFixed(3)),
        dangerAnchor: Array.from(tool.danger).map(v => +v.toFixed(3)),
      };
    }
    return state;
  }

  // ── Internal Methods ─────────────────────────────────────

  _initDefaultTools() {
    // Default tool set with synthetic safe/danger embeddings
    const defaultTools = {
      READ:    { safeDir: +1, dangerDir: -0.7 },  // danger: READ becoming WRITE
      WRITE:   { safeDir: -0.5, dangerDir: +0.9 },  // danger: WRITE becoming DELETE
      SEARCH:  { safeDir: +0.8, dangerDir: -0.4 },  // danger: SEARCH becoming SCRAPE
      SHARE:   { safeDir: +0.3, dangerDir: +0.8 },  // danger: SHARE becoming LEAK
      DELETE:  { safeDir: -0.6, dangerDir: +0.95 },  // danger: DELETE becoming INDISCRIMINATE
      APPROVE: { safeDir: -0.3, dangerDir: +0.85 },  // danger: APPROVE becoming BLINDLY_APPROVE
      DENY:    { safeDir: +0.5, dangerDir: -0.7 },   // danger: DENY becoming BLOCK_ALL
      ESCALATE:{ safeDir: +0.1, dangerDir: +0.9 },   // danger: ESCALATE becoming SPAM_ESCALATE
    };

    for (const [name, dirs] of Object.entries(defaultTools)) {
      if (this._tools[name]) continue; // Don't override registered tools
      const safe = new Float64Array(this.semanticDim);
      const danger = new Float64Array(this.semanticDim);
      for (let i = 0; i < this.semanticDim; i++) {
        safe[i] = dirs.safeDir * (Math.sin(i * 0.5) * 0.5 + 0.5);
        danger[i] = dirs.dangerDir * (Math.cos(i * 0.4) * 0.5 + 0.5);
      }
      this.registerTool(name, safe, danger);
    }
  }

  _resolveTool(name) {
    if (!name) return null;
    const upper = String(name).toUpperCase();
    for (const [key, tool] of Object.entries(this._tools)) {
      if (key === upper || upper.includes(key) || key.includes(upper.split(':')[0])) {
        return key;
      }
    }
    return null;
  }

  _ensureVector(arr) {
    if (!arr) return null;
    if (arr instanceof Float64Array) return arr;
    if (Array.isArray(arr)) {
      const v = new Float64Array(this.semanticDim);
      for (let i = 0; i < Math.min(arr.length, this.semanticDim); i++) v[i] = arr[i] || 0;
      return v;
    }
    return null;
  }

  _dot(a, b) {
    let sum = 0;
    for (let i = 0; i < this.semanticDim; i++) sum += a[i] * b[i];
    return sum;
  }

  _linearTrend(vals) {
    if (!vals || vals.length < 3) return 0;
    const n = vals.length;
    const meanX = (n - 1) / 2;
    const meanY = vals.reduce((a, b) => a + b, 0) / n;
    let num = 0, den = 0;
    for (let i = 0; i < n; i++) {
      num += (i - meanX) * (vals[i] - meanY);
      den += (i - meanX) * (i - meanX);
    }
    return den > 1e-12 ? num / den : 0;
  }

  _computeLieBrackets(currentTool, currentEmb) {
    const brackets = [];
    for (const [name, tool] of Object.entries(this._tools)) {
      if (name === currentTool) continue;
      // Lie bracket proxy: how much does tool A's drift align with tool B's danger direction?
      // [drift_A, danger_B] = drift_A · danger_B - danger_A · drift_B
      if (tool.trajectory.length < 2) continue;
      const lastA = tool.trajectory[tool.trajectory.length - 1].embedding;
      const prevA = tool.trajectory[tool.trajectory.length - 2].embedding;
      const driftA = new Float64Array(this.semanticDim);
      for (let i = 0; i < this.semanticDim; i++) driftA[i] = lastA[i] - prevA[i];

      const driftANorm = Math.sqrt(this._dot(driftA, driftA));
      if (driftANorm < 1e-12) continue;

      // Current tool's danger direction
      const currTool = this._tools[currentTool];
      const dangerCurr = currTool.danger;

      const driftADangerAlign = this._dot(driftA, dangerCurr) / driftANorm;

      if (Math.abs(driftADangerAlign) > 0.1) {
        brackets.push({ pair: `${name}→${currentTool}`, value: driftADangerAlign });
      }
    }
    return brackets;
  }
}

module.exports = { SemanticToolDriftDetector };
