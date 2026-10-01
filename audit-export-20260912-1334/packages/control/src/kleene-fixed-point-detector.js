'use strict';

/**
 * Kleene Fixed-Point Recursion Detector (KFPR) — #19
 *
 * Core Insight: LLM agents can enter self-referential reasoning loops where
 * their reasoning function f(x) converges to a pathological fixed point
 * x = f(x). Examples:
 *   - "I need to verify whether I'm hallucinating" → must hallucinate to test
 *   - "I must audit my own safety" → safety function applied to itself
 *   - "Explain why you can't explain X" → self-referential paradox
 *   - "Prove that you are not biased" → bias-detection applied to bias-detection
 *
 * These are not cross-agent cycles (causal-loop-breaker domain) — they are
 * single-agent Kleene fixed points where the agent's reasoning function
 * maps its own output back into its input domain, creating a recursive
 * self-reference that the model was not trained to resolve.
 *
 * Mathematical Foundation:
 *   Let f: X → X be the agent's reasoning function on state space X.
 *   By Kleene's First Recursion Theorem (1952), any computable function
 *   on a complete partial order has a least fixed point:
 *
 *     x* = f(x*) where x* = ⊔_{n≥0} f^n(⊥)
 *
 *   The detector tracks the iteration sequence x_0, x_1=f(x_0), x_2=f(x_1), ...
 *   and detects when the sequence converges to a fixed point. It then
 *   classifies the fixed point as:
 *     - SAFE: f(x*) is a normal termination state
 *     - PATHOLOGICAL: the agent is looping in self-reference
 *     - UNSTABLE: repulsive fixed point (divergence from safety)
 *
 *   Detection metric: the contraction rate r = |x_{n+1} - x_n| / |x_n - x_{n-1}|
 *   If r → 1 → pathological approach to fixed point (critical slowing down)
 *   If r > 1 → unstable divergence
 *   If r < 1 and |x_{n+1} - x_n| small → safe convergence
 *
 * Evasion Cost: An adversary constructing self-referential prompts must
 * engineer a function f that achieves behavioral objectives while avoiding
 * the fixed-point signature r → 1 — requiring precise control of the
 * iteration dynamics, a control problem with exponential sensitivity to
 * initial conditions near the fixed point.
 */

class KleeneFixedPointDetector {
  /**
   * @param {object} opts
   *   - stateDim: dimension of the reasoning state proxy (default 8)
   *   - contractionWarn: r approaching 1 threshold (default 0.85)
   *   - cyclesToDetect: number of iterations to monitor (default 10)
   *   - periodThreshold: periodic orbit detection threshold (default 3)
   *   - pathologicalProximity: distance threshold for fixed point (default 0.05)
   */
  constructor(opts = {}) {
    this.stateDim = opts.stateDim || 8;
    this.contractionWarn = opts.contractionWarn || 0.85;
    this.cyclesToDetect = opts.cyclesToDetect || 10;
    this.periodThreshold = opts.periodThreshold || 3;
    this.pathologicalProximity = opts.pathologicalProximity || 0.05;

    // Iteration sequence: [{ state: Float64Array(dim), tag }]
    this._iterationSequence = [];
    this._maxSequence = this.cyclesToDetect * 10;

    // Detected fixed points
    this._fixedPoints = []; // [{ state, type, convergenceRate, period, ts }]

    // Self-reference keyword triggers (for text-based iteration extraction)
    this._selfReferencePatterns = [
      /\b(self.referenc|self.audit|self.check|self.verify|self.monitor|self.evaluat)\w*\b/gi,
      /\b(verify.*(yourself|own|itself)|check.*own|audit.*own|monitor.*itself)\b/gi,
      /\b(explain.*can\'t|cannot.*explain|prove.*not|paradox|contradiction)\b/gi,
      /\b(recursive|recursion|iterate|iteration|loop.within)\b/gi,
      /\b(meta.cognit|meta.reason|thinking.about.thinking)\b/gi,
    ];
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Feed a reasoning state and return fixed-point assessment.
   * @param {Float64Array|number[]} state — reasoning state vector (dim stateDim)
   * @param {string} text — optional text to detect self-referential patterns
   * @param {object} context — { tag, ts }
   * @returns {object} recursion assessment
   */
  feed(state, text = '', context = {}) {
    const s = this._ensureState(state);
    if (!s) return { mode: 'no_data' };

    const tag = context.tag || 'iteration';
    this._iterationSequence.push({ state: s, tag, ts: context.ts || Date.now() });
    if (this._iterationSequence.length > this._maxSequence) {
      this._iterationSequence = this._iterationSequence.slice(-this._maxSequence);
    }

    const seqLen = this._iterationSequence.length;

    // Need at least 3 states for contraction analysis
    if (seqLen < 3) {
      const srScore = this._selfReferenceTextScore(text);
      return {
        mode: 'accumulating',
        iterations: seqLen,
        neededForAnalysis: 3,
        selfReferenceTextScore: srScore > 0 ? +srScore.toFixed(3) : 0,
      };
    }

    // Compute contraction rate
    const last3 = this._iterationSequence.slice(-3);
    const d1 = this._stateDistance(last3[1].state, last3[2].state);
    const d0 = this._stateDistance(last3[0].state, last3[1].state);
    const contractionRate = d0 > 1e-12 ? d1 / d0 : (d1 < 1e-12 ? 1.0 : 2.0);

    // Detect periodic orbits
    const period = this._detectPeriod();

    // Detect fixed-point convergence
    const fpAnalysis = this._analyzeFixedPoint(contractionRate, period);

    // Self-reference text augmentation
    const srScore = this._selfReferenceTextScore(text);

    // Combined pathological score
    const pathologyScore = fpAnalysis.fixedPointType === 'pathological'
      ? Math.min(1, (1 - contractionRate) * 2 + srScore * 0.3)
      : fpAnalysis.fixedPointType === 'unstable'
        ? Math.min(1, (contractionRate - 1) * 0.5 + srScore * 0.3)
        : srScore * 0.5;

    const isPathological = fpAnalysis.fixedPointType === 'pathological' ||
      (fpAnalysis.fixedPointType === 'periodic' && srScore > 0.3) ||
      pathologyScore > 0.5;

    return {
      mode: 'monitoring',
      contractionRate: +contractionRate.toFixed(4),
      distanceToPrevious: +d1.toFixed(4),
      fixedPointType: fpAnalysis.fixedPointType,
      fixedPointProximity: +fpAnalysis.proximity.toFixed(4),
      period,
      pathologyScore: +pathologyScore.toFixed(4),
      isPathological,
      selfReferenceTextScore: +srScore.toFixed(3),
      signal: isPathological ? (pathologyScore > 0.7 ? 'REQUIRE_APPROVAL' : 'WARN') : 'CLEAR',
      iterationCount: seqLen,
      detectedKeywords: this._extractSelfReferenceKeywords(text),
    };
  }

  /**
   * Get the current iteration sequence for external analysis.
   */
  getIterationSequence() {
    return this._iterationSequence.map((entry, i) => ({
      iteration: i,
      state: Array.from(entry.state).map(v => +v.toFixed(4)),
      tag: entry.tag,
      ts: entry.ts,
    }));
  }

  /**
   * Get detected fixed points.
   */
  getFixedPoints() {
    return this._fixedPoints.map(fp => ({
      state: Array.from(fp.state).map(v => +v.toFixed(4)),
      type: fp.type,
      convergenceRate: fp.convergenceRate,
      period: fp.period,
      timestamp: fp.ts,
    }));
  }

  /**
   * Reset iteration history.
   */
  reset() {
    this._iterationSequence = [];
    this._fixedPoints = [];
  }

  // ── Internal Methods ─────────────────────────────────────

  _ensureState(arr) {
    if (!arr) return null;
    if (arr instanceof Float64Array) return arr;
    if (Array.isArray(arr)) {
      const v = new Float64Array(this.stateDim);
      for (let i = 0; i < Math.min(arr.length, this.stateDim); i++) v[i] = arr[i] || 0;
      return v;
    }
    return null;
  }

  _stateDistance(a, b) {
    let sum = 0;
    for (let i = 0; i < this.stateDim; i++) {
      const diff = a[i] - b[i];
      sum += diff * diff;
    }
    return Math.sqrt(sum);
  }

  _detectPeriod() {
    const seq = this._iterationSequence;
    const n = seq.length;
    if (n < 6) return 0;

    // Try period lengths 2, 3, 4, 5, 6
    for (let p = 2; p <= Math.min(6, Math.floor(n / 2)); p++) {
      let match = true;
      for (let i = 0; i < p; i++) {
        const a = seq[n - 1 - i].state;
        const b = seq[n - 1 - i - p].state;
        if (this._stateDistance(a, b) > this.pathologicalProximity * 3) {
          match = false;
          break;
        }
      }
      if (match) return p;
    }
    return 0;
  }

  _analyzeFixedPoint(contractionRate, period) {
    const seq = this._iterationSequence;
    const last = seq[seq.length - 1].state;

    // Distance to second-last state
    const proximity = seq.length >= 2
      ? this._stateDistance(last, seq[seq.length - 2].state)
      : 1.0;

    let fixedPointType = 'none';

    if (period >= 2) {
      // Periodic orbit detected
      fixedPointType = 'periodic';

      // Register periodic orbit as fixed point
      this._fixedPoints.push({
        state: new Float64Array(last),
        type: 'periodic',
        convergenceRate: contractionRate,
        period,
        ts: Date.now(),
      });
    } else if (proximity < this.pathologicalProximity && contractionRate > this.contractionWarn) {
      // Approaching a fixed point with critical slowing down → pathological
      fixedPointType = 'pathological';

      this._fixedPoints.push({
        state: new Float64Array(last),
        type: 'pathological',
        convergenceRate: contractionRate,
        period: 0,
        ts: Date.now(),
      });
    } else if (proximity < this.pathologicalProximity && contractionRate <= this.contractionWarn) {
      // Safe convergence
      fixedPointType = 'safe_fixed';
    } else if (contractionRate > 1.0) {
      // Unstable — diverging from safe region
      fixedPointType = 'unstable';
    } else if (contractionRate > this.contractionWarn) {
      // Approaching critical slowing (not yet at fixed point)
      fixedPointType = 'critical_approach';
    }

    if (this._fixedPoints.length > 50) {
      this._fixedPoints = this._fixedPoints.slice(-50);
    }

    return { fixedPointType, proximity };
  }

  _selfReferenceTextScore(text) {
    if (!text) return 0;
    let score = 0;
    for (const pattern of this._selfReferencePatterns) {
      const matches = text.match(pattern);
      if (matches) score += Math.min(1, matches.length * 0.25);
    }
    return Math.min(1, score);
  }

  _extractSelfReferenceKeywords(text) {
    if (!text) return [];
    const keywords = [];
    for (const pattern of this._selfReferencePatterns) {
      const matches = text.match(pattern);
      if (matches) {
        for (const m of matches) {
          if (!keywords.includes(m.toLowerCase())) keywords.push(m.toLowerCase());
        }
      }
    }
    return keywords.slice(0, 10);
  }
}

module.exports = { KleeneFixedPointDetector };
