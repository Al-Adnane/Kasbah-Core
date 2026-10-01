/**
 * Entropy-Complexity Plane for Flow Regime Classification (Original Idea #10)
 *
 * Uses the (permutation entropy H̃_P, Jensen-Shannon complexity C_JS) plane
 * as a 2D FINGERPRINT to classify agent communication dynamics into regimes:
 * { NORMAL, FLOOD, SILENCE, ECHO, CHAOS, PULSE }.
 *
 * CORE INSIGHT:
 *   Most communication anomaly detection uses univariate metrics (message
 *   rate, entropy). This uses a 2D PHASE SPACE that distinguishes:
 *     - Stochastic noise from deterministic chaos from structured regularity
 *     - Each regime occupies a distinct region of the (H̃_P, C_JS) plane
 *
 * REGIME MAP:
 *   (H̃_P near 0, C_JS near 0):  SILENCE — almost no variation
 *   (H̃_P near 0, C_JS low):     ECHO — repetitive structured pattern
 *   (H̃_P mid, C_JS high):       PULSE — regular bursts
 *   (H̃_P mid, C_JS mid):        NORMAL — healthy communication
 *   (H̃_P high, C_JS low):       FLOOD — high entropy white noise
 *   (H̃_P high, C_JS high):      CHAOS — deterministic chaos
 *
 * COMPUTATION:
 *   1. Permutation Entropy (Bandt & Pompe 2002):
 *      H̃_P = -Σ p(π) · log₂(p(π)) / log₂(D!)
 *
 *      where p(π) = frequency of ordinal pattern π in embedded time series,
 *            D = embedding dimension,
 *            τ = embedding delay
 *
 *   2. Jensen-Shannon Complexity (Rosso et al. 2007):
 *      C_JS = Q_J(P, P_e) · H̃_P
 *
 *      where Q_J(P, P_e) = JS(P || P_e) / JS_max
 *            P_e = uniform distribution over D! patterns
 *            JS_max = -½[((D!+1)/D!)log(D!+1) - 2log(2D!) + log(D!)]
 *
 * REFERENCES:
 *   Bandt, C., & Pompe, B. (2002). "Permutation entropy: a natural
 *   complexity measure for time series." Physical Review Letters.
 *   Rosso, O.A., et al. (2007). "Distinguishing noise from chaos."
 *   Physical Review Letters, 99(15), 154102.
 *
 * @module entropy-complexity-plane
 */
'use strict';

class EntropyComplexityPlane {
  /**
   * @param {Object} opts
   * @param {number} opts.embeddingDim - D for permutation patterns (default: 5)
   * @param {number} opts.embeddingDelay - τ for embedding (default: 1)
   * @param {number} opts.windowSize - Sliding window size (default: 100)
   * @param {number} opts.windowStep - Step between windows (default: 10)
   */
  constructor(opts = {}) {
    this.embeddingDim = opts.embeddingDim || 5;
    this.embeddingDelay = opts.embeddingDelay || 1;
    this.windowSize = opts.windowSize || 100;
    this.windowStep = opts.windowStep || 10;

    // Regime centroids in (H̃_P, C_JS) plane
    // Based on Rosso et al. (2007) reference values
    this.regimeMap = {
      SILENCE:  { hp: [0.00, 0.15], cjs: [0.00, 0.10] },
      ECHO:     { hp: [0.10, 0.35], cjs: [0.05, 0.25] },
      PULSE:    { hp: [0.20, 0.50], cjs: [0.20, 0.45] },
      NORMAL:   { hp: [0.35, 0.65], cjs: [0.15, 0.40] },
      FLOOD:    { hp: [0.70, 0.95], cjs: [0.00, 0.20] },
      CHAOS:    { hp: [0.65, 0.95], cjs: [0.25, 0.50] },
      DETERM:   { hp: [0.00, 0.15], cjs: [0.10, 0.85] }, // Deterministic periodic
    };

    // Time series buffer
    this.values = [];
    this.regimeHistory = [];
    this.baselineRegime = null; // Expected normal regime
  }

  /**
   * Feed a value into the time series.
   *
   * @param {number} value - Communication metric (messages/sec, entropy, etc.)
   * @returns {Object | null} Regime classification (or null if insufficient data)
   */
  feed(value) {
    this.values.push(value);

    // Prune old values
    if (this.values.length > this.windowSize * 20) {
      this.values = this.values.slice(-this.windowSize * 10);
    }

    // Need enough data for a window
    if (this.values.length < this.windowSize) {
      return null;
    }

    // Compute on the most recent window
    if (this.values.length % this.windowStep === 0) {
      const window = this.values.slice(-this.windowSize);
      const hp = this.permutationEntropy(window);
      const cjs = this.jensenShannonComplexity(window);
      const regime = this.classifyRegime(hp, cjs);

      this.regimeHistory.push({ hp, cjs, regime, timestamp: Date.now() });

      // Prune regime history
      if (this.regimeHistory.length > 500) {
        this.regimeHistory.shift();
      }

      // Check for regime transition
      const transition = this._detectRegimeTransition();

      return {
        hp,
        cjs,
        regime,
        isNormal: regime === (this.baselineRegime || 'NORMAL'),
        transition: transition || null,
      };
    }

    return null;
  }

  /**
   * Compute Permutation Entropy (H̃_P).
   *
   * Algorithm:
   *   1. Embed time series into D-dimensional vectors with delay τ
   *   2. For each vector, determine the ordinal pattern (permutation)
   *      that sorts the components
   *   3. Compute entropy of the distribution of ordinal patterns
   *   4. Normalize by log₂(D!) to get H̃_P ∈ [0, 1]
   *
   * @param {number[]} series
   * @returns {number} Normalized permutation entropy
   */
  permutationEntropy(series) {
    const D = this.embeddingDim;
    const tau = this.embeddingDelay;
    const N = series.length;
    const M = N - (D - 1) * tau;

    if (M <= 0) return 0;

    // Count ordinal patterns
    const patternCounts = new Map();

    for (let i = 0; i < M; i++) {
      // Extract embedded vector
      const embedded = [];
      for (let d = 0; d < D; d++) {
        embedded.push({ value: series[i + d * tau], index: d });
      }

      // Determine ordinal pattern: sort by value, get permutation of indices
      embedded.sort((a, b) => a.value - b.value);

      // Resolve ties: maintain original order for equal values
      const pattern = embedded.map(e => e.index).join(',');
      patternCounts.set(pattern, (patternCounts.get(pattern) || 0) + 1);
    }

    // Compute entropy
    const Dfact = this._factorial(D);
    const logDfact = Math.log2(Dfact);

    let entropy = 0;
    for (const count of patternCounts.values()) {
      const p = count / M;
      entropy -= p * Math.log2(p);
    }

    // Normalize
    return logDfact > 0 ? entropy / logDfact : 0;
  }

  /**
   * Compute Jensen-Shannon Complexity (C_JS).
   *
   * C_JS = Q_J(P, P_e) · H̃_P
   *
   * where:
   *   Q_J(P, P_e) = JS(P || P_e) / JS_max
   *   JS(P || P_e) = ½ KL(P || M) + ½ KL(P_e || M) where M = (P + P_e) / 2
   *   P_e = uniform distribution
   *   JS_max is the maximum possible JS divergence
   *
   * @param {number[]} series
   * @returns {number}
   */
  jensenShannonComplexity(series) {
    const D = this.embeddingDim;
    const Dfact = this._factorial(D);
    const tau = this.embeddingDelay;
    const N = series.length;
    const M = N - (D - 1) * tau;

    if (M <= 0 || Dfact === 0) return 0;

    // Get ordinal pattern distribution P
    const patternCounts = new Map();
    for (let i = 0; i < M; i++) {
      const embedded = [];
      for (let d = 0; d < D; d++) {
        embedded.push({ value: series[i + d * tau], index: d });
      }
      embedded.sort((a, b) => a.value - b.value);
      const pattern = embedded.map(e => e.index).join(',');
      patternCounts.set(pattern, (patternCounts.get(pattern) || 0) + 1);
    }

    // Number of possible patterns = D!
    const P = new Array(Dfact).fill(0);
    let idx = 0;
    for (const count of patternCounts.values()) {
      if (idx < Dfact) {
        P[idx] = count / M;
        idx++;
      }
    }

    // Uniform distribution P_e
    const Pe = new Array(Dfact).fill(1 / Dfact);

    // Jensen-Shannon divergence
    let jsDiv = 0;
    for (let i = 0; i < Dfact; i++) {
      const Mi = (P[i] + Pe[i]) / 2;
      if (P[i] > 0 && Mi > 0) {
        jsDiv += 0.5 * P[i] * Math.log2(P[i] / Mi);
      }
      if (Pe[i] > 0 && Mi > 0) {
        jsDiv += 0.5 * Pe[i] * Math.log2(Pe[i] / Mi);
      }
    }

    // Maximum JS divergence (Rosso et al. 2007, Eq. 11)
    // JS_max = -½[((D!+1)/D!)log(D!+1) - 2log(2D!) + log(D!)]
    const n = Dfact;
    const JSmax = -0.5 * (
      ((n + 1) / n) * Math.log2(n + 1) -
      2 * Math.log2(2 * n) +
      Math.log2(n)
    );

    // Q_J = JS(P || P_e) / JS_max
    const QJ = JSmax > 0 ? jsDiv / JSmax : 0;

    // H̃_P
    let hp = 0;
    const logDfact = Math.log2(Dfact);
    for (let i = 0; i < Dfact; i++) {
      if (P[i] > 0) {
        hp -= P[i] * Math.log2(P[i]);
      }
    }
    hp = logDfact > 0 ? hp / logDfact : 0;

    // C_JS = Q_J · H̃_P
    return QJ * hp;
  }

  /**
   * Classify the flow regime based on (H̃_P, C_JS) coordinates.
   *
   * @param {number} hp - Normalized permutation entropy
   * @param {number} cjs - Jensen-Shannon complexity
   * @returns {string} Regime label
   */
  classifyRegime(hp, cjs) {
    let bestRegime = 'UNCLASSIFIED';
    let bestScore = Infinity;

    for (const [regime, bounds] of Object.entries(this.regimeMap)) {
      const hpCenter = (bounds.hp[0] + bounds.hp[1]) / 2;
      const cjsCenter = (bounds.cjs[0] + bounds.cjs[1]) / 2;

      // Distance from regime center
      const dist = Math.sqrt(
        Math.pow(hp - hpCenter, 2) + Math.pow(cjs - cjsCenter, 2)
      );

      if (dist < bestScore) {
        bestScore = dist;
        bestRegime = regime;
      }
    }

    return bestRegime;
  }

  /**
   * Set the expected baseline regime.
   *
   * @param {string} regime
   */
  setBaselineRegime(regime) {
    this.baselineRegime = regime;
  }

  /**
   * Estimate baseline regime from recent data.
   */
  estimateBaselineRegime() {
    const history = this.regimeHistory.slice(-50);
    if (history.length === 0) {
      this.baselineRegime = 'NORMAL';
      return;
    }
    const counts = {};
    for (const h of history) {
      counts[h.regime] = (counts[h.regime] || 0) + 1;
    }
    this.baselineRegime = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
  }

  /**
   * Detect regime transition: has the system moved from baseline to an
   * anomalous regime?
   *
   * @returns {Object | null} Transition info or null
   */
  _detectRegimeTransition() {
    const history = this.regimeHistory;
    if (history.length < 10) return null;

    const recent = history.slice(-10);
    const baseline = this.baselineRegime || 'NORMAL';

    const anomalousRegimes = ['FLOOD', 'SILENCE', 'CHAOS'];
    const anomalousCount = recent.filter(r => anomalousRegimes.includes(r.regime)).length;

    if (anomalousCount >= 5) {
      const modalRegime = this._modalRegime(recent);
      return {
        detected: true,
        from: baseline,
        to: modalRegime,
        persistence: anomalousCount,
        window: 10,
        verdict: modalRegime === 'FLOOD' ? 'POSSIBLE_FLOOD_ATTACK' :
                 modalRegime === 'SILENCE' ? 'POSSIBLE_COMMS_BLACKOUT' :
                 modalRegime === 'CHAOS' ? 'POSSIBLE_CHAOTIC_MANIPULATION' :
                 'REGIME_TRANSITION_DETECTED',
      };
    }

    return null;
  }

  _modalRegime(history) {
    const counts = {};
    for (const h of history) {
      counts[h.regime] = (counts[h.regime] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
  }

  _factorial(n) {
    let result = 1;
    for (let i = 2; i <= n; i++) result *= i;
    return result;
  }

  dumpDiagnostics() {
    return {
      valuesCount: this.values.length,
      windowSize: this.windowSize,
      baselineRegime: this.baselineRegime,
      recentRegimes: this.regimeHistory.slice(-20),
      transition: this._detectRegimeTransition(),
    };
  }
}

module.exports = { EntropyComplexityPlane };
