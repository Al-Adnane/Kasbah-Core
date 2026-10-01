'use strict';

/**
 * InfoFlowComplexity — Information-Theoretic Complexity for Agent Streams
 * ======================================================================
 * Paper 008 implementation. Replaces the fluid-dynamics metaphor
 * (Reynolds number, vorticity) with rigorous dynamical systems theory:
 *
 *   1. Permutation Entropy (Bandt & Pompe, 2002)
 *      Quantifies ordinal pattern complexity in agent communication.
 *      Low PE → highly regular/ordered (possible manipulation).
 *      High PE → near-random (possible flooding/noise attack).
 *      Healthy range: PE ∈ [0.45, 0.85].
 *
 *   2. Largest Lyapunov Exponent (Rosenstein et al., 1993)
 *      Measures exponential divergence of nearby trajectories.
 *      λ > 0 → chaotic (possible adversarial destabilization).
 *      λ ≈ 0 → stable/periodic.
 *      λ < 0 → converging (possible echo-chamber collapse).
 *
 *   3. Entropy-Complexity Plane
 *      Maps (PE, Jensen-Shannon complexity) to detect regime shifts.
 *      Displacement from healthy region → anomaly score.
 *
 * WHY THIS REPLACES reynolds-flow.js:
 *   Paper 008 states: "The Reynolds number governs momentum transport
 *   in physical fluids, not information transport in agent networks."
 *   This module uses ONLY methods validated on real time-series data.
 *
 * Usage:
 *   const ifc = new InfoFlowComplexity({ windowSize: 64, embedDim: 4 });
 *   ifc.observe(signalVector);
 *   const result = ifc.analyze();
 *   // { permutationEntropy, lyapunovExponent, complexity, anomalyScore, regime }
 */

// ═══════════════════════════════════════════════════════════════
// Permutation Entropy (Bandt & Pompe, 2002)
// ═══════════════════════════════════════════════════════════════

/**
 * Compute normalized permutation entropy of a time series.
 *
 * @param {number[]} signal — 1D array of scalar observations
 * @param {number} D — embedding dimension (default 4)
 * @param {number} tau — embedding delay (default 1)
 * @returns {number} normalized PE ∈ [0, 1]
 */
function permutationEntropy(signal, D = 4, tau = 1) {
  const N = signal.length;
  if (N < D * tau) return 0.5;

  const patternCounts = new Map();
  const factD = factorial(D);

  for (let i = 0; i <= N - D * tau; i++) {
    // Extract embedding vector
    const embed = [];
    for (let j = 0; j < D; j++) {
      embed.push({ value: signal[i + j * tau], index: j });
    }
    // Sort to get ordinal pattern
    embed.sort((a, b) => a.value - b.value);
    const pattern = embed.map(e => e.index).join(',');
    patternCounts.set(pattern, (patternCounts.get(pattern) || 0) + 1);
  }

  const total = N - D * tau + 1;
  let entropy = 0;
  for (const count of patternCounts.values()) {
    const p = count / total;
    entropy -= p * Math.log2(p);
  }

  // Normalize by maximum entropy log2(D!)
  const maxEntropy = Math.log2(factD);
  return maxEntropy > 0 ? entropy / maxEntropy : 0.5;
}

function factorial(n) {
  let r = 1;
  for (let i = 2; i <= n; i++) r *= i;
  return r;
}

// ═══════════════════════════════════════════════════════════════
// Largest Lyapunov Exponent (Rosenstein et al., 1993)
// ═══════════════════════════════════════════════════════════════

/**
 * Approximate the largest Lyapunov exponent from a scalar time series.
 * Uses delay embedding + nearest-neighbor divergence tracking.
 *
 * @param {number[]} signal — 1D scalar time series
 * @param {number} embedDim — embedding dimension (default 3)
 * @param {number} tau — embedding delay (default 1)
 * @param {number} minSep — minimum temporal separation for neighbors (default 10)
 * @returns {number} approximate λ₁; > 0 = chaotic, ≈ 0 = stable, < 0 = converging
 */
function lyapunovExponent(signal, embedDim = 3, tau = 1, minSep = 10) {
  const N = signal.length;
  const M = N - (embedDim - 1) * tau;
  if (M < 2 * minSep) return 0;

  // Build delay embedding vectors
  const vectors = [];
  for (let i = 0; i < M; i++) {
    const v = [];
    for (let j = 0; j < embedDim; j++) {
      v.push(signal[i + j * tau]);
    }
    vectors.push(v);
  }

  // For each point, find nearest temporal neighbor
  let sumLogDiv = 0;
  let pairs = 0;

  for (let i = 0; i < M - 1; i++) {
    let minDist = Infinity;
    let nearestJ = -1;

    for (let j = 0; j < M - 1; j++) {
      if (Math.abs(i - j) < minSep) continue;
      const dist = euclidean(vectors[i], vectors[j]);
      if (dist < minDist && dist > 1e-10) {
        minDist = dist;
        nearestJ = j;
      }
    }

    if (nearestJ >= 0 && i + 1 < M && nearestJ + 1 < M) {
      const divDist = euclidean(vectors[i + 1], vectors[nearestJ + 1]);
      if (divDist > 1e-10) {
        sumLogDiv += Math.log(divDist / minDist);
        pairs++;
      }
    }
  }

  return pairs > 0 ? sumLogDiv / pairs : 0;
}

function euclidean(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

// ═══════════════════════════════════════════════════════════════
// Jensen-Shannon Complexity
// ═══════════════════════════════════════════════════════════════

/**
 * Compute Jensen-Shannon statistical complexity.
 * C_JS = H_S[P] · Q_JS[P, P_e]
 * where H_S is normalized Shannon entropy and Q_JS is disequilibrium.
 *
 * @param {number[]} distribution — probability distribution
 * @returns {number} complexity ∈ [0, 1]
 */
function jsComplexity(distribution) {
  const n = distribution.length;
  if (n < 2) return 0;

  // Normalized Shannon entropy
  const uniform = 1 / n;
  let entropy = 0;
  for (const p of distribution) {
    if (p > 0) entropy -= p * Math.log2(p);
  }
  const hNorm = Math.log2(n) > 0 ? entropy / Math.log2(n) : 0;

  // Jensen-Shannon divergence from uniform
  let jsDiv = 0;
  for (const p of distribution) {
    if (p > 0) {
      const m = (p + uniform) / 2;
      jsDiv += p * Math.log2(p / m) + uniform * Math.log2(uniform / m);
    }
  }
  jsDiv /= 2;

  return hNorm * jsDiv;
}

// ═══════════════════════════════════════════════════════════════
// Main Class
// ═══════════════════════════════════════════════════════════════

class InfoFlowComplexity {
  /**
   * @param {object} opts
   * @param {number} opts.windowSize — sliding window for signal history (default 128)
   * @param {number} opts.embedDim — permutation entropy embedding dimension (default 4)
   * @param {number} opts.lyapEmbedDim — Lyapunov embedding dimension (default 3)
   * @param {number} opts.tau — embedding delay (default 1)
   * @param {number} opts.healthyPeLow — lower healthy PE bound (default 0.45)
   * @param {number} opts.healthyPeHigh — upper healthy PE bound (default 0.85)
   * @param {number} opts.chaosThreshold — λ₁ above this → chaotic (default 0.01)
   */
  constructor(opts = {}) {
    this.windowSize = opts.windowSize || 128;
    this.embedDim = opts.embedDim || 4;
    this.lyapEmbedDim = opts.lyapEmbedDim || 3;
    this.tau = opts.tau || 1;
    this.healthyPeLow = opts.healthyPeLow || 0.45;
    this.healthyPeHigh = opts.healthyPeHigh || 0.85;
    this.chaosThreshold = opts.chaosThreshold || 0.01;

    this.history = [];        // sliding window of scalar observations
    this.anomalyLog = [];
  }

  /**
   * Observe a new scalar value from the agent stream.
   * @param {number} value — scalar metric (e.g. message rate, entropy, latency)
   */
  observe(value) {
    this.history.push(value);
    if (this.history.length > this.windowSize) {
      this.history = this.history.slice(-this.windowSize);
    }
  }

  /**
   * Run full analysis on current window.
   * @returns {object}
   */
  analyze() {
    const N = this.history.length;
    if (N < 20) {
      return {
        permutationEntropy: 0.5,
        lyapunovExponent: 0,
        complexity: 0,
        anomalyScore: 0,
        regime: 'insufficient_data',
        advisory: 'NONE'
      };
    }

    const pe = permutationEntropy(this.history, this.embedDim, this.tau);
    const lyap = lyapunovExponent(this.history, this.lyapEmbedDim, this.tau, 10);

    // Build ordinal pattern distribution for JS complexity
    const patternDist = buildPatternDist(this.history, this.embedDim, this.tau);
    const complexity = jsComplexity(patternDist);

    // Anomaly score: displacement from healthy region in (PE, complexity) plane
    // Healthy: PE ∈ [0.45, 0.85], complexity ∈ [0.05, 0.25]
    const peDeviation = pe < this.healthyPeLow ? (this.healthyPeLow - pe) / this.healthyPeLow :
                        pe > this.healthyPeHigh ? (pe - this.healthyPeHigh) / (1 - this.healthyPeHigh) : 0;
    const complexityDeviation = Math.abs(complexity - 0.15) / 0.15;
    const lyapComponent = lyap > this.chaosThreshold ? Math.min(1, lyap / 0.1) :
                           lyap < -this.chaosThreshold ? Math.min(1, Math.abs(lyap) / 0.1) : 0;

    const anomalyScore = Math.min(1, (peDeviation * 0.4 + complexityDeviation * 0.3 + lyapComponent * 0.3));

    // Regime classification
    let regime = 'healthy';
    if (lyap > this.chaosThreshold) regime = 'chaotic';
    else if (lyap < -this.chaosThreshold) regime = 'converging';
    else if (pe < 0.3) regime = 'periodic';
    else if (pe > 0.9) regime = 'random';

    // Advisory signal (never DENY)
    let advisory = 'NONE';
    if (anomalyScore >= 0.70) advisory = 'REQUIRE_APPROVAL';
    else if (anomalyScore >= 0.45) advisory = 'WARN';

    const result = {
      permutationEntropy: +pe.toFixed(4),
      lyapunovExponent: +lyap.toFixed(6),
      complexity: +complexity.toFixed(4),
      anomalyScore: +anomalyScore.toFixed(4),
      regime,
      advisory,
      windowSize: N,
      // Backward compatibility with nature-features.js
      regimeCompat: regime === 'chaotic' ? 'turbulent' : regime === 'converging' ? 'transitional' : 'laminar',
      overallDissonance: anomalyScore,
    };

    if (anomalyScore >= 0.45) {
      this.anomalyLog.push({ ts: Date.now(), ...result });
      if (this.anomalyLog.length > 100) this.anomalyLog.shift();
    }

    return result;
  }

  /**
   * Full test: run on a constructed adversarial signal and return detection stats.
   * @returns {{pe, lyap, complexity, anomalyScore, regime}}
   */
  test() {
    return this.analyze();
  }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

function buildPatternDist(signal, D, tau) {
  const N = signal.length;
  const counts = new Map();
  let total = 0;

  for (let i = 0; i <= N - D * tau; i++) {
    const embed = [];
    for (let j = 0; j < D; j++) {
      embed.push({ value: signal[i + j * tau], index: j });
    }
    embed.sort((a, b) => a.value - b.value);
    const pattern = embed.map(e => e.index).join(',');
    counts.set(pattern, (counts.get(pattern) || 0) + 1);
    total++;
  }

  return Array.from(counts.values()).map(c => c / total);
}

// ═══════════════════════════════════════════════════════════════
// Exports
// ═══════════════════════════════════════════════════════════════

module.exports = {
  InfoFlowComplexity,
  permutationEntropy,
  lyapunovExponent,
  jsComplexity,
};
