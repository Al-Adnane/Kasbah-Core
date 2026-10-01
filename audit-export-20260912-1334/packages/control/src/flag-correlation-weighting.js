/**
 * Flag Correlation Evidential Weighting (Idea #8)
 *
 * When multiple detectors flag simultaneously, the evidential weight accounts
 * for the CORRELATION STRUCTURE between detectors. Independent confirmations
 * are weighted more heavily than correlated false alarms.
 *
 * KEY INSIGHT:
 *   Simple ensemble methods count flags or average scores:
 *     W_simple(k) = k  (just count the flags)
 *
 *   This is wrong because 5 flags from highly correlated detectors provide
 *   less evidence than 2 flags from genuinely independent detectors.
 *
 *   This module computes:
 *     W(k) = -log(∏ Pr(F_i=1|H₀) · ∏ (Pr(F_i=1,F_j=1|H₀) /
 *              (Pr(F_i=1|H₀)·Pr(F_j=1|H₀)))^(1/k))
 *
 *   Where R_ij = Pr(F_i=1, F_j=1 | H₀) / (Pr(F_i=1|H₀) · Pr(F_j=1|H₀))
 *   is the flag correlation ratio.
 *
 *   - Uncorrelated detectors: R_ij ≈ 1, no penalty
 *   - Highly correlated detectors: R_ij > 1, evidential weight is DOWNWEIGHTED
 *   - Anti-correlated detectors: R_ij < 1, evidential weight is UPWEIGHTED
 *
 * This penalizes detectors that always fire together (likely correlated noise)
 * and rewards independent confirmations (genuinely new evidence).
 *
 * @module flag-correlation-weighting
 */

'use strict';

/**
 * FlagCorrelationFuser: Computes evidential weight of multi-detector flags
 * accounting for the correlation structure between detectors.
 */
class FlagCorrelationFuser {
  /**
   * @param {Object} options
   * @param {number} options.priorFlagProb - Prior probability any detector flags under H₀
   * @param {number} options.decayFactor - Exponential decay for correlation window
   */
  constructor(options = {}) {
    this.priorFlagProb = options.priorFlagProb || 0.1; // P(flag | H₀)
    this.decayFactor = options.decayFactor || 0.95;
    this.correlationMatrix = null;  // R_ij matrix (nDetector × nDetector)
    this.jointFlagCounts = null;    // Count of joint flag events
    this.marginalFlagCounts = null; // Count of per-detector flags
    this.totalObservations = 0;
    this.observationWindow = [];    // Sliding window of flag vectors
    this.maxWindowSize = options.maxWindowSize || 10000;
  }

  /**
   * Initialize the detector set.
   *
   * @param {string[]} detectorIds - Array of detector identifiers
   */
  initializeDetectors(detectorIds) {
    const n = detectorIds.length;
    this.detectorIds = detectorIds;

    // Initialize correlation matrix to identity (uncorrelated prior)
    this.correlationMatrix = Array.from({ length: n }, () => new Array(n).fill(0));
    for (let i = 0; i < n; i++) {
      this.correlationMatrix[i][i] = 1.0;
      for (let j = i + 1; j < n; j++) {
        this.correlationMatrix[i][j] = 1.0; // Uncorrelated prior
        this.correlationMatrix[j][i] = 1.0;
      }
    }

    // Joint flag counts: n × n matrix
    this.jointFlagCounts = Array.from({ length: n }, () => new Array(n).fill(1));

    // Marginal flag counts: n array (Laplace smoothing: start at 1)
    this.marginalFlagCounts = new Array(n).fill(1);
    this.totalObservations = 1;
  }

  /**
   * Observe a flag vector from the detector ensemble.
   *
   * @param {number[]} flags - Binary flag vector (0 = no flag, 1 = flag)
   *                           flags[i] corresponds to detectorIds[i]
   */
  observe(flags) {
    const n = this.detectorIds.length;
    this.totalObservations++;

    // Update marginal counts
    for (let i = 0; i < n; i++) {
      if (flags[i] === 1) {
        this.marginalFlagCounts[i]++;
      }
    }

    // Update joint counts (upper triangular only, matrix is symmetric)
    for (let i = 0; i < n; i++) {
      for (let j = i; j < n; j++) {
        if (flags[i] === 1 && flags[j] === 1) {
          this.jointFlagCounts[i][j]++;
          if (i !== j) {
            this.jointFlagCounts[j][i] = this.jointFlagCounts[i][j];
          }
        }
      }
    }

    // Update sliding window
    this.observationWindow.push(flags);
    if (this.observationWindow.length > this.maxWindowSize) {
      this.observationWindow.shift();
    }

    // Recompute correlation matrix
    this.correlationMatrix = this.estimateCorrelationMatrix();
  }

  /**
   * Estimate the flag correlation matrix R_ij from observed data.
   *
   * R_ij = P(F_i=1, F_j=1 | H₀) / (P(F_i=1 | H₀) · P(F_j=1 | H₀))
   *
   * Interpreted as:
   *   R_ij = 1: Independent (flags occur at rate predicted by marginals)
   *   R_ij > 1: Positively correlated (flags tend to co-occur)
   *   R_ij < 1: Negatively correlated (flags tend to anti-co-occur)
   *
   * @returns {number[][]} n×n correlation matrix
   */
  estimateCorrelationMatrix() {
    const n = this.detectorIds.length;
    const R = Array.from({ length: n }, () => new Array(n).fill(1.0));
    const T = this.totalObservations;

    for (let i = 0; i < n; i++) {
      const p_i = this.marginalFlagCounts[i] / T;
      for (let j = i; j < n; j++) {
        const p_j = this.marginalFlagCounts[j] / T;
        const p_ij = this.jointFlagCounts[i][j] / T;

        // Avoid division by zero
        const denom = Math.max(p_i * p_j, 1e-10);
        R[i][j] = denom > 0 ? p_ij / denom : 1.0;
        R[j][i] = R[i][j];
      }
    }

    return R;
  }

  /**
   * Compute evidential weight W(k) for a set of k simultaneous flags.
   *
   * W(k) = -log(∏_{i∈F} Pr(F_i=1|H₀) · ∏_{i,j∈F, i<j} R_ij^(1/k))
   *
   * Intuition:
   *   - Start with independent weight: -∑ log Pr(F_i=1|H₀)
   *   - Penalize correlated flags: subtract log(R_ij) weight for each pair
   *   - Normalize by k to prevent double-counting
   *
   * @param {boolean[]} flags - Current flag vector
   * @returns {Object} Weight analysis
   */
  computeEvidentialWeight(flags) {
    const n = this.detectorIds.length;
    const R = this.correlationMatrix;

    // Identify which detectors flagged
    const flaggedIndices = [];
    for (let i = 0; i < n; i++) {
      if (flags[i] === 1) flaggedIndices.push(i);
    }
    const k = flaggedIndices.length;

    if (k === 0) {
      return {
        num_flags: 0,
        simple_weight: 0,
        evidential_weight: 0,
        correlation_penalty: 1.0,
        interpretation: 'NO_FLAGS'
      };
    }

    // Simple weight: -∑ log Pr(F_i=1|H₀)
    let simpleWeight = 0;
    for (const i of flaggedIndices) {
      const p_i = this.marginalFlagCounts[i] / this.totalObservations;
      simpleWeight += -Math.log2(Math.max(p_i, 1e-10));
    }

    // Correlation penalty: ∏_{i<j} R_ij^(1/k)
    // This is the geometric mean of pairwise correlation ratios
    let correlationPenaltyLog = 0;
    let numPairs = 0;
    for (let a = 0; a < k; a++) {
      for (let b = a + 1; b < k; b++) {
        const i = flaggedIndices[a];
        const j = flaggedIndices[b];
        const R_ij = R[i][j];
        // Penalty = log(R_ij) / k (distributed equally across k flags)
        correlationPenaltyLog += Math.log2(Math.max(R_ij, 1e-10)) / k;
        numPairs++;
      }
    }

    const correlationPenalty = Math.pow(2, correlationPenaltyLog);

    // Evidential weight = simple weight - correlation penalty (in bits)
    const evidentialWeight = simpleWeight - correlationPenaltyLog;

    // Classification
    let interpretation;
    if (k === 1) {
      interpretation = 'SINGLE_DETECTOR';
    } else if (correlationPenalty < 0.5) {
      interpretation = 'HIGHLY_INDEPENDENT_CONFIRMATION';
    } else if (correlationPenalty < 1.5) {
      interpretation = 'MODERATELY_CORRELATED';
    } else if (correlationPenalty < 3.0) {
      interpretation = 'SIGNIFICANTLY_CORRELATED';
    } else {
      interpretation = 'HIGHLY_CORRELATED_LOW_WEIGHT';
    }

    return {
      num_flags: k,
      flagged_detectors: flaggedIndices.map(i => this.detectorIds[i]),
      simple_weight: simpleWeight,
      correlation_penalty: correlationPenalty,
      evidential_weight: evidentialWeight,
      correlation_penalty_bits: correlationPenaltyLog,
      num_correlated_pairs: numPairs,
      interpretation
    };
  }

  /**
   * Identify detector clusters that are highly correlated.
   * Useful for diagnostics and detector pruning.
   *
   * @param {number} threshold - Correlation ratio threshold (default: 2.0)
   * @returns {Object[]} Clusters of correlated detectors
   */
  findCorrelatedClusters(threshold = 2.0) {
    const n = this.detectorIds.length;
    const R = this.correlationMatrix;
    const visited = new Array(n).fill(false);
    const clusters = [];

    // Build adjacency: (i,j) connected if R_ij > threshold
    const adjacency = Array.from({ length: n }, () => []);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        if (R[i][j] > threshold) {
          adjacency[i].push(j);
          adjacency[j].push(i);
        }
      }
    }

    // BFS to find connected components
    for (let i = 0; i < n; i++) {
      if (visited[i]) continue;
      const cluster = [];
      const queue = [i];
      visited[i] = true;

      while (queue.length > 0) {
        const v = queue.shift();
        cluster.push(v);
        for (const neighbor of adjacency[v]) {
          if (!visited[neighbor]) {
            visited[neighbor] = true;
            queue.push(neighbor);
          }
        }
      }

      if (cluster.length >= 2) {
        clusters.push({
          detectors: cluster.map(idx => this.detectorIds[idx]),
          size: cluster.length,
          average_correlation: this.computeAverageClusterCorrelation(cluster),
          recommendation: cluster.length >= 3 ?
            'PRUNE_REDUNDANT_DETECTORS' : 'MONITOR_CORRELATION'
        });
      }
    }

    return clusters;
  }

  /**
   * Compute average correlation within a cluster.
   *
   * @param {number[]} clusterIndices
   * @returns {number}
   */
  computeAverageClusterCorrelation(clusterIndices) {
    const R = this.correlationMatrix;
    let sum = 0;
    let count = 0;
    for (let a = 0; a < clusterIndices.length; a++) {
      for (let b = a + 1; b < clusterIndices.length; b++) {
        sum += R[clusterIndices[a]][clusterIndices[b]];
        count++;
      }
    }
    return count > 0 ? sum / count : 0;
  }

  /**
   * Compute the effective number of independent detectors.
   *
   * n_eff = n / (1 + (n-1) · ρ̄)  where ρ̄ is average off-diagonal correlation.
   *
   * This is the "effective sample size" concept applied to detectors.
   *
   * @returns {number} Effective number of independent detectors
   */
  effectiveIndependentDetectors() {
    const n = this.detectorIds.length;
    const R = this.correlationMatrix;

    // Average off-diagonal correlation ratio
    let sumOffDiagonal = 0;
    let countOffDiagonal = 0;
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        // Convert to correlation via: ρ = (R - 1) / max(R...)
        // R_ij = 1 means independent, R_ij > 1 means correlated
        const excessCorrelation = R[i][j] - 1; // Excess over independence
        sumOffDiagonal += excessCorrelation;
        countOffDiagonal++;
      }
    }

    const rhoBar = countOffDiagonal > 0 ? sumOffDiagonal / countOffDiagonal : 1;
    return n / (1 + (n - 1) * rhoBar);
  }

  /**
   * Dump diagnostic state.
   *
   * @returns {Object}
   */
  dumpDiagnostics() {
    return {
      detector_ids: this.detectorIds,
      total_observations: this.totalObservations,
      marginal_flag_counts: this.marginalFlagCounts,
      marginal_flag_probs: this.marginalFlagCounts.map(
        c => c / this.totalObservations
      ),
      correlation_matrix: this.correlationMatrix,
      effective_independent_detectors: this.effectiveIndependentDetectors(),
      correlated_clusters: this.findCorrelatedClusters(2.0)
    };
  }
}

module.exports = { FlagCorrelationFuser };
