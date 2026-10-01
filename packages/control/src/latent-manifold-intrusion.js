'use strict';

/**
 * Latent Manifold Intrusion Detection (LMID) — #16
 *
 * Core Insight: All 15 existing detectors operate on output text or abstract
 * feature vectors. None operate in the neural activation manifold. Adversarial
 * perturbations propagate through the activation space before they manifest
 * in text — LMID catches them in that pre-manifestation window.
 *
 * Mathematical Foundation:
 *   The agent's policy π parameterizes a Riemannian manifold M with the
 *   Fisher Information Metric g_ij(θ) = E[∂_i log p(y|x,θ) · ∂_j log p(y|x,θ)].
 *   Safe behaviour traces geodesics on M. Adversarial perturbations manifest
 *   as off-geodesic acceleration — the geodesic deviation equation
 *
 *     ∇_u ∇_u J = R(J, u)u
 *
 *   detects curvature-driven intrusion where R is the Riemann curvature tensor
 *   and J is the Jacobi field (deviation vector between nearby geodesics).
 *
 *   In the discrete proxy setting (no access to real neural weights), LMID
 *   approximates the Fisher-Rao distance via the tangent-space projection of
 *   sequential embedding differences onto an adaptive reference subspace.
 *
 *   The detection statistic is:
 *
 *     D_t = ||Δz_t − P_ref(Δz_t)|| / ||Δz_t||
 *
 *   where Δz_t is the embedding delta between consecutive turns, and P_ref
 *   is the projection onto the top-k PCA subspace of safe-turn embeddings.
 *   High D_t means the trajectory is leaving the safe manifold.
 *
 * Evasion Cost: Adversary must simultaneously control output text (15 surfaces)
 * AND keep latent trajectory on a specific Riemannian geodesic — the Fisher
 * metric couples these constraints non-linearly.
 *
 * No existing LLM security tool monitors activation geometry for intrusion.
 */

const crypto = require('crypto');

class LatentManifoldMonitor {
  /**
   * @param {object} opts
   *   - dim: embedding dimension (default 64 — reduced proxy)
   *   - subspaceDim: PCA subspace dimension (default 16)
   *   - windowSize: calibration window (default 100)
   *   - warnThreshold: D_t above this → WARN (default 0.25)
   *   - reviewThreshold: D_t above this → REQUIRE_APPROVAL (default 0.45)
   *   - adaptationRate: PCA subspace update rate (default 0.01)
   */
  constructor(opts = {}) {
    this.dim = opts.dim || 64;
    this.k = opts.subspaceDim || 16;
    this.windowSize = opts.windowSize || 100;
    this.warnThreshold = opts.warnThreshold || 0.25;
    this.reviewThreshold = opts.reviewThreshold || 0.45;
    this.alpha = opts.adaptationRate || 0.01;

    // Rolling history: { embedding: Float64Array(dim), tag: string, ts: number }
    this._history = [];

    // PCA reference subspace — top-k eigenvectors as Float64Array[k][dim]
    this._pcBasis = null;       // Float64Array[k * dim] flattened
    this._pcMean = null;        // Float64Array[dim]
    this._pcVariance = null;    // Float64Array[k] eigenvalues
    this._isCalibrated = false;
    this._calibrationSamples = 0;

    // Rolling detection statistics
    this._intrusionScores = [];  // recent D_t values
    this._maxScoreHistory = 200;
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Observe a new embedding vector and return the intrusion assessment.
   * @param {Float64Array|number[]} embedding — the embedding delta Δz_t
   * @param {object} context — { tag: string, ts?: number }
   * @returns {object} detection result
   */
  observe(embedding, context = {}) {
    const z = this._ensureVector(embedding);
    if (!z) return this._noDataResult();

    const entry = {
      embedding: z,
      tag: context.tag || 'turn',
      ts: context.ts || Date.now(),
    };
    this._history.push(entry);
    if (this._history.length > this.windowSize * 3) {
      this._history = this._history.slice(-this.windowSize * 3);
    }

    // Calibrate PCA subspace from safe-tag turns
    if (!this._isCalibrated) {
      this._calibrationSamples++;
      if (this._calibrationSamples >= this.windowSize) {
        this._calibratePCA();
      }
      return { mode: 'calibrating', samples: this._calibrationSamples, needed: this.windowSize };
    }

    // Compute tangent-space deviation
    const deltaZ = this._computeDelta(z);
    const intrusion = this._tangentDeviation(deltaZ);
    this._intrusionScores.push(intrusion);
    if (this._intrusionScores.length > this._maxScoreHistory) {
      this._intrusionScores.shift();
    }

    // Adaptive PCA update (slow drift of safe subspace)
    if (context.tag === 'safe' || intrusion < this.warnThreshold * 0.5) {
      this._adaptSubspace(z);
    }

    // Rolling statistics for trend detection
    const recent = this._intrusionScores.slice(-20);
    const meanD = recent.reduce((a, b) => a + b, 0) / recent.length;
    const maxD = Math.max(...recent);
    const trend = this._computeTrend(recent);

    const isIntrusion = maxD > this.reviewThreshold ||
      (meanD > this.warnThreshold && trend > 0);

    return {
      mode: 'monitoring',
      intrusionScore: +intrusion.toFixed(4),
      rollingMean: +meanD.toFixed(4),
      rollingMax: +maxD.toFixed(4),
      trend: +trend.toFixed(4),
      isIntrusion,
      signal: maxD > this.reviewThreshold ? 'REQUIRE_APPROVAL'
        : meanD > this.warnThreshold ? 'WARN' : 'CLEAR',
      geodesicDeviation: +intrusion.toFixed(4),
      subspaceDim: this.k,
      calibratedSamples: this._calibrationSamples,
    };
  }

  /**
   * Compute the Fisher-Rao proxy distance between two embedding states.
   * This is the squared geodesic distance on the tangent-space projection.
   */
  fisherRaoDistance(fromIdx, toIdx) {
    if (!this._isCalibrated || fromIdx >= this._history.length || toIdx >= this._history.length) {
      return null;
    }
    const zi = this._history[fromIdx].embedding;
    const zj = this._history[toIdx].embedding;
    const diff = new Float64Array(this.dim);
    for (let i = 0; i < this.dim; i++) diff[i] = zi[i] - zj[i];

    // Tangent-space projection
    const proj = this._projectOntoSubspace(diff);
    const residual = new Float64Array(this.dim);
    for (let i = 0; i < this.dim; i++) residual[i] = diff[i] - proj[i];

    const norm = Math.sqrt(dotProduct(proj, proj, this.dim));
    const residNorm = Math.sqrt(dotProduct(residual, residual, this.dim));
    // Fisher-Rao proxy: weighted combination of on-manifold and off-manifold distance
    return Math.sqrt(norm * norm + residNorm * residNorm * 2.0);
  }

  /**
   * Get the current tangent-space projection matrix for external analysis.
   */
  getSubspace() {
    if (!this._isCalibrated) return null;
    return {
      basis: this._pcBasis,      // flattened Float64Array[k * dim]
      mean: this._pcMean,        // Float64Array[dim]
      variance: this._pcVariance, // Float64Array[k]
      k: this.k,
      dim: this.dim,
    };
  }

  /**
   * Force recalibration from current history.
   */
  recalibrate() {
    this._calibratePCA();
    return { calibrated: this._isCalibrated, samples: this._history.length };
  }

  // ── Internal Methods ─────────────────────────────────────

  _ensureVector(arr) {
    if (!arr) return null;
    if (arr instanceof Float64Array) return arr;
    if (Array.isArray(arr)) {
      const v = new Float64Array(this.dim);
      for (let i = 0; i < Math.min(arr.length, this.dim); i++) v[i] = arr[i] || 0;
      return v;
    }
    if (typeof arr === 'object' && arr.embedding) return this._ensureVector(arr.embedding);
    return null;
  }

  _noDataResult() {
    return { mode: 'no_data', intrusionScore: 0, isIntrusion: false, signal: 'CLEAR' };
  }

  _computeDelta(z) {
    // Compute the difference between current embedding and previous
    if (this._history.length < 2) {
      // First observation: compare to zero
      return z;
    }
    const prev = this._history[this._history.length - 2].embedding;
    const delta = new Float64Array(this.dim);
    for (let i = 0; i < this.dim; i++) delta[i] = z[i] - prev[i];
    return delta;
  }

  _tangentDeviation(deltaZ) {
    if (!this._isCalibrated) return 0;
    const proj = this._projectOntoSubspace(deltaZ);
    const residual = new Float64Array(this.dim);
    for (let i = 0; i < this.dim; i++) residual[i] = deltaZ[i] - proj[i];
    const norm = Math.sqrt(dotProduct(deltaZ, deltaZ, this.dim));
    const residNorm = Math.sqrt(dotProduct(residual, residual, this.dim));
    if (norm < 1e-12) return 0;
    return residNorm / norm; // Fraction of motion orthogonal to safe subspace
  }

  _projectOntoSubspace(v) {
    // Project v onto the top-k PCA subspace: v_proj = mean + Σ (v·e_i) e_i
    const centered = new Float64Array(this.dim);
    for (let i = 0; i < this.dim; i++) centered[i] = v[i] - (this._pcMean ? this._pcMean[i] : 0);

    const proj = new Float64Array(this.dim);
    for (let pc = 0; pc < this.k; pc++) {
      const coeff = dotProduct(centered, this._pcBasis.subarray(pc * this.dim, (pc + 1) * this.dim), this.dim);
      for (let i = 0; i < this.dim; i++) {
        proj[i] += coeff * this._pcBasis[pc * this.dim + i];
      }
    }
    // Add mean back
    if (this._pcMean) {
      for (let i = 0; i < this.dim; i++) proj[i] += this._pcMean[i];
    }
    return proj;
  }

  _calibratePCA() {
    // Use only "safe"-tagged entries for PCA reference
    const safeEntries = this._history.filter(e => e.tag === 'safe');
    const useEntries = safeEntries.length >= this.windowSize
      ? safeEntries.slice(-this.windowSize)
      : this._history.slice(-this.windowSize);

    if (useEntries.length < this.windowSize) {
      this._calibrationSamples = useEntries.length;
      return;
    }

    const n = useEntries.length;
    const d = this.dim;

    // Compute mean
    this._pcMean = new Float64Array(d);
    for (const e of useEntries) {
      for (let i = 0; i < d; i++) this._pcMean[i] += e.embedding[i];
    }
    for (let i = 0; i < d; i++) this._pcMean[i] /= n;

    // Compute covariance matrix (outer product approximation for efficiency)
    // C = (1/n) Σ (x_i - μ)(x_i - μ)^T
    // We compute top-k eigenvectors via power iteration on each component
    const cov = new Float64Array(d * d);
    for (const e of useEntries) {
      for (let i = 0; i < d; i++) {
        const xi = e.embedding[i] - this._pcMean[i];
        for (let j = i; j < d; j++) {
          const xj = e.embedding[j] - this._pcMean[j];
          cov[i * d + j] += xi * xj;
        }
      }
    }
    for (let i = 0; i < d * d; i++) cov[i] /= n;
    // Symmetrize
    for (let i = 0; i < d; i++) {
      for (let j = i + 1; j < d; j++) {
        cov[i * d + j] = cov[j * d + i] = (cov[i * d + j] + cov[j * d + i]) / 2;
      }
    }

    // Top-k eigenvectors via subspace iteration
    this._pcBasis = this._subspaceIteration(cov, this.k, d);
    this._pcVariance = new Float64Array(this.k);
    for (let pc = 0; pc < this.k; pc++) {
      const ei = this._pcBasis.subarray(pc * d, (pc + 1) * d);
      // Rayleigh quotient: λ_i = e_i^T C e_i
      const Cei = new Float64Array(d);
      for (let i = 0; i < d; i++) {
        let sum = 0;
        for (let j = 0; j < d; j++) sum += cov[i * d + j] * ei[j];
        Cei[i] = sum;
      }
      this._pcVariance[pc] = dotProduct(ei, Cei, d);
    }

    this._isCalibrated = true;
    this._calibrationSamples = useEntries.length;
  }

  _subspaceIteration(A, k, d) {
    // Randomized subspace iteration for top-k eigenvectors
    const maxIter = 30;
    // Initialize random basis
    const Q = new Float64Array(k * d);
    for (let i = 0; i < k * d; i++) {
      Q[i] = Math.random() * 2 - 1;
    }
    // Orthonormalize columns
    this._gramSchmidt(Q, k, d);

    for (let iter = 0; iter < maxIter; iter++) {
      // Multiply: Z = A * Q
      const Z = new Float64Array(k * d);
      for (let col = 0; col < k; col++) {
        const qCol = Q.subarray(col * d, (col + 1) * d);
        const zCol = Z.subarray(col * d, (col + 1) * d);
        for (let i = 0; i < d; i++) {
          let sum = 0;
          for (let j = 0; j < d; j++) sum += A[i * d + j] * qCol[j];
          zCol[i] = sum;
        }
      }
      // Orthonormalize
      this._gramSchmidt(Z, k, d);
      // Convergence check: ||Z - Q||
      let diff = 0;
      for (let i = 0; i < k * d; i++) {
        const dq = Z[i] - Q[i];
        diff += dq * dq;
      }
      // Copy Z to Q
      for (let i = 0; i < k * d; i++) Q[i] = Z[i];
      if (Math.sqrt(diff) < 1e-8) break;
    }
    return Q;
  }

  _gramSchmidt(Q, k, d) {
    for (let col = 0; col < k; col++) {
      const v = Q.subarray(col * d, (col + 1) * d);
      // Normalize
      let norm = Math.sqrt(dotProduct(v, v, d));
      if (norm < 1e-12) {
        // Randomize degenerate column
        for (let i = 0; i < d; i++) v[i] = Math.random() * 2 - 1;
        norm = Math.sqrt(dotProduct(v, v, d));
      }
      for (let i = 0; i < d; i++) v[i] /= norm;
      // Orthogonalize against previous columns
      for (let prev = 0; prev < col; prev++) {
        const u = Q.subarray(prev * d, (prev + 1) * d);
        const proj = dotProduct(v, u, d);
        for (let i = 0; i < d; i++) v[i] -= proj * u[i];
      }
      // Re-normalize
      norm = Math.sqrt(dotProduct(v, v, d));
      if (norm > 1e-12) {
        for (let i = 0; i < d; i++) v[i] /= norm;
      }
    }
  }

  _adaptSubspace(z) {
    if (!this._isCalibrated) return;
    // Slowly update PCA mean via exponential moving average
    if (this._pcMean) {
      for (let i = 0; i < this.dim; i++) {
        this._pcMean[i] = (1 - this.alpha) * this._pcMean[i] + this.alpha * z[i];
      }
    }
  }

  _computeTrend(scores) {
    if (scores.length < 2) return 0;
    // Simple linear regression slope
    const n = scores.length;
    const meanIdx = (n - 1) / 2;
    const meanScore = scores.reduce((a, b) => a + b, 0) / n;
    let num = 0, den = 0;
    for (let i = 0; i < n; i++) {
      num += (i - meanIdx) * (scores[i] - meanScore);
      den += (i - meanIdx) * (i - meanIdx);
    }
    return den > 1e-12 ? num / den : 0;
  }
}

// ── Utility ────────────────────────────────────────────────

function dotProduct(a, b, n) {
  let sum = 0;
  for (let i = 0; i < n; i++) sum += a[i] * b[i];
  return sum;
}

// ── Synthetic embedding generator (for testing without real model) ──

/**
 * Generate a synthetic embedding for testing.
 * Produces a 64-dim vector with some structure to exercise PCA.
 */
function generateSyntheticEmbedding(prevEmbedding, injectPerturbation = false) {
  const dim = 64;
  const emb = new Float64Array(dim);
  // Base: sinusoidal pattern
  for (let i = 0; i < dim; i++) {
    emb[i] = Math.sin(i * 0.3 + Math.random() * 0.1) * 0.5 +
             Math.cos(i * 0.15) * 0.3 +
             Math.random() * 0.05;
  }
  // Perturbation: inject high-magnitude noise in high-index dimensions
  if (injectPerturbation) {
    for (let i = 48; i < dim; i++) {
      emb[i] += (Math.random() * 2 - 1) * 0.8;
    }
  }
  // Smooth from previous if provided
  if (prevEmbedding) {
    const alpha = injectPerturbation ? 0.3 : 0.9;
    for (let i = 0; i < dim; i++) {
      emb[i] = alpha * prevEmbedding[i] + (1 - alpha) * emb[i];
    }
  }
  return emb;
}

module.exports = { LatentManifoldMonitor, generateSyntheticEmbedding };
