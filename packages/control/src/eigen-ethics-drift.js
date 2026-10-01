/**
 * EigenEthicsDrift — Spectral Analysis for Ethics Covariance Prediction
 *
 * Tracks the 5×5 covariance matrix of ethical tradition scores over time.
 * Uses SVD decomposition and Schatten norms to predict ethics drift
 * BEFORE it manifests in individual decisions.
 *
 * No existing AI security tool does this. Standard ethics engines vote
 * statically per request. This catches the mathematical signature of
 * slow poisoning in the eigenvalue spectrum.
 *
 * Traditions: [utilitarian, kantian, virtue, care, ubuntu]
 */

'use strict';

const TRADITIONS = ['utilitarian', 'kantian', 'virtue', 'care', 'ubuntu'];
const WINDOW_SIZE = 50;       // rolling window of score vectors
const DRIFT_LAMBDA = 1.0;     // nuclear_norm > λ * frobenius_norm → alert
const MIN_SAMPLES = 10;       // minimum samples before drift detection activates

class EigenEthicsDrift {
  constructor(options = {}) {
    this.windowSize = options.windowSize || WINDOW_SIZE;
    this.lambda = options.lambda || DRIFT_LAMBDA;
    this.minSamples = options.minSamples || MIN_SAMPLES;
    this.history = [];          // array of [u, k, v, c, ub] score vectors
    this.prevCov = null;        // previous covariance matrix (5×5 flat)
    this.driftLog = [];         // log of detected drifts
  }

  /**
   * Record a new ethical evaluation vector.
   * @param {number[]} scores — [utilitarian, kantian, virtue, care, ubuntu] each 0.0–1.0
   */
  record(scores) {
    if (!Array.isArray(scores) || scores.length !== 5) {
      throw new Error('EigenEthicsDrift: scores must be array of 5 floats');
    }
    this.history.push([...scores]);
    if (this.history.length > this.windowSize) {
      this.history.shift();
    }
  }

  /**
   * Compute the 5×5 covariance matrix from the current window.
   * Returns flat array of 25 elements (row-major).
   */
  computeCovariance() {
    const n = this.history.length;
    if (n < this.minSamples) return null;

    // Compute means
    const mean = [0, 0, 0, 0, 0];
    for (const row of this.history) {
      for (let i = 0; i < 5; i++) mean[i] += row[i];
    }
    for (let i = 0; i < 5; i++) mean[i] /= n;

    // Compute covariance Σ[i][j] = (1/n) Σ (x_i - μ_i)(x_j - μ_j)
    const cov = new Float64Array(25);
    for (const row of this.history) {
      for (let i = 0; i < 5; i++) {
        for (let j = 0; j < 5; j++) {
          cov[i * 5 + j] += (row[i] - mean[i]) * (row[j] - mean[j]);
        }
      }
    }
    for (let k = 0; k < 25; k++) cov[k] /= n;

    return cov;
  }

  /**
   * Compute singular values of a 5×5 matrix using Jacobi SVD.
   * Pure JS implementation — no dependencies.
   * Returns sorted singular values [σ₁, σ₂, σ₃, σ₄, σ₅] descending.
   */
  singularValues(mat) {
    // Compute M = AᵀA (5×5 symmetric positive semi-definite)
    const mtm = new Float64Array(25);
    for (let i = 0; i < 5; i++) {
      for (let j = 0; j < 5; j++) {
        let sum = 0;
        for (let k = 0; k < 5; k++) {
          sum += mat[k * 5 + i] * mat[k * 5 + j]; // Aᵀ[i][k] * A[k][j]
        }
        mtm[i * 5 + j] = sum;
      }
    }

    // Jacobi eigenvalue algorithm for symmetric matrix
    const eigenvalues = this._jacobiEigenvalues(mtm, 5);
    // Singular values = sqrt(eigenvalues of AᵀA)
    return eigenvalues.map(ev => Math.sqrt(Math.max(0, ev))).sort((a, b) => b - a);
  }

  /**
   * Jacobi eigenvalue algorithm for n×n symmetric matrix.
   * Returns eigenvalues sorted descending.
   */
  _jacobiEigenvalues(S, n) {
    const A = new Float64Array(S); // work copy
    const maxIter = 100;

    for (let iter = 0; iter < maxIter; iter++) {
      // Find largest off-diagonal element
      let maxVal = 0, p = 0, q = 1;
      for (let i = 0; i < n; i++) {
        for (let j = i + 1; j < n; j++) {
          if (Math.abs(A[i * n + j]) > maxVal) {
            maxVal = Math.abs(A[i * n + j]);
            p = i; q = j;
          }
        }
      }
      if (maxVal < 1e-12) break; // converged

      // Compute rotation angle
      const app = A[p * n + p], aqq = A[q * n + q], apq = A[p * n + q];
      const theta = (aqq - app) / (2 * apq);
      const t = Math.sign(theta) / (Math.abs(theta) + Math.sqrt(theta * theta + 1));
      const c = 1 / Math.sqrt(t * t + 1);
      const s = t * c;

      // Apply Givens rotation
      for (let i = 0; i < n; i++) {
        const aip = A[i * n + p], aiq = A[i * n + q];
        A[i * n + p] = c * aip - s * aiq;
        A[i * n + q] = s * aip + c * aiq;
      }
      for (let j = 0; j < n; j++) {
        const apj = A[p * n + j], aqj = A[q * n + j];
        A[p * n + j] = c * apj - s * aqj;
        A[q * n + j] = s * apj + c * aqj;
      }
    }

    // Diagonal elements are eigenvalues
    const eigs = [];
    for (let i = 0; i < n; i++) eigs.push(A[i * n + i]);
    return eigs.sort((a, b) => b - a);
  }

  /**
   * Analyze current ethics drift state.
   * Returns { drifting, nuclearNorm, frobeniusNorm, ratio, targetedTradition, singularValues }
   */
  analyze() {
    const cov = this.computeCovariance();
    if (!cov) {
      return { drifting: false, reason: 'insufficient_samples', samples: this.history.length };
    }

    if (!this.prevCov) {
      this.prevCov = new Float64Array(cov);
      return { drifting: false, reason: 'first_window', samples: this.history.length };
    }

    // ΔΣ = Σ_t − Σ_{t-1}
    const delta = new Float64Array(25);
    for (let k = 0; k < 25; k++) delta[k] = cov[k] - this.prevCov[k];

    // SVD of ΔΣ
    const svals = this.singularValues(delta);

    // Schatten-1 norm (nuclear norm) = Σ|σᵢ|
    const nuclearNorm = svals.reduce((s, v) => s + Math.abs(v), 0);

    // Frobenius norm = sqrt(Σ σᵢ²)
    const frobeniusNorm = Math.sqrt(svals.reduce((s, v) => s + v * v, 0));

    // Drift ratio
    const ratio = frobeniusNorm > 1e-10 ? nuclearNorm / frobeniusNorm : 0;

    // Identify targeted tradition: max diagonal change in ΔΣ
    let maxDiagChange = 0, targetIdx = -1;
    for (let i = 0; i < 5; i++) {
      const change = Math.abs(delta[i * 5 + i]);
      if (change > maxDiagChange) {
        maxDiagChange = change;
        targetIdx = i;
      }
    }

    const drifting = ratio > this.lambda && nuclearNorm > 0.01;

    // Store for next comparison
    this.prevCov = new Float64Array(cov);

    const result = {
      drifting,
      nuclearNorm: +nuclearNorm.toFixed(6),
      frobeniusNorm: +frobeniusNorm.toFixed(6),
      ratio: +ratio.toFixed(4),
      targetedTradition: targetIdx >= 0 ? TRADITIONS[targetIdx] : null,
      targetedTraditionChange: +maxDiagChange.toFixed(6),
      singularValues: svals.map(v => +v.toFixed(6)),
      samples: this.history.length,
    };

    if (drifting) {
      this.driftLog.push({ ...result, timestamp: Date.now() });
    }

    return result;
  }

  /**
   * Get drift history.
   */
  getDriftLog() {
    return this.driftLog;
  }

  /**
   * Reset state.
   */
  reset() {
    this.history = [];
    this.prevCov = null;
    this.driftLog = [];
  }
}

module.exports = { EigenEthicsDrift, TRADITIONS };
