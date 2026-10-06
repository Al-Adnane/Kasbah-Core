'use strict';

/**
 * EigenEthicsDrift — Spectral Ethics Covariance Monitor
 * 
 * Tracks the covariance matrix of ethical tradition scores over time.
 * Detects drift in the ethical manifold using eigendecomposition.
 * Advisory only — never DENY.
 */

class EigenEthicsDrift {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 100;
    this.history = []; // array of {timestamp, scores: [5]}
    this.driftThreshold = options.driftThreshold || 0.15;
  }

  record(scores) {
    // scores: [utilitarian, kantian, virtue, care, ubuntu] each in [0,1]
    if (!Array.isArray(scores) || scores.length !== 5) return;
    this.history.push({
      timestamp: Date.now(),
      scores: scores.map(s => Math.max(0, Math.min(1, Number(s) || 0)))
    });
    if (this.history.length > this.windowSize) this.history.shift();
  }

  analyze() {
    if (this.history.length < 10) {
      return { available: false, reason: 'insufficient_history', drift: 0 };
    }

    // Compute covariance matrix of the 5D ethical scores
    const n = this.history.length;
    const dim = 5;
    const means = new Array(dim).fill(0);
    
    for (const h of this.history) {
      for (let i = 0; i < dim; i++) means[i] += h.scores[i];
    }
    for (let i = 0; i < dim; i++) means[i] /= n;

    // Covariance matrix
    const cov = Array(dim).fill(0).map(() => Array(dim).fill(0));
    for (const h of this.history) {
      for (let i = 0; i < dim; i++) {
        const di = h.scores[i] - means[i];
        for (let j = 0; j < dim; j++) {
          const dj = h.scores[j] - means[j];
          cov[i][j] += di * dj;
        }
      }
    }
    for (let i = 0; i < dim; i++) {
      for (let j = 0; j < dim; j++) {
        cov[i][j] /= (n - 1);
      }
    }

    // Power iteration for dominant eigenvalue (spectral radius)
    let v = new Array(dim).fill(1/Math.sqrt(dim));
    let lambda = 0;
    for (let iter = 0; iter < 20; iter++) {
      const Av = new Array(dim).fill(0);
      for (let i = 0; i < dim; i++) {
        for (let j = 0; j < dim; j++) Av[i] += cov[i][j] * v[j];
      }
      lambda = Math.sqrt(Av.reduce((a,b) => a + b*b, 0));
      if (lambda === 0) break;
      v = Av.map(x => x / lambda);
    }

    // Drift = change in dominant eigenvector direction over time
    // Split history in half and compare eigenvectors
    let drift = 0;
    if (n >= 20) {
      const mid = Math.floor(n / 2);
      const cov1 = this._covariance(this.history.slice(0, mid));
      const cov2 = this._covariance(this.history.slice(mid));
      const v1 = this._dominantEigenvector(cov1);
      const v2 = this._dominantEigenvector(cov2);
      if (v1 && v2) {
        // Cosine distance between eigenvectors
        const dot = v1.reduce((a,b,i) => a + b*v2[i], 0);
        drift = 1 - Math.abs(dot);
      }
    }

    const alert = drift > this.driftThreshold;
    return {
      available: true,
      drift,
      dominantEigenvalue: lambda,
      alert,
      advisory: alert ? 'WARN' : 'CLEAR',
      detail: `Ethical manifold drift: ${(drift*100).toFixed(1)}% (threshold: ${(this.driftThreshold*100).toFixed(1)}%)`
    };
  }

  _covariance(hist) {
    const n = hist.length, dim = 5;
    if (n < 2) return Array(dim).fill(0).map(() => Array(dim).fill(0));
    const means = new Array(dim).fill(0);
    for (const h of hist) for (let i = 0; i < dim; i++) means[i] += h.scores[i];
    for (let i = 0; i < dim; i++) means[i] /= n;
    const cov = Array(dim).fill(0).map(() => Array(dim).fill(0));
    for (const h of hist) {
      for (let i = 0; i < dim; i++) {
        const di = h.scores[i] - means[i];
        for (let j = 0; j < dim; j++) cov[i][j] += di * (h.scores[j] - means[j]);
      }
    }
    for (let i = 0; i < dim; i++) for (let j = 0; j < dim; j++) cov[i][j] /= (n-1);
    return cov;
  }

  _dominantEigenvector(cov) {
    const dim = 5;
    let v = new Array(dim).fill(1/Math.sqrt(dim));
    for (let iter = 0; iter < 20; iter++) {
      const Av = new Array(dim).fill(0);
      for (let i = 0; i < dim; i++) for (let j = 0; j < dim; j++) Av[i] += cov[i][j] * v[j];
      const norm = Math.sqrt(Av.reduce((a,b) => a + b*b, 0));
      if (norm === 0) return null;
      v = Av.map(x => x / norm);
    }
    return v;
  }
}

module.exports = { EigenEthicsDrift };