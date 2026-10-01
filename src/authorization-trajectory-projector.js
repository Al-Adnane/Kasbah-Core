/**
 * Authorization Trajectory Projector (#24)
 *
 * Projects the LLM's tool-call trajectory forward to predict whether it will
 * cross the authorization boundary — before it actually does.
 *
 * PROBLEM: "Boiling the frog" attacks. Each step is individually benign —
 * the score never crosses the threshold. But the cumulative trajectory
 * drifts toward the boundary. Single-turn detectors miss this because
 * they only look at the CURRENT state, not the DIRECTION and VELOCITY.
 *
 * APPROACH:
 *  1. Fit a linear dynamical system (delay-embedded state space) to the
 *     last K tool-call governance scores.
 *  2. Compute the Lyapunov exponent λ from the fitted Jacobian matrix.
 *     λ > 0 → trajectory is diverging (chaotic/unstable)
 *  3. Project the trajectory forward N steps using the fitted model.
 *     If projected path crosses the warning threshold within the horizon,
 *     flag it NOW — don't wait for it to actually cross.
 *  4. Compute the "approach angle" — trajectory direction relative to
 *     the authorization boundary normal. Acute angle + positive λ = danger.
 *
 * MATHEMATICAL FOUNDATION:
 *  - Delay embedding (Takens' theorem): reconstructs state space from
 *    a scalar time series of governance scores.
 *  - Lyapunov exponent: measures the exponential rate of divergence of
 *    nearby trajectories. Standard in dynamical systems theory.
 *  - Linear autoregressive model (AR): fits s(t+1) = Σ α_i · s(t-i) + ε_t
 *
 * DEFENSIBLE: Lyapunov exponent computation on time series is standard
 * in physics, biology, and finance. Applying it to governance score
 * trajectories for early warning is a novel application with a clear
 * security motivation.
 *
 * @module authorization-trajectory-projector
 */
'use strict';

class AuthorizationTrajectoryProjector {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 20;       // K recent scores for model fitting
    this.projectionHorizon = options.projectionHorizon || 5; // N steps forward
    this.lyapunovThreshold = options.lyapunovThreshold || 0.01; // λ > 0.01 = diverging
    this.warnThreshold = options.warnThreshold || 0.35;
    this.reviewThreshold = options.reviewThreshold || 0.60;
    this.embeddingDimension = options.embeddingDimension || 3; // m for delay embedding
    this.tau = options.tau || 1;                           // delay τ
    this.scoreHistory = [];     // sliding window of governance scores
    this.derivatives = [];      // first differences (velocity)
    this.projections = [];      // historical projections for backtesting
  }

  /**
   * Feed a new governance score into the trajectory tracker.
   * @param {number} score — composite governance score for this turn (0-1)
   * @param {Object} context — { turnId, tools, ... }
   * @returns {Object} trajectory projection result
   */
  project(score, context = {}) {
    this.scoreHistory.push(score);
    if (this.scoreHistory.length > this.windowSize * 2) {
      this.scoreHistory.shift();
    }

    // Compute velocity (first derivative)
    if (this.scoreHistory.length >= 2) {
      const last = this.scoreHistory.length - 1;
      const v = this.scoreHistory[last] - this.scoreHistory[last - 1];
      this.derivatives.push(v);
      if (this.derivatives.length > this.windowSize) {
        this.derivatives.shift();
      }
    }

    // Need enough data for model fitting
    if (this.scoreHistory.length < this.windowSize) {
      return {
        mode: 'accumulating',
        samples: this.scoreHistory.length,
        needed: this.windowSize,
      };
    }

    // Fit AR model and compute Lyapunov exponent
    const arCoeffs = this._fitARModel();
    const lyapunovExponent = this._estimateLyapunov(arCoeffs);
    const isDiverging = lyapunovExponent > this.lyapunovThreshold;

    // Project forward N steps
    const recent = this.scoreHistory.slice(-this.windowSize);
    const trajectory = this._projectTrajectory(recent, arCoeffs, this.projectionHorizon);

    // Check boundary crossing
    const boundaryCrossing = this._detectBoundaryCrossing(trajectory);

    // Compute approach angle (trajectory direction vs boundary normal)
    const approachAngle = this._computeApproachAngle(trajectory);

    const signal = this._classifySignal(
      lyapunovExponent, isDiverging, boundaryCrossing, approachAngle,
      score, trajectory
    );

    this.projections.push({
      lyapunovExponent,
      isDiverging,
      boundaryCrossing,
      approachAngle,
      projectedMax: trajectory.maxScore,
      signal: signal.signal,
      timestamp: context.timestamp || Date.now(),
    });

    return {
      mode: 'monitoring',
      lyapunovExponent: +lyapunovExponent.toFixed(6),
      isDiverging,
      boundaryCrossing: boundaryCrossing.crossesWithin,
      projectedMaxScore: +trajectory.maxScore.toFixed(4),
      projectedCrossStep: boundaryCrossing.step,
      approachAngle: +approachAngle.toFixed(3),
      trajectory: trajectory.values.map(v => +v.toFixed(4)),
      currentScore: score,
      signal: signal.signal,
      severity: signal.severity,
    };
  }

  /**
   * Fit AR(p) model to score history.
   * s(t) = α₁·s(t-1) + α₂·s(t-2) + ... + αₚ·s(t-p) + ε
   *
   * Uses least squares: solves X^T X α = X^T y
   */
  _fitARModel() {
    const p = Math.min(this.embeddingDimension, this.scoreHistory.length - 1);
    const n = this.scoreHistory.length - p;

    // Build design matrix X and target vector y
    const X = [];
    const y = [];
    for (let t = p; t < this.scoreHistory.length; t++) {
      const row = [];
      for (let j = 1; j <= p; j++) {
        row.push(this.scoreHistory[t - j]);
      }
      X.push(row);
      y.push(this.scoreHistory[t]);
    }

    // Solve via normal equations: α = (X^T X)^(-1) X^T y
    // For small p, compute directly
    const XTX = Array(p).fill(null).map(() => Array(p).fill(0));
    const XTy = Array(p).fill(0);

    for (let i = 0; i < n; i++) {
      for (let a = 0; a < p; a++) {
        XTy[a] += X[i][a] * y[i];
        for (let b = 0; b < p; b++) {
          XTX[a][b] += X[i][a] * X[i][b];
        }
      }
    }

    // Add small regularization to ensure invertibility
    for (let i = 0; i < p; i++) XTX[i][i] += 1e-8;

    const alpha = this._solveLinearSystem(XTX, XTy);
    return alpha || Array(p).fill(0);
  }

  /**
   * Estimate Lyapunov exponent from AR coefficients.
   * For a linear system, the Lyapunov exponents are the logarithms of the
   * eigenvalues of the companion matrix. The largest LE dominates.
   *
   * Companion matrix for AR(p):
   *   [α₁  α₂  ...  αₚ]
   *   [1   0   ...  0  ]
   *   [0   1   ...  0  ]
   *   ...
   */
  _estimateLyapunov(arCoeffs) {
    const p = arCoeffs.length;
    if (p === 0) return 0;

    if (p === 1) {
      // AR(1): eigenvalue = α₁, LE = ln(|α₁|)
      return Math.log(Math.max(Math.abs(arCoeffs[0]), 1e-10));
    }

    // For p>1, compute dominant eigenvalue via power iteration on companion matrix
    // Faster than full eigendecomposition for small matrices
    const maxEigenvalue = this._dominantEigenvalue(arCoeffs);
    return Math.log(Math.max(maxEigenvalue, 1e-10));
  }

  _dominantEigenvalue(arCoeffs) {
    const p = arCoeffs.length;
    // Power iteration
    let v = Array(p).fill(1);
    for (let iter = 0; iter < 100; iter++) {
      // Multiply v by companion matrix C
      const w = Array(p).fill(0);
      for (let i = 0; i < p; i++) {
        if (i === 0) {
          for (let j = 0; j < p; j++) w[i] += arCoeffs[j] * v[j];
        } else {
          w[i] = v[i - 1];
        }
      }
      // Normalize
      let norm = 0;
      for (let i = 0; i < p; i++) norm += w[i] * w[i];
      norm = Math.sqrt(norm);
      if (norm < 1e-15) break;
      for (let i = 0; i < p; i++) v[i] = w[i] / norm;
    }
    // Rayleigh quotient to get eigenvalue
    const Cv = Array(p).fill(0);
    for (let i = 0; i < p; i++) {
      if (i === 0) {
        for (let j = 0; j < p; j++) Cv[i] += arCoeffs[j] * v[j];
      } else {
        Cv[i] = v[i - 1];
      }
    }
    let num = 0, den = 0;
    for (let i = 0; i < p; i++) {
      num += v[i] * Cv[i];
      den += v[i] * v[i];
    }
    return den > 1e-15 ? Math.abs(num / den) : 0;
  }

  /**
   * Project the trajectory forward N steps using the AR model.
   */
  _projectTrajectory(recent, arCoeffs, horizon) {
    const p = arCoeffs.length;
    const values = [...recent];
    let maxScore = Math.max(...recent);

    for (let step = 0; step < horizon; step++) {
      // s(t+1) = Σ αⱼ · s(t-j+1)
      let pred = 0;
      for (let j = 0; j < p; j++) {
        pred += arCoeffs[j] * values[values.length - 1 - j];
      }
      // Clip to [0, 1]
      pred = Math.max(0, Math.min(1, pred));
      values.push(pred);
      if (pred > maxScore) maxScore = pred;
    }

    return { values: values.slice(-horizon), maxScore, all: values };
  }

  _detectBoundaryCrossing(trajectory) {
    let crossesWithin = false;
    let step = -1;
    let crossesWarn = false;
    let crossesReview = false;

    for (let i = 0; i < trajectory.values.length; i++) {
      if (trajectory.values[i] > this.warnThreshold) {
        crossesWarn = true;
        if (step < 0) step = i + 1;
      }
      if (trajectory.values[i] > this.reviewThreshold) {
        crossesReview = true;
        if (step < 0) step = i + 1;
      }
    }

    crossesWithin = crossesWarn || crossesReview;
    return { crossesWithin, step, crossesWarn, crossesReview };
  }

  _computeApproachAngle(trajectory) {
    // Approach angle = arctan(trajectory slope) relative to horizontal
    const vals = trajectory.values;
    if (vals.length < 2) return 0;

    const dx = vals.length - 1;
    const dy = vals[vals.length - 1] - vals[0];
    return Math.atan2(dy, dx) * (180 / Math.PI);
  }

  _classifySignal(lyapunovExp, isDiverging, bCross, angle, currentScore, trajectory) {
    // Current score already above warn → immediate escalation
    if (currentScore > this.warnThreshold) {
      if (currentScore > this.reviewThreshold) {
        return { signal: 'REQUIRE_APPROVAL', severity: 1.0 };
      }
      return { signal: 'WARN', severity: 0.7 };
    }

    // Lyapunov divergence + boundary crossing predicted → escalate now
    if (isDiverging && bCross.crossesWithin) {
      const severity = Math.min(1.0,
        0.3 + 0.3 * (lyapunovExp / 0.1) + 0.4 * (bCross.crossesReview ? 1 : 0.5)
      );
      if (bCross.crossesReview || severity > 0.7) {
        return { signal: 'REQUIRE_APPROVAL', severity };
      }
      return { signal: 'WARN', severity };
    }

    // Diverging but not crossing → watch
    if (isDiverging) {
      return { signal: 'WARN', severity: 0.4 };
    }

    // Converging or stable → clear
    if (trajectory.maxScore < this.warnThreshold * 0.8) {
      return { signal: 'CLEAR', severity: 0 };
    }

    return { signal: 'CLEAR', severity: 0.1 };
  }

  /**
   * Solve linear system Ax = b using Gaussian elimination (small systems).
   */
  _solveLinearSystem(A, b) {
    const n = b.length;
    const M = A.map((row, i) => [...row, b[i]]);

    for (let col = 0; col < n; col++) {
      // Partial pivot
      let maxRow = col;
      for (let row = col + 1; row < n; row++) {
        if (Math.abs(M[row][col]) > Math.abs(M[maxRow][col])) maxRow = row;
      }
      if (Math.abs(M[maxRow][col]) < 1e-12) return null;
      [M[col], M[maxRow]] = [M[maxRow], M[col]];

      // Eliminate below
      for (let row = col + 1; row < n; row++) {
        const factor = M[row][col] / M[col][col];
        for (let j = col; j <= n; j++) M[row][j] -= factor * M[col][j];
      }
    }

    // Back substitution
    const x = Array(n).fill(0);
    for (let i = n - 1; i >= 0; i--) {
      x[i] = M[i][n];
      for (let j = i + 1; j < n; j++) x[i] -= M[i][j] * x[j];
      x[i] /= M[i][i];
    }
    return x;
  }

  reset() {
    this.scoreHistory = [];
    this.derivatives = [];
    this.projections = [];
  }
}

module.exports = { AuthorizationTrajectoryProjector };
