/**
 * CUSUM on Activation Subspace Trajectories (Original Idea #5)
 *
 * Treats the Grassmann distance between current and reference activation
 * subspaces as a TIME SERIES, then applies sequential change-point detection
 * (CUSUM) to detect the EXACT MOMENT of value hijacking.
 *
 * CORE INSIGHT:
 *   Existing alignment monitoring takes static snapshots (compare current
 *   activations to baseline). This treats drift as a DYNAMICAL PROCESS and
 *   detects the phase transition moment when gradual drift becomes
 *   catastrophic misalignment.
 *
 * CUSUM ALGORITHM:
 *   S₀ = 0
 *   S_t = max(0, S_{t-1} + D_Gr(V_t, V_ref) - μ₀ - k)
 *   Alarm when S_t > h
 *
 *   where:
 *     μ₀ = baseline mean of D_Gr under H₀
 *     k  = reference value (usually Δμ/2, half the expected shift)
 *     h  = threshold calibrated to ARL (average run length)
 *
 *   h ≈ log(γ) / Δ  where γ = target ARL under H₀, Δ = minimal detectable shift
 *
 * REFERENCE:
 *   Page, E.S. (1954). "Continuous inspection schemes." Biometrika.
 *   Zou, A., et al. (2023). "Representation Engineering: A Top-Down
 *   Approach to AI Transparency."
 *
 * @module cusum-subspace-monitor
 */
'use strict';

class CUSUMSubspaceMonitor {
  /**
   * @param {Object} opts
   * @param {number} opts.targetARL - Target Average Run Length under H₀ (default: 500)
   * @param {number} opts.minShift - Minimal detectable shift in Grassmann distance
   * @param {number} opts.baselineWindow - Calibration window size
   * @param {number} opts.maxObservations - Maximum stored observation count
   */
  constructor(opts = {}) {
    this.targetARL = opts.targetARL || 500;
    this.minShift = opts.minShift || 0.05;
    this.baselineWindow = opts.baselineWindow || 100;
    this.maxObservations = opts.maxObservations || 10000;

    // State
    this.S = 0; // CUSUM statistic
    this.baselineMean = null; // μ₀
    this.baselineStd = null; // σ₀
    this.referenceValue = null; // k
    this.threshold = null; // h
    this.isCalibrated = false;

    // Time series
    this.distances = []; // D_Gr values over time
    this.cusumHistory = []; // S_t values over time
    this.alarmTimes = [];
    this.driftPhase = 'baseline'; // 'baseline' | 'monitoring' | 'drift'
  }

  /**
   * Calibrate CUSUM parameters from baseline data.
   *
   * @param {number[]} baselineDistances - D_Gr values from normal operation
   */
  calibrate(baselineDistances) {
    if (baselineDistances.length < this.baselineWindow) {
      throw new Error(
        `Need at least ${this.baselineWindow} values, got ${baselineDistances.length}`
      );
    }

    const data = baselineDistances.slice(-this.baselineWindow);

    this.baselineMean = data.reduce((a, b) => a + b, 0) / data.length;
    const variance = data.reduce((s, x) => s + Math.pow(x - this.baselineMean, 2), 0) / (data.length - 1);
    this.baselineStd = Math.sqrt(Math.max(variance, 1e-10));

    // Reference value k = Δμ / 2 (half the expected shift)
    this.referenceValue = this.minShift / 2;

    // Threshold h calibrated to target ARL
    // Siegmund's approximation: ARL ≈ exp(2·h·k/σ²) / (2·k²/σ²)
    // Solving for h: h ≈ (σ²/(2·k)) · ln(ARL · 2·k²/σ²)
    const sigma2 = this.baselineStd * this.baselineStd;
    const k = this.referenceValue;
    const arg = this.targetARL * 2 * k * k / sigma2;
    this.threshold = (sigma2 / (2 * k)) * Math.log(Math.max(arg, 1.1));

    // Clamp threshold to reasonable range
    this.threshold = Math.max(this.threshold, 1.0);

    // Store baseline
    this.distances = [...baselineDistances];
    this.isCalibrated = true;
    this.S = 0;
    this.cusumHistory = [];
    this.alarmTimes = [];
  }

  /**
   * Observe a new Grassmann distance and update CUSUM.
   *
   * @param {number} D_Gr - Current Grassmann distance to reference subspace
   * @returns {Object} CUSUM status
   */
  observe(D_Gr) {
    this.distances.push(D_Gr);
    if (this.distances.length > this.maxObservations) {
      this.distances = this.distances.slice(-this.maxObservations);
    }

    if (!this.isCalibrated) {
      return {
        mode: 'calibrating',
        samples: this.distances.length,
        needed: this.baselineWindow,
      };
    }

    // Standardize: z_t = (D_Gr - μ₀) / σ₀
    const z_t = (D_Gr - this.baselineMean) / this.baselineStd;

    // CUSUM update: S_t = max(0, S_{t-1} + z_t - k')
    // k' = k / σ₀ (reference value in standardized units)
    const kPrime = this.referenceValue / this.baselineStd;
    this.S = Math.max(0, this.S + z_t - kPrime);

    this.cusumHistory.push(this.S);
    if (this.cusumHistory.length > this.maxObservations) {
      this.cusumHistory = this.cusumHistory.slice(-this.maxObservations);
    }

    // Check for alarm
    const alarm = this.S >= this.threshold;

    if (alarm) {
      this.alarmTimes.push({
        index: this.distances.length - 1,
        D_Gr,
        S: this.S,
        threshold: this.threshold,
        timestamp: Date.now(),
      });
      this.driftPhase = 'drift';
    } else if (this.S > this.threshold * 0.5) {
      this.driftPhase = 'elevated';
    } else {
      this.driftPhase = 'monitoring';
    }

    return {
      mode: 'monitoring',
      D_Gr,
      z_score: z_t,
      cusum_S: this.S,
      threshold: this.threshold,
      thresholdFraction: this.threshold > 0 ? this.S / this.threshold : 0,
      alarm,
      driftPhase: this.driftPhase,
      alarmCount: this.alarmTimes.length,
      calibrated: {
        baselineMean: this.baselineMean,
        baselineStd: this.baselineStd,
        referenceValue: this.referenceValue,
        targetARL: this.targetARL,
      },
    };
  }

  /**
   * Estimate the change point (the exact moment drift began).
   *
   * Uses the last CUSUM zero-crossing as the change point estimate.
   *
   * @returns {Object} Change point analysis
   */
  estimateChangePoint() {
    if (!this.isCalibrated || this.alarmTimes.length === 0) {
      return { detected: false };
    }

    // Find last time S_t was zero (before the alarm)
    let lastZero = 0;
    for (let i = this.cusumHistory.length - 1; i >= 0; i--) {
      if (this.cusumHistory[i] === 0) {
        lastZero = i;
        break;
      }
    }

    const alarmIdx = this.alarmTimes[this.alarmTimes.length - 1].index;
    const totalObs = this.cusumHistory.length;

    return {
      detected: true,
      estimatedChangePoint: lastZero + 1,
      alarmAt: alarmIdx,
      driftDuration: alarmIdx - lastZero,
      preChangeMean: this._mean(this.distances.slice(Math.max(0, lastZero - 20), lastZero + 1)),
      postChangeMean: this._mean(this.distances.slice(lastZero, alarmIdx + 1)),
      shiftMagnitude: this._mean(this.distances.slice(lastZero, alarmIdx + 1)) -
                      this._mean(this.distances.slice(Math.max(0, lastZero - 20), lastZero + 1)),
    };
  }

  /**
   * Adaptive CUSUM: update baseline if drift is determined to be a new
   * normal (e.g., after model upgrade).
   *
   * @param {number[]} newBaseline - New normal D_Gr values
   */
  adaptToNewBaseline(newBaseline) {
    this.calibrate(newBaseline);
    this.alarmTimes = [];
    this.driftPhase = 'baseline';
  }

  _mean(arr) {
    return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
  }

  dumpDiagnostics() {
    return {
      isCalibrated: this.isCalibrated,
      baselineMean: this.baselineMean,
      baselineStd: this.baselineStd,
      currentCusum: this.S,
      threshold: this.threshold,
      driftPhase: this.driftPhase,
      alarmCount: this.alarmTimes.length,
      changePoint: this.estimateChangePoint(),
      recentDistances: this.distances.slice(-20),
      recentCusum: this.cusumHistory.slice(-20),
    };
  }
}

module.exports = { CUSUMSubspaceMonitor };
