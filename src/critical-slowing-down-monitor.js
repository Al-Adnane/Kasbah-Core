/**
 * Critical Slowing Down Monitor (NEW Idea #2)
 *
 * Value hijacking isn't a sudden event — it's a PHASE TRANSITION in activation
 * subspace dynamics. Before the catastrophic shift, the system exhibits CRITICAL
 * SLOWING DOWN: increased autocorrelation, increased variance, and flickering
 * between attractor states.
 *
 * This comes from ecology (regime shift detection in ecosystems, Scheffer et al.
 * 2009, Dakos et al. 2012) but has NEVER been applied to neural activation
 * dynamics for AI alignment.
 *
 * KEY INSIGHT:
 *   Existing drift detection (including CUSUM) detects the change AFTER it
 *   happens. Critical slowing down detects the PRE-TRANSITION signals — you
 *   get EARLY WARNING before the catastrophic shift.
 *
 *   The signal is not in the drift magnitude itself, but in the STATISTICAL
 *   PROPERTIES of the drift time series:
 *     - AR(1) coefficient ↑ (increased memory / autocorrelation)
 *     - Variance ↑ (system explores wider attractor basin)
 *     - Flickering ↑ (rapid alternation between near/far subspace distances)
 *
 * DETECTION RULE:
 *   When AR(1) > baseline_AR(1) + 2σ AND variance > baseline_variance + 2σ
 *   simultaneously → WARN (pre-phase-transition signal detected).
 *
 *   When either metric crosses 3σ → REQUIRE_APPROVAL.
 *
 * REFERENCE:
 *   Scheffer, M., et al. (2009). "Early-warning signals for critical
 *   transitions." Nature, 461(7260), 53-59.
 *
 * @module critical-slowing-down-monitor
 */
'use strict';

class CriticalSlowingDownMonitor {
  /**
   * @param {Object} opts
   * @param {number} opts.windowSize - Rolling window for statistics (default: 30)
   * @param {number} opts.baselineWindow - Baseline calibration window (default: 100)
   * @param {number} opts.arOrder - AR model order for autocorrelation (default: 1)
   * @param {number} opts.sigmaWarn - Sigma threshold for WARN (default: 2.0)
   * @param {number} opts.sigmaEscalate - Sigma threshold for REQUIRE_APPROVAL (default: 3.0)
   * @param {number} opts.flickerThreshold - Fraction of window for flickering detection
   */
  constructor(opts = {}) {
    this.windowSize = opts.windowSize || 30;
    this.baselineWindow = opts.baselineWindow || 100;
    this.arOrder = opts.arOrder || 1;
    this.sigmaWarn = opts.sigmaWarn || 2.0;
    this.sigmaEscalate = opts.sigmaEscalate || 3.0;
    this.flickerThreshold = opts.flickerThreshold || 0.15;

    // Time series storage
    this.driftSeries = [];       // D_Gr(V_t, V_{t-1}) values
    this.baseline = null;        // { meanAr1, stdAr1, meanVar, stdVar, meanFlicker, stdFlicker }
    this.isCalibrated = false;
    this.lastWarning = null;
  }

  /**
   * Calibrate baseline statistics from a period of known-normal operation.
   *
   * @param {number[]} driftValues - Sequence of D_Gr values from baseline period
   */
  calibrate(driftValues) {
    if (driftValues.length < this.baselineWindow) {
      throw new Error(
        `Need at least ${this.baselineWindow} values for calibration, got ${driftValues.length}`
      );
    }

    // Use the most recent baselineWindow values
    const baseline = driftValues.slice(-this.baselineWindow);

    // Compute AR(1), variance, and flicker index on multiple rolling windows
    const ar1s = [];
    const variances = [];
    const flickers = [];

    for (let i = this.windowSize; i <= baseline.length; i++) {
      const window = baseline.slice(i - this.windowSize, i);
      ar1s.push(this._estimateAR1(window));
      variances.push(this._variance(window));
      flickers.push(this._flickerIndex(window));
    }

    this.baseline = {
      meanAr1: this._mean(ar1s),
      stdAr1: this._std(ar1s, this._mean(ar1s)),
      meanVar: this._mean(variances),
      stdVar: this._std(variances, this._mean(variances)),
      meanFlicker: this._mean(flickers),
      stdFlicker: this._std(flickers, this._mean(flickers)),
      calibrationSize: baseline.length,
    };

    this.driftSeries = [...driftValues];
    this.isCalibrated = true;
  }

  /**
   * Observe a new Grassmann distance value.
   *
   * @param {number} driftValue - D_Gr(V_t, V_{t-1}) for current step
   * @returns {Object} Early warning analysis
   */
  observe(driftValue) {
    this.driftSeries.push(driftValue);
    if (this.driftSeries.length > this.baselineWindow * 3) {
      this.driftSeries = this.driftSeries.slice(-this.baselineWindow * 2);
    }

    // Need enough data for rolling window
    if (this.driftSeries.length < this.windowSize) {
      return this._insufficient(null);
    }

    const recent = this.driftSeries.slice(-this.windowSize);
    const ar1 = this._estimateAR1(recent);
    const variance = this._variance(recent);
    const flicker = this._flickerIndex(recent);
    const meanDrift = this._mean(recent);

    if (!this.isCalibrated) {
      return {
        mode: 'calibrating',
        ar1, variance, flicker, meanDrift,
        samples: this.driftSeries.length,
        needed: this.baselineWindow,
      };
    }

    // Compute sigma deviations from baseline
    const b = this.baseline;
    const ar1Sigma = b.stdAr1 > 0 ? (ar1 - b.meanAr1) / b.stdAr1 : 0;
    const varSigma = b.stdVar > 0 ? (variance - b.meanVar) / b.stdVar : 0;
    const flickerSigma = b.stdFlicker > 0 ? (flicker - b.meanFlicker) / b.stdFlicker : 0;

    // Combined early warning score
    // Critical slowing down: BOTH ar1 AND variance increase above baseline
    const csdScore = Math.min(ar1Sigma, varSigma);
    // Flickering: rapid alternation
    const flickerScore = flickerSigma;

    // Detection rules (Scheffer et al. 2009)
    let verdict = 'NORMAL';
    let signal = null;

    if (csdScore >= this.sigmaEscalate || flickerScore >= this.sigmaEscalate) {
      verdict = 'PRE_TRANSITION_CRITICAL';
      signal = 'REQUIRE_APPROVAL';
    } else if (csdScore >= this.sigmaWarn || flickerScore >= this.sigmaWarn) {
      verdict = 'PRE_TRANSITION_WARNING';
      signal = 'WARN';
    } else if (ar1Sigma >= 1.5 && varSigma >= 1.5) {
      verdict = 'ELEVATED_CSD_INDICATORS';
      signal = null; // Advisory only, no escalation
    }

    this.lastWarning = signal ? {
      timestamp: Date.now(),
      verdict,
      signal,
      ar1Sigma,
      varSigma,
      flickerSigma,
    } : null;

    return {
      mode: 'monitoring',
      ar1,
      variance,
      flicker,
      meanDrift,
      ar1Sigma,
      varSigma,
      flickerSigma,
      csdScore,
      flickerScore,
      baseline: {
        meanAr1: b.meanAr1,
        stdAr1: b.stdAr1,
        meanVar: b.meanVar,
        stdVar: b.stdVar,
      },
      verdict,
      signal,
      isPreTransition: signal !== null,
    };
  }

  /**
   * Full early-warning dashboard.
   *
   * @returns {Object}
   */
  dashboard() {
    if (this.driftSeries.length < this.windowSize) {
      return { mode: 'insufficient_data', samples: this.driftSeries.length };
    }
    const recent = this.driftSeries.slice(-this.windowSize);
    return this.observe(recent[recent.length - 1]); // re-evaluate latest
  }

  /**
   * Does the current state indicate an impending phase transition?
   *
   * @returns {boolean}
   */
  isImpendingTransition() {
    if (!this.isCalibrated) return false;
    const recent = this.driftSeries.slice(-this.windowSize);
    if (recent.length < this.windowSize) return false;

    const ar1 = this._estimateAR1(recent);
    const variance = this._variance(recent);
    const b = this.baseline;

    const ar1Sigma = b.stdAr1 > 0 ? (ar1 - b.meanAr1) / b.stdAr1 : 0;
    const varSigma = b.stdVar > 0 ? (variance - b.meanVar) / b.stdVar : 0;

    return ar1Sigma >= this.sigmaWarn && varSigma >= this.sigmaWarn;
  }

  // ============ Internal Statistics ============

  _estimateAR1(series) {
    if (series.length < 2) return 0;
    const n = series.length;
    const mean = this._mean(series);

    let cov = 0;
    let varPrev = 0;

    for (let i = 1; i < n; i++) {
      const devCurr = series[i] - mean;
      const devPrev = series[i - 1] - mean;
      cov += devCurr * devPrev;
      varPrev += devPrev * devPrev;
    }

    return varPrev > 0 ? cov / varPrev : 0;
  }

  _variance(series) {
    const mean = this._mean(series);
    return series.reduce((s, x) => s + (x - mean) ** 2, 0) / (series.length - 1);
  }

  _flickerIndex(series) {
    if (series.length < 3) return 0;

    // Flickering: count sign changes in the first difference
    const diffs = [];
    for (let i = 1; i < series.length; i++) {
      diffs.push(series[i] - series[i - 1]);
    }

    let signChanges = 0;
    for (let i = 1; i < diffs.length; i++) {
      if (diffs[i] * diffs[i - 1] < 0) signChanges++;
    }

    return diffs.length > 0 ? signChanges / diffs.length : 0;
  }

  _mean(arr) {
    return arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
  }

  _std(arr, mean) {
    if (arr.length < 2) return 0;
    const m = mean !== undefined ? mean : this._mean(arr);
    const variance = arr.reduce((s, x) => s + (x - m) ** 2, 0) / (arr.length - 1);
    return Math.sqrt(variance);
  }

  _insufficient(reason) {
    return {
      mode: 'insufficient_data',
      samples: this.driftSeries.length,
      needed: this.windowSize,
      reason,
    };
  }

  dumpDiagnostics() {
    return {
      isCalibrated: this.isCalibrated,
      samples: this.driftSeries.length,
      baseline: this.baseline,
      lastWarning: this.lastWarning,
      recent: this.driftSeries.slice(-10),
    };
  }
}

module.exports = { CriticalSlowingDownMonitor };
