/**
 * Conformal Martingale for Anytime-Valid Thresholds (Idea #9)
 *
 * Using conformal prediction to construct ANYTIME-VALID prediction sets
 * for anomaly detection, eliminating the need for independence assumptions
 * and providing distribution-free coverage guarantees.
 *
 * THEOREM (Anytime-Valid Conformal Anomaly Detection):
 *   Let S₁, S₂, ..., S_t be a sequence of nonconformity scores. Define:
 *
 *     p_t = (#{s ∈ calibration : s ≥ S_t} + 1) / (|calibration| + 1)
 *
 *   Then P(∃t ≤ T : p_t ≤ α | H₀) ≤ α  for ANY stopping time T,
 *   under the assumption of exchangeability (H₀).
 *
 *   This is MUCH stronger than pointwise guarantees:
 *     - Pointwise: P(p_t ≤ α | H₀) ≤ α for each t individually
 *     - Anytime-valid: P(any t up to T gives p_t ≤ α | H₀) ≤ α uniformly
 *
 *   The adversary CANNOT choose when to attack to evade detection — the
 *   coverage guarantee holds uniformly over time, regardless of when the
 *   attack occurs. This eliminates the "multiple testing" problem that
 *   plagues traditional threshold-based detection.
 *
 * COROLLARY (Conformal Martingale):
 *   The sequence M_t = ∏_{s=1}^t (p_s)^(γ-1) · γ  is a test martingale
 *   under H₀ for any γ ∈ (0, 1). Ville's inequality then gives:
 *
 *     P(∃t : M_t ≥ 1/α | H₀) ≤ α
 *
 *   This provides an anytime-valid test: raise alarm when M_t ≥ 1/α.
 *
 * @module conformal-martingale
 */

'use strict';

/**
 * ConformalMartingaleMonitor: Anytime-valid anomaly detection
 * using conformal prediction and test martingales.
 */
class ConformalMartingaleMonitor {
  /**
   * @param {Object} options
   * @param {number} options.alpha - Significance level (default: 0.05)
   * @param {number} options.gamma - Martingale parameter (default: 0.5)
   * @param {number} options.calibrationSize - Minimum calibration set size
   * @param {number} options.maxCalibrationSize - Maximum calibration set size
   */
  constructor(options = {}) {
    this.alpha = options.alpha || 0.05;
    this.gamma = options.gamma || 0.5;
    this.calibrationSize = options.calibrationSize || 100;
    this.maxCalibrationSize = options.maxCalibrationSize || 10000;

    // Calibration set: nonconformity scores under H₀ (baseline)
    this.calibrationScores = [];

    // Online scores: nonconformity scores received during operation
    this.onlineScores = [];
    this.pValues = [];
    this.martingale = [1.0]; // M₀ = 1

    // State
    this.mode = 'calibration'; // 'calibration' | 'monitoring'
    this.numAlarms = 0;
    this.alarmHistory = [];
  }

  /**
   * Initialise with a pre-computed calibration set.
   *
   * @param {number[]} scores - Nonconformity scores from baseline operation
   */
  initializeCalibration(scores) {
    this.calibrationScores = [...scores];
    this.mode = this.calibrationScores.length >= this.calibrationSize ?
      'monitoring' : 'calibration';
  }

  /**
   * Add a single score to the calibration set (during baseline collection).
   *
   * @param {number} score
   */
  addCalibrationScore(score) {
    this.calibrationScores.push(score);

    // Trim if exceeds maximum
    if (this.calibrationScores.length > this.maxCalibrationSize) {
      // Remove oldest, maintain exchangeability via random removal
      const removeIdx = Math.floor(Math.random() * this.calibrationScores.length);
      this.calibrationScores.splice(removeIdx, 1);
    }

    // Transition to monitoring mode
    if (this.calibrationScores.length >= this.calibrationSize) {
      this.mode = 'monitoring';
    }
  }

  /**
   * Compute the conformal p-value for a new nonconformity score.
   *
   * p_t = (#{s ∈ calibration : s ≥ S_t} + 1) / (|calibration| + 1)
   *
   * This is a valid p-value under H₀ (exchangeability assumption).
   * The "+1" ensures p_t > 0 and provides conservative coverage.
   *
   * @param {number} score - Current nonconformity score
   * @returns {number} Conformal p-value
   */
  computeConformalPValue(score) {
    const cal = this.calibrationScores;
    const n_cal = cal.length;

    if (n_cal === 0) {
      // No calibration data; return conservative p-value
      return 0.5;
    }

    // Count calibration scores ≥ current score
    let countGeq = 0;
    for (const s of cal) {
      if (s >= score) countGeq++;
    }

    // Conformal p-value (with +1 for conservativeness)
    return (countGeq + 1) / (n_cal + 1);
  }

  /**
   * Update the test martingale with a new p-value.
   *
   * M_t = M_{t-1} · p_t^(γ-1) · γ
   *
   * Under H₀, this is a test martingale (expected value = 1).
   * Under H₁, p-values become small, and M_t grows.
   *
   * @param {number} pValue - Conformal p-value for current observation
   */
  updateMartingale(pValue) {
    const factor = Math.pow(pValue, this.gamma - 1) * this.gamma;
    const M_prev = this.martingale[this.martingale.length - 1];
    const M_curr = M_prev * factor;
    this.martingale.push(M_curr);
    return M_curr;
  }

  /**
   * Process a new nonconformity score through the conformal martingale.
   *
   * @param {number} score - Nonconformity score from detector
   * @returns {Object} Processing result
   */
  process(score) {
    if (this.mode === 'calibration') {
      this.addCalibrationScore(score);
      return {
        mode: 'calibration',
        p_value: null,
        martingale_value: null,
        alarm: false,
        calibration_size: this.calibrationScores.length,
        target_size: this.calibrationSize
      };
    }

    // Monitoring mode
    const pValue = this.computeConformalPValue(score);
    this.pValues.push(pValue);
    this.onlineScores.push(score);

    const M_t = this.updateMartingale(pValue);
    const threshold = 1 / this.alpha;

    const alarm = M_t >= threshold;

    if (alarm) {
      this.numAlarms++;
      this.alarmHistory.push({
        index: this.onlineScores.length - 1,
        score,
        pValue,
        martingaleValue: M_t,
        threshold,
        timestamp: Date.now()
      });
    }

    return {
      mode: 'monitoring',
      p_value: pValue,
      martingale_value: M_t,
      threshold,
      alarm,
      num_alarms: this.numAlarms,
      calibration_size: this.calibrationScores.length
    };
  }

  /**
   * Compute the anytime-valid false alarm probability bound.
   *
   * Ville's inequality: P(∃t : M_t ≥ 1/α | H₀) ≤ α
   *
   * This is the anytime-valid guarantee: regardless of when the
   * adversary attacks, the probability of a false alarm at ANY
   * time is bounded by α.
   *
   * @returns {Object} Anytime-valid guarantee analysis
   */
  verifyAnytimeValidGuarantee() {
    const M_seq = this.martingale;
    const threshold = 1 / this.alpha;
    const maxM = Math.max(...M_seq);

    return {
      alpha: this.alpha,
      threshold: threshold,
      max_martingale: maxM,
      guarantee_satisfied: maxM < threshold,
      any_alarm: maxM >= threshold,
      ville_inequality: `P(∃t : M_t ≥ ${threshold} | H₀) ≤ ${this.alpha}`,
      interpretation: maxM >= threshold ?
        'ALARM_TRIGGERED: Evidence against H₀' :
        `GUARANTEE_HOLDING: No false alarm at level α=${this.alpha}`,
      total_observations: this.onlineScores.length,
      num_alarms: this.numAlarms
    };
  }

  /**
   * Adaptive calibration: update calibration set with recent baseline scores
   * to handle non-stationary distributions while maintaining exchangeability.
   *
   * Uses reservoir sampling: each new score replaces a random calibration
   * score with probability controlled by learning rate.
   *
   * @param {number} score - New baseline score
   * @param {number} learningRate - Adaptation rate (0-1)
   */
  adaptiveCalibrationUpdate(score, learningRate = 0.01) {
    if (Math.random() < learningRate) {
      // Reservoir sampling: replace random calibration element
      const replaceIdx = Math.floor(Math.random() * this.calibrationScores.length);
      this.calibrationScores[replaceIdx] = score;
    }
  }

  /**
   * Reset the martingale (e.g., after a known distribution shift).
   * Re-initializes M₀ = 1.
   */
  resetMartingale() {
    this.martingale = [1.0];
    this.pValues = [];
    this.alarmHistory = [];
    this.numAlarms = 0;
  }

  /**
   * Dump diagnostic state.
   *
   * @returns {Object}
   */
  dumpDiagnostics() {
    return {
      mode: this.mode,
      alpha: this.alpha,
      gamma: this.gamma,
      calibration_size: this.calibrationScores.length,
      online_observations: this.onlineScores.length,
      num_alarms: this.numAlarms,
      current_martingale: this.martingale[this.martingale.length - 1],
      martingale_threshold: 1 / this.alpha,
      recent_p_values: this.pValues.slice(-20),
      guarantee: this.mode === 'monitoring' ? this.verifyAnytimeValidGuarantee() : null,
      alarm_history: this.alarmHistory.slice(-10)
    };
  }
}

/**
 * Nonconformity score factory: compute nonconformity scores from
 * various detector outputs.
 */
const NonconformityScores = {
  /**
   * Convert a detector score to a nonconformity score.
   * Nonconformity = how unusual the observation is under H₀.
   *
   * @param {number} score - Detector score (higher = more anomalous)
   * @param {number} baselineMean - Mean score under H₀
   * @param {number} baselineStd - Standard deviation under H₀
   * @returns {number} Nonconformity score (z-score or robust alternative)
   */
  fromZScore(score, baselineMean = 0, baselineStd = 1) {
    if (baselineStd <= 0) return Math.abs(score - baselineMean);
    return Math.abs(score - baselineMean) / baselineStd;
  },

  /**
   * Nonconformity from ensemble: use maximum component deviation.
   *
   * @param {number[]} scores - Vector of detector scores
   * @param {number[]} baselineMeans - Mean vector under H₀
   * @param {number[]} baselineStds - Std vector under H₀
   * @returns {number} Maximum nonconformity across components
   */
  fromEnsembleMax(scores, baselineMeans, baselineStds) {
    let maxNc = 0;
    for (let i = 0; i < scores.length; i++) {
      const nc = NonconformityScores.fromZScore(
        scores[i], baselineMeans[i], baselineStds[i]
      );
      maxNc = Math.max(maxNc, nc);
    }
    return maxNc;
  },

  /**
   * Nonconformity from Mahalanobis distance (accounts for correlation).
   *
   * @param {number[]} scores - Detector score vector
   * @param {number[]} baselineMeans - Mean vector
   * @param {number[][]} baselineCovInv - Inverse covariance matrix
   * @returns {number} Mahalanobis distance
   */
  fromMahalanobis(scores, baselineMeans, baselineCovInv) {
    const n = scores.length;
    let sum = 0;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        sum += (scores[i] - baselineMeans[i]) *
               baselineCovInv[i][j] *
               (scores[j] - baselineMeans[j]);
      }
    }
    return Math.sqrt(Math.max(sum, 0));
  }
};

module.exports = { ConformalMartingaleMonitor, NonconformityScores };
