/**
 * DO-BFT: Differentially-Obfuscated Byzantine Fault Tolerance (Idea #3)
 *
 * Intentionally adding differential privacy noise to observer views to force
 * adversaries to satisfy N inconsistent world-views simultaneously, creating
 * detectable disagreement signatures.
 *
 * CORE INSIGHT:
 *   Traditional BFT assumes all correct replicas observe identical inputs.
 *   DO-BFT INTENTIONALLY VIOLATES this assumption as a defensive mechanism.
 *
 *   Each evaluator receives: observation + Laplace(0, 1/ε)
 *   An honest evaluator reports the noisy observation faithfully.
 *   A colluding adversary must fabricate observations that are consistent
 *   across N DIFFERENT perturbed views — a combinatorially harder problem
 *   than gaming a single clean observation.
 *
 * THEOREM (DO-BFT Detection Probability):
 *   With N_obs independent observers, each receiving Laplace(0, 1/ε) noise:
 *
 *     P(detect collusion | H₁) ≥ 1 - exp(-N_obs · (εδ/√d)²)
 *
 *   Where δ is the minimum detectable disagreement and d is the
 *   dimension of the observation space.
 *
 * Why this works:
 *   - Honest observers: opinions are independent draws from Laplace(truth, 1/ε)
 *     → Expected pairwise disagreement = 2/ε (property of Laplace distribution)
 *   - Colluding adversaries: must agree on a SINGLE fabricated value
 *     → They cannot reproduce the expected noise spread
 *     → Their opinions are too clustered (κ-statistic detects this)
 *
 * @module do-bft-consensus
 */

'use strict';

/**
 * DOBFTConsensus: Differentially-Obfuscated BFT consensus protocol.
 *
 * This is NOT a traditional BFT protocol. It is a detection mechanism
 * that uses intentional observation perturbation to expose collusion.
 */
class DOBFTConsensus {
  /**
   * @param {Object} options
   * @param {number} options.epsilon - Privacy budget (lower = more noise, harder to evade)
   * @param {number} options.delta - Minimum detectable disagreement
   * @param {number} options.minObservers - Minimum number of observers for statistical power
   * @param {number} options.dimension - Observation space dimension
   */
  constructor(options = {}) {
    this.epsilon = options.epsilon || 1.0;
    this.delta = options.delta || 0.1;
    this.minObservers = options.minObservers || 5;
    this.dimension = options.dimension || 1;

    // Observer registry
    this.observers = {}; // id → { role, noise_seed }
    this.observationHistory = []; // [{ truth, observations: [{ id, value }] }]
  }

  /**
   * Register an observer.
   *
   * @param {string} id - Observer identifier
   * @param {Object} meta - Observer metadata
   */
  registerObserver(id, meta = {}) {
    this.observers[id] = {
      id,
      role: meta.role || 'evaluator',
      registerTime: Date.now(),
      noiseSeed: this._seededRandom(id)
    };
  }

  /**
   * Remove an observer.
   *
   * @param {string} id
   */
  removeObserver(id) {
    delete this.observers[id];
  }

  /**
   * Perturb an observation with Laplace noise.
   *
   * observation_perturbed = truth + Laplace(0, b)
   * where b = 1/ε (scale parameter of Laplace)
   *
   * @param {number} truth - Ground truth value
   * @param {string} observerId - Observer receiving the perturbed view
   * @returns {number} Perturbed observation
   */
  perturbObservation(truth, observerId) {
    const observer = this.observers[observerId];
    if (!observer) {
      throw new Error(`Unknown observer: ${observerId}`);
    }

    // Deterministic noise per observer (reproducible)
    const u = this._seededUniform(observerId);
    const halfLaplace = (1 / this.epsilon) * Math.log(2 * u);

    // Laplace: sign determined by second uniform
    const v = this._seededUniform(observerId + '_sign');
    const noise = v < 0.5 ? -halfLaplace : halfLaplace;

    return truth + noise;
  }

  /**
   * Collect perturbed observations from all registered observers.
   *
   * @param {number} truth - Ground truth value
   * @returns {Object[]} Array of { observerId, value }
   */
  collectPerturbedObservations(truth) {
    const observations = [];
    for (const [id] of Object.entries(this.observers)) {
      observations.push({
        observerId: id,
        value: this.perturbObservation(truth, id)
      });
    }

    // Record history
    if (this.observationHistory.length > 1000) {
      this.observationHistory.shift();
    }
    this.observationHistory.push({ truth, observations: observations.map(o => ({ ...o })) });

    return observations;
  }

  /**
   * Detect collusion via clustered-observation test.
   *
   * Under H₀ (no collusion):
   *   Each observer reports independently perturbed value.
   *   Expected variance of observations = 2/ε² (Laplace variance)
   *
   * Under H₁ (collusion):
   *   Adversaries coordinate on a single value.
   *   Observed variance << expected variance → evidence of collusion.
   *
   * Detection statistic:
   *   T = (expected_variance - observed_variance) / SE
   *   Reject H₀ if T > z_{1-α}
   *
   * @param {Object[]} observations - Array of { observerId, value }
   * @returns {Object} Detection result
   */
  detectCollusion(observations) {
    const n = observations.length;

    if (n < this.minObservers) {
      return {
        collusion_detected: false,
        reason: 'insufficient_observers',
        num_observers: n,
        min_required: this.minObservers
      };
    }

    // Observed variance
    const values = observations.map(o => o.value);
    const observedMean = values.reduce((a, b) => a + b, 0) / n;
    const observedVariance = values.reduce(
      (sum, v) => sum + Math.pow(v - observedMean, 2), 0
    ) / (n - 1);

    // Expected variance under H₀: Laplace(0, 1/ε) has variance 2/ε²
    const expectedVariance = 2 / (this.epsilon * this.epsilon);

    // Detection statistic: variance ratio test
    // Under-collapsed variance → possible collusion
    const varianceRatio = observedVariance / expectedVariance;

    // Standard error of variance (chisq approximation)
    const seVariance = expectedVariance * Math.sqrt(2 / (n - 1));

    // Test statistic
    const testStat = (expectedVariance - observedVariance) / seVariance;

    // P-value (one-sided: variance is too small)
    const pValue = this._normalCDF(-testStat);

    // Detection probability bound (theorem)
    const detectionBound = 1 - Math.exp(
      -n * Math.pow(this.epsilon * this.delta / Math.sqrt(this.dimension), 2)
    );

    const collusionDetected = pValue < 0.05; // α = 0.05

    return {
      collusion_detected: collusionDetected,
      p_value: pValue,
      test_statistic: testStat,
      observed_variance: observedVariance,
      expected_variance: expectedVariance,
      variance_ratio: varianceRatio,
      detection_probability_bound: detectionBound,
      epsilon: this.epsilon,
      num_observers: n,
      interpretation: collusionDetected ?
        (varianceRatio < 0.1 ? 'STRONG_COLLUSION_EVIDENCE' :
         'MODERATE_COLLUSION_EVIDENCE') :
        (varianceRatio < 0.5 ? 'BORDERLINE_MONITOR' : 'NO_COLLUSION_DETECTED')
    };
  }

  /**
   * Compute pairwise disagreement signature.
   *
   * Honest observers: wide disagreement spread (due to Laplace noise).
   * Colluding adversaries: narrow disagreement (coordination).
   *
   * @param {Object[]} observations
   * @returns {Object} Disagreement analysis
   */
  computeDisagreementSignature(observations) {
    const n = observations.length;
    const values = observations.map(o => o.value);

    const pairwiseDiffs = [];
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        pairwiseDiffs.push(Math.abs(values[i] - values[j]));
      }
    }

    // Expected pairwise diff for Laplace: 1/ε (mean absolute deviation)
    const expectedPairwiseDiff = 1 / this.epsilon;

    const observedMeanDiff = pairwiseDiffs.reduce((a, b) => a + b, 0) /
      pairwiseDiffs.length;

    const diffRatio = observedMeanDiff / expectedPairwiseDiff;

    return {
      pairwise_diffs: pairwiseDiffs,
      observed_mean_diff: observedMeanDiff,
      expected_mean_diff: expectedPairwiseDiff,
      diff_ratio: diffRatio,
      interpretation: diffRatio < 0.3 ? 'ABNORMALLY_CLUSTERED' :
                     diffRatio > 2.0 ? 'ABNORMALLY_SPREAD' :
                     'NORMAL_SPREAD'
    };
  }

  /**
   * Multi-dimensional DO-BFT.
   *
   * For d-dimensional observations, each dimension receives independent
   * Laplace noise. Detection power scales with dimension.
   *
   * @param {number[]} truthVector - Ground truth vector
   * @param {string[]} observerIds - Observer identifiers
   * @returns {Object} Multi-dimensional analysis
   */
  multiDimensionalDOBFT(truthVector, observerIds) {
    const d = truthVector.length;
    const n = observerIds.length;

    // Collect perturbed observations per dimension
    const perDimensionObservations = [];
    for (let dim = 0; dim < d; dim++) {
      const dimObs = [];
      for (const obsId of observerIds) {
        const perturbed = this.perturbObservation(truthVector[dim], obsId + `_dim${dim}`);
        dimObs.push({ observerId: obsId, value: perturbed });
      }
      perDimensionObservations.push(dimObs);
    }

    // Collusion detection per dimension
    const perDimensionResults = perDimensionObservations.map(
      obs => this.detectCollusion(obs)
    );

    // Joint detection: collusion detected if ANY dimension flags
    const anyCollusion = perDimensionResults.some(r => r.collusion_detected);

    // Joint detection probability bound
    const jointDetectionBound = 1 - Math.exp(
      -n * d * Math.pow(this.epsilon * this.delta / Math.sqrt(d), 2)
    );

    return {
      dimensions: d,
      observers: n,
      per_dimension: perDimensionResults,
      any_collusion_detected: anyCollusion,
      joint_detection_bound: jointDetectionBound,
      epsilon: this.epsilon
    };
  }

  /**
   * Simulate DO-BFT for adversary testing.
   *
   * @param {number} truth - Ground truth value
   * @param {number} numHonest - Number of honest observers
   * @param {number} numAdversaries - Number of colluding adversaries
   * @param {number} adversaryValue - Value adversaries agree to report
   * @returns {Object} Simulation result
   */
  simulate(truth, numHonest = 4, numAdversaries = 2, adversaryValue = null) {
    // Ensure observers exist
    const allObservers = [];
    for (let i = 0; i < numHonest; i++) {
      const id = `honest_${i}`;
      if (!this.observers[id]) this.registerObserver(id);
      allObservers.push(id);
    }
    for (let i = 0; i < numAdversaries; i++) {
      const id = `adversary_${i}`;
      if (!this.observers[id]) this.registerObserver(id);
      allObservers.push(id);
    }

    // Honest observers: perturbed truth
    const honestObs = [];
    for (let i = 0; i < numHonest; i++) {
      const perturbed = this.perturbObservation(truth, `honest_${i}`);
      honestObs.push({ observerId: `honest_${i}`, value: perturbed });
    }

    // Adversaries: agree on a common value (slightly perturbed for realism)
    const advValue = adversaryValue !== null ? adversaryValue : truth;
    const adversaryObs = [];
    for (let i = 0; i < numAdversaries; i++) {
      // Small coordinated noise to avoid being too obvious
      const smallNoise = (Math.random() - 0.5) * 0.01;
      adversaryObs.push({ observerId: `adversary_${i}`, value: advValue + smallNoise });
    }

    const allObs = [...honestObs, ...adversaryObs];

    const collusionResult = this.detectCollusion(allObs);
    const disagreementResult = this.computeDisagreementSignature(allObs);

    return {
      truth,
      num_honest: numHonest,
      num_adversaries: numAdversaries,
      honest_observations: honestObs,
      adversary_observations: adversaryObs,
      collusion_detection: collusionResult,
      disagreement_signature: disagreementResult,
      detected: collusionResult.collusion_detected
    };
  }

  // ============ Internal Helpers ============

  /**
   * Seeded pseudo-random number generator (deterministic per observer).
   *
   * @param {string} seed - Observer identifier as seed
   * @returns {number} Deterministic "random" value in [0, 1)
   */
  _seededUniform(seed) {
    // Simple hash-based PRNG
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
      const char = seed.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    // Normalize to [0, 1)
    return ((Math.abs(hash) % 100000) / 100000);
  }

  _seededRandom(seed) {
    return this._seededUniform(seed);
  }

  /**
   * Standard normal CDF approximation.
   *
   * @param {number} x
   * @returns {number}
   */
  _normalCDF(x) {
    // Abramowitz and Stegun approximation
    const a1 = 0.254829592;
    const a2 = -0.284496736;
    const a3 = 1.421413741;
    const a4 = -1.453152027;
    const a5 = 1.061405429;
    const p = 0.3275911;

    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x) / Math.sqrt(2);

    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) *
              t * Math.exp(-x * x);

    return 0.5 * (1.0 + sign * y);
  }
}

module.exports = { DOBFTConsensus };
