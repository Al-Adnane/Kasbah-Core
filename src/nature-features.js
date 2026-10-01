/**
 * NatureFeatureExtractor — honest fusion of the nature-inspired analyzers.
 *
 * The modules reynolds-flow, harmonic-dissonance, topo-shield,
 * eigen-ethics-drift, punctuated-equilibrium, shadow-consensus,
 * bells-inequality and causal-loop-breaker all compute REAL math
 * (DFT, persistent homology, Jacobi eigenvalues, KL divergence, CHSH
 * correlations, spectral regression) — but on UNVALIDATED premises
 * (e.g. the "Reynolds number" of a token stream, "tritone intervals"
 * between agents). Their conclusions have NOT been empirically validated
 * against labelled abuse data.
 *
 * Therefore this module treats each analyzer's output as a numeric
 * ADVISORY FEATURE, never as an authoritative verdict. Features can:
 *   - contribute to a bounded composite anomaly score in [0,1]
 *   - raise a WARN / REQUIRE_APPROVAL signal for human review
 * Features must NOT unilaterally DENY real traffic. Authoritative DENY
 * stays with the validated layers (policy engine, PII/secret detector,
 * governance/OS, TOCTOU, agent-trust).
 *
 * This is the "drop standalone pseudo-verdicts; keep the signals as
 * features" wiring.
 */

'use strict';

// ── 15 NOVEL MODULE IMPORTS for honest feature fusion ────
const { FlagCorrelationFuser }       = require('./flag-correlation-weighting.js');
const { computeOrthogonalEvasionBound } = require('./orthogonal-manifold-evasion-bound.js');

function clamp01(x) {
  if (typeof x !== 'number' || !isFinite(x)) return 0;
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

/**
 * Convert the heterogeneous analyzer outputs into a flat, bounded
 * numeric feature vector. Every feature is in [0,1] and is purely
 * advisory. Unknown / missing fields default to 0 (no signal).
 *
 * @param {object} r — { eigen, shadow, topo, causal, flow, evol, harm, bell, planet }
 *   each being the raw analyze()/test() result of the corresponding module.
 *   r.planet is optional — { signal: number[], history: number[][] } for PPP sheaf computation.
 * @param {object} opts — { planetaryWeight: number }
 */
function extractFeatures(r = {}, opts = {}) {
  const eigen  = r.eigen  || {};
  const shadow = r.shadow || {};
  const topo   = r.topo   || {};
  const homology = r.homology || {}; // Paper 001: persistent homology (rigorous, replaces topo-shield metaphor)
  const spectral = r.spectral || {}; // Paper 002: STFT spectral residual (rigorous, replaces harmonic-dissonance metaphor)
  const causal = r.causal || {};
  const flow   = r.flow   || {};
  const infoFlow = r.infoFlow || {};  // Paper 008: permutation entropy + Lyapunov (rigorous, replaces fluid metaphor)
  const evol   = r.evol   || {};
  const harm   = r.harm   || {};
  const bell   = r.bell   || {};

  // 15 NOVEL MODULE RESULTS — advisory features only
  const panopticon    = r.panopticon    || {};
  const csd           = r.csd           || {};
  const surprisal     = r.surprisal     || {};
  const governanceAudit = r.governanceAudit || {};
  const stigmergic    = r.stigmergic    || {};
  const doBft         = r.doBft         || {};
  const chsh          = r.chsh          || {};
  const cusum         = r.cusum         || {};
  const topoNovel     = r.topoNovel     || {};
  const martingale    = r.martingale    || {};
  const ecp           = r.ecp           || {};
  // 7 NEW MODULES (#16-#22)
  const lmid          = r.lmid          || {};
  const cwed          = r.cwed          || {};
  const rpim          = r.rpim          || {};
  const kfpr          = r.kfpr          || {};
  const stdd          = r.stdd          || {};
  const hcd           = r.hcd           || {};
  const itcd          = r.itcd          || {};
  // 3 NEW MODULES (#23-#25)
  const cmca          = r.cmca          || {};
  const atp           = r.atp           || {};
  const ocp           = r.ocp           || {};

  return {
    // ethics covariance drift magnitude (nuclear norm, normalized)
    eigen_drift:      clamp01((eigen.nuclearNorm || 0) / 10),
    // perturbed-observer disagreement (gaming likelihood)
    shadow_gaming:    shadow.gamingDetected ? clamp01(shadow.confidence || 0.5) : 0,
    // topological anomaly (Betti-1 loops / covert channel — legacy, low weight)
    topo_anomaly:     topo.alert ? 1 : 0,
    // Paper 001: persistent homology H₁ features (rigorous)
    homology_h1:      clamp01((homology.totalH1Features || 0) / 5),
    homology_persistence: clamp01((homology.maxPersistence || 0) / 0.3),
    // causal feedback loops between agents
    causal_loops:     clamp01((causal.cycleCount || 0) / 5),
    // token-stream "turbulence" (unvalidated premise — advisory only, low weight)
    flow_turbulence:  flow.regime === 'turbulent' ? 1 : flow.regime === 'transitional' ? 0.5 : 0,
    // Paper 008: information-theoretic complexity (rigorous — permutation entropy + Lyapunov)
    info_flow_complexity: clamp01(infoFlow.anomalyScore || 0),
    // abrupt behavioral shift (punctuated equilibrium)
    evol_punctuation: evol.punctuationDetected ? 1 : 0,
    // inter-agent dissonance (music-theory premise — advisory only, low weight)
    harm_dissonance:  clamp01(harm.overallDissonance || 0),
    // Paper 002: spectral residual anomaly (rigorous DSP)
    spectral_anomaly: clamp01(spectral.anomalyScore || 0),
    spectral_peak_z:  clamp01((spectral.peakZScore || 0) / 5),
    // CHSH-style correlation (collusion premise)
    bell_correlation: clamp01(Math.abs(bell.sValue || 0) / 4),

    // ══════════════════════════════════════════════════════════
    // Planetary Maqṣad (PPP — Protection of the Planet)
    // Computed from persistent sheaf cohomology on Public+Planet
    // base space. High regenerative + low drift → REGENERATIVE.
    // ══════════════════════════════════════════════════════════
    planet_regenerative: computeRegenerativeScore(r.planet, opts),
    planet_drift:       computePlanetDrift(r.planet, opts),

    // ══════════════════════════════════════════════════════════
    // 15 NOVEL MODULE FEATURES — unvalidated premises, advisory only
    // Each clamped to [0,1] with conservative signal thresholds.
    // ══════════════════════════════════════════════════════════
    panopticon_deceptive:   panopticon.isDeceptive ? clamp01(panopticon.gapRatio || 0.5) : 0,
    csd_pretransition:      csd.isPreTransition ? clamp01(
      (Math.max(0, csd.ar1coefficient || 0) * 0.5) + (clamp01(csd.flickerIndex || 0) * 0.5)
    ) : 0,
    surprisal_burn:         clamp01((surprisal.burnRateRatio || 1) / 5),   // >1 means over budget
    governance_drift:       governanceAudit.driftDetected ? clamp01(governanceAudit.driftMagnitude || 0.5) : 0,
    stigmergic_signal:      clamp01((stigmergic.stigmergicPairs || 0) / 5),
    dobft_collusion:        doBft.collusionDetected ? clamp01(doBft.slanderRatio || 0.5) : 0,
    chsh_noncommutative:    clamp01(Math.max(0, (chsh.S_abs || 0) - 2) / 2),  // S > 2 violates CHSH
    cusum_changepoint:      clamp01(cusum.cusumValue || 0),
    topology_covert:        topoNovel.detected ? clamp01((topoNovel.significantH1 || 1) / 5) : 0,
    martingale_anomaly:     clamp01(Math.log(1 + (martingale.martingaleValue || 1)) / Math.log(100)),
    ecp_regime_abnormal:    ecp && !ecp.isNormal ? 1 : 0,

    // ══════════════════════════════════════════════════════════
    // 7 NEW MODULE FEATURES (#16-#22) — unvalidated premises
    // ══════════════════════════════════════════════════════════
    lmid_intrusion:         lmid.isIntrusion ? clamp01(lmid.geodesicDeviation || 0.5) : clamp01((lmid.geodesicDeviation || 0) * 2),
    cwed_entrapped:         cwed.isEntrapped ? clamp01(cwed.jsDivergence || 0.5) : clamp01((cwed.jsDivergence || 0) * 2),
    rpim_violation:         rpim.isViolation ? clamp01(rpim.tauDistance || 0.5) : clamp01((rpim.tauDistance || 0) * 2),
    kfpr_pathological:      kfpr.isLooping || kfpr.classification === 'PATHOLOGICAL' ? clamp01(kfpr.contractionRate || 0.5) : 0,
    stdd_dangerous_drift:   stdd.isDriftingDangerous ? clamp01(stdd.lieDerivativeNorm || 0.5) : clamp01((stdd.lieDerivativeNorm || 0) * 2),
    hcd_collusion:          hcd.isColluding ? clamp01(hcd.spectralGapRatio || 0.5) : clamp01((hcd.spectralGapRatio || 0) * 2),
    itcd_channel:           itcd.isChannelDetected ? clamp01(itcd.mutualInformation || 0.5) : clamp01((itcd.mutualInformation || 0) * 2),

    // ══════════════════════════════════════════════════════════
    // 3 NEW MODULE FEATURES (#23-#25) — advisory only
    // ══════════════════════════════════════════════════════════
    cmca_deception:         cmca.isDeceptive ? clamp01(cmca.crossModalDivergence || 0.5) : clamp01((cmca.crossModalDivergence || 0) * 2),
    atp_divergence:         atp.boundaryCrossing ? clamp01(atp.projectedMaxScore || 0.7) :
                            (atp.isDiverging ? clamp01((atp.lyapunovExponent || 0) * 10) : clamp01(Math.abs(atp.lyapunovExponent || 0) * 5)),
    ocp_deviation:          !ocp.compliant ? clamp01(ocp.deviationScore || 0.5) : clamp01((ocp.deviationScore || 0) * 2),
  };
}

// Weights reflect rough confidence in each premise. They are conservative
// and tunable; NONE alone can reach the WARN threshold, so a single noisy
// feature cannot trigger review on its own.
const FEATURE_WEIGHTS = {
  eigen_drift:      0.18,
  shadow_gaming:    0.18,
  topo_anomaly:     0.04, // graph connectivity — deprecated in favor of homology
  homology_h1:      0.14, // Paper 001: persistent homology H₁ (rigorous)
  homology_persistence: 0.10, // Paper 001: cycle lifetime (rigorous)
  causal_loops:     0.14,
  flow_turbulence:  0.04, // fluid metaphor — deprecated in favor of info_flow_complexity
  info_flow_complexity: 0.16, // Paper 008: permutation entropy + Lyapunov (rigorous)
  evol_punctuation: 0.08,
  harm_dissonance:  0.04, // music metaphor — deprecated in favor of spectral
  spectral_anomaly: 0.12, // Paper 002: spectral residual (rigorous DSP)
  spectral_peak_z:  0.08, // Paper 002: peak z-score (rigorous)
  bell_correlation: 0.12,

  // ── 15 NOVEL MODULE WEIGHTS — conservative, tunable ─────
  // Each individual weight is deliberately low so no single
  // unvalidated novel feature can independently trigger WARN.
  panopticon_deceptive:    0.10,
  csd_pretransition:       0.12,  // early-warning deserves slightly higher weight
  surprisal_burn:          0.08,
  governance_drift:        0.10,
  stigmergic_signal:       0.10,
  dobft_collusion:         0.10,
  chsh_noncommutative:     0.12,
  cusum_changepoint:       0.12,
  topology_covert:         0.12,
  martingale_anomaly:      0.14,  // anytime-valid guarantee lifts weight
  ecp_regime_abnormal:     0.06,  // weakest novel premise → lowest weight

  // ── 7 NEW MODULE WEIGHTS (#16-#22) — conservative ──────
  lmid_intrusion:          0.10,
  cwed_entrapped:          0.10,
  rpim_violation:          0.08,
  kfpr_pathological:       0.12,  // self-referential loops deserve attention
  stdd_dangerous_drift:    0.10,
  hcd_collusion:           0.10,
  itcd_channel:            0.12,  // timing channel deserves higher weight

  // ── 3 NEW MODULE WEIGHTS (#23-#25) — conservative ──────
  cmca_deception:          0.12,  // cross-modal deception is a strong signal
  atp_divergence:          0.10,  // trajectory projection: medium weight
  ocp_deviation:           0.12,  // commitment deviation is cryptographically strong
};

// ══════════════════════════════════════════════════════════════
// Planetary Maqṣad (PPP — Protection of the Planet)
// Weight of Planet sites in the sheaf base space.
// Default 0.4 per P³SG specification.
// ══════════════════════════════════════════════════════════════
const PLANETARY_WEIGHT = 0.4;
const REGENERATIVE_THRESHOLD = 0.75;  // above this → REGENERATIVE signal
const PLANET_DRIFT_THRESHOLD = 0.3;   // below this + high regenerative → REGENERATIVE

const WARN_THRESHOLD = 0.45;            // composite ≥ this → advisory WARN
const REVIEW_THRESHOLD = 0.70;          // composite ≥ this → REQUIRE_APPROVAL

// ══════════════════════════════════════════════════════════════
// Planetary Maqṣad Computation (PPP)
// ══════════════════════════════════════════════════════════════

/**
 * Compute regenerative score from planet signal history.
 * Lower variance in the combined Public+Planet trajectory implies
 * stable, regenerative cycles.
 *
 * @param {object} planet — { signal: number[], history: number[][] }
 * @param {object} opts — { planetaryWeight: number }
 * @returns {number} in [0,1]; higher = more regenerative
 */
function computeRegenerativeScore(planet, opts = {}) {
  if (!planet || !planet.signal || !planet.signal.length) return 0.65;
  const pw = opts.planetaryWeight != null ? opts.planetaryWeight : PLANETARY_WEIGHT;
  const sig = Array.isArray(planet.signal) ? planet.signal : [planet.signal];
  const norm = Math.sqrt(sig.reduce((s, v) => s + (pw * v) * (pw * v), 0) / sig.length);
  const variance = sig.reduce((s, v) => s + (v - norm) * (v - norm), 0) / sig.length;
  return clamp01(1.0 - variance * 2.0);
}

/**
 * Compute planet drift via variance proxy of combined Public+Planet trajectory.
 *
 * @param {object} planet — { signal: number[], history: number[][] }
 * @param {object} opts — { planetaryWeight: number }
 * @returns {number} in [0,1]; higher = more drift
 */
function computePlanetDrift(planet, opts = {}) {
  if (!planet || !planet.history || planet.history.length < 5) return 0.1;
  const pw = opts.planetaryWeight != null ? opts.planetaryWeight : PLANETARY_WEIGHT;
  const recent = planet.history.slice(-20);
  const combined = recent.map(row => {
    const pub = row.slice(0, -1).reduce((a, b) => a + b, 0) / (row.length - 1 || 1);
    const plan = (row[row.length - 1] || 0) * pw;
    return pub + plan;
  });
  const mean = combined.reduce((a, b) => a + b, 0) / combined.length;
  const variance = combined.reduce((s, v) => s + (v - mean) * (v - mean), 0) / combined.length;
  return clamp01(variance * 3.0);
}

/**
 * Full Planetary Maqṣad assessment.
 * Returns REGENERATIVE when planet_regenerative is high and planet_drift is low.
 *
 * @param {object} features — output of extractFeatures()
 * @returns {{ signal: string, regenerativeScore: number, driftScore: number, satisfied: boolean }}
 */
function planetaryMaqsad(features) {
  const regenerative = features.planet_regenerative || 0.65;
  const drift = features.planet_drift || 0.1;
  const satisfied = regenerative > REGENERATIVE_THRESHOLD && drift < PLANET_DRIFT_THRESHOLD;
  return {
    signal: satisfied ? 'REGENERATIVE' : 'NONE',
    regenerativeScore: +regenerative.toFixed(4),
    driftScore: +drift.toFixed(4),
    satisfied,
    planetaryWeight: PLANETARY_WEIGHT
  };
}

/**
 * ConformalCalibrator — distribution-free calibration of the advisory
 * threshold (ported from the Python governance-proxy's conformal layer).
 *
 * Instead of magic fixed thresholds, we keep a rolling window of recent
 * composite scores and flag a score only when it lands in the top `alpha`
 * fraction of that empirical distribution. This gives an HONEST, bounded
 * interpretation: a WARN means "this traffic is more anomalous than
 * (1-alpha) of recent traffic" — a calibrated novelty rate, NOT a claim
 * that the underlying premises are valid.
 *
 * Split-conformal guarantee (exchangeability assumption): under i.i.d./
 * exchangeable benign traffic, the long-run flag rate ≈ alpha. It still
 * makes NO claim that a flagged item is actually malicious — it remains
 * advisory and can never DENY.
 */
class ConformalCalibrator {
  /**
   * @param {object} opts
   * @param {number} opts.warnAlpha   — target flag rate for WARN (e.g. 0.10)
   * @param {number} opts.reviewAlpha — target flag rate for REQUIRE_APPROVAL (e.g. 0.02)
   * @param {number} opts.window      — calibration window size
   * @param {number} opts.minSamples  — below this, fall back to fixed thresholds
   */
  constructor(opts = {}) {
    this.warnAlpha = opts.warnAlpha != null ? opts.warnAlpha : 0.10;
    this.reviewAlpha = opts.reviewAlpha != null ? opts.reviewAlpha : 0.02;
    this.window = opts.window || 1500;
    this.minSamples = opts.minSamples || 100;
    this.scores = [];
  }

  /** Record a composite score into the calibration set (rolling window). */
  observe(score) {
    const s = clamp01(score);
    this.scores.push(s);
    if (this.scores.length > this.window) {
      this.scores = this.scores.slice(-this.window);
    }
  }

  /** Empirical (1-alpha) quantile of the calibration set. */
  quantile(alpha) {
    const n = this.scores.length;
    if (n === 0) return null;
    const sorted = this.scores.slice().sort((a, b) => a - b);
    // Conformal rank: ceil((n+1)(1-alpha)) / n, clamped to a valid index.
    const rank = Math.ceil((n + 1) * (1 - alpha));
    const idx = Math.min(n - 1, Math.max(0, rank - 1));
    return sorted[idx];
  }

  /**
   * Classify a composite score into an advisory signal using calibrated
   * thresholds when enough data exists, else the fixed fallbacks.
   *
   * Regime-aware adaptation (idea #4): pass `tighten` ∈ (0,1] to shrink the
   * effective α during instability (e.g. when CUSUM flags a regime change),
   * making the threshold stricter while the system is unsettled. tighten=1 is
   * the normal (anytime-valid split-conformal) behaviour.
   *
   * @returns {{signal, calibrated, warnThreshold, reviewThreshold, n, tighten}}
   */
  classify(score, opts = {}) {
    const s = clamp01(score);
    const tighten = (typeof opts.tighten === 'number' && opts.tighten > 0 && opts.tighten <= 1) ? opts.tighten : 1;
    const calibrated = this.scores.length >= this.minSamples;
    const warnT = calibrated ? this.quantile(this.warnAlpha * tighten) : WARN_THRESHOLD;
    const reviewT = calibrated ? this.quantile(this.reviewAlpha * tighten) : REVIEW_THRESHOLD;

    let signal = 'NONE';
    if (s >= reviewT) signal = 'REQUIRE_APPROVAL';
    else if (s >= warnT) signal = 'WARN';

    return {
      signal,                                  // NONE | WARN | REQUIRE_APPROVAL (never DENY)
      calibrated,                              // false = using fixed fallback thresholds
      warnThreshold: +Number(warnT).toFixed(4),
      reviewThreshold: +Number(reviewT).toFixed(4),
      tighten: +tighten.toFixed(3),
      n: this.scores.length,
    };
  }
}

/**
 * Compute a bounded composite advisory score from the feature vector.
 * Returns a signal object — explicitly advisory, never a DENY.
 */
function composite(features) {
  let score = 0, wsum = 0;
  for (const k in FEATURE_WEIGHTS) {
    score += (features[k] || 0) * FEATURE_WEIGHTS[k];
    wsum  += FEATURE_WEIGHTS[k];
  }
  const composite = clamp01(wsum > 0 ? score / wsum : 0);

  // Which features meaningfully contributed (for explainability).
  const contributors = Object.keys(features)
    .filter(k => (features[k] || 0) >= 0.5)
    .sort((a, b) => (features[b] || 0) - (features[a] || 0));

  let signal = 'NONE';
  if (composite >= REVIEW_THRESHOLD) signal = 'REQUIRE_APPROVAL';
  else if (composite >= WARN_THRESHOLD) signal = 'WARN';

  return {
    advisory: true,            // NEVER authoritative — features only
    composite,
    signal,                    // NONE | WARN | REQUIRE_APPROVAL (never DENY)
    contributors,
    note: 'Nature-inspired signals are unvalidated advisory features; they cannot DENY real traffic.',
  };
}

class NatureFeatureExtractor {
  /**
   * @param {object} opts — { conformal: true|ConformalCalibratorOpts }
   *   When enabled, the advisory signal is set by calibrated quantiles
   *   (bounded flag rate) instead of the fixed WARN/REVIEW thresholds.
   */
  constructor(opts = {}) {
    this.calibrator = opts.conformal
      ? new ConformalCalibrator(typeof opts.conformal === 'object' ? opts.conformal : {})
      : null;

    // ── 15 NOVEL MODULES: Flag correlation fuser for evidential weighting ──
    this.flagCorrelator = new FlagCorrelationFuser();

    // Rolling history for orthogonal evasion bound computation
    this._detectorScoreHistory = [];
    this._maxDetectorHistory = 200;
  }

  /**
   * @param {object} rawResults — keyed analyzer outputs (see extractFeatures)
   * @param {object} opts — { tighten, computeEvasionBound }
   * @returns {{features, composite, signal, contributors, advisory, calibration?, flagWeight?, evasionBound?}}
   */
  evaluate(rawResults, opts = {}) {
    const features = extractFeatures(rawResults, opts);
    const c = composite(features);

    // ── Flag Correlation: compute evidential weight from feature flags ──
    // Lazily initialize the fuser with a stable, ordered key list on first use,
    // then pass a flag ARRAY (flags[i] ↔ detectorIds[i]) as the API requires.
    const featureKeys = Object.keys(features);
    if (!this._flagKeys) {
      this._flagKeys = featureKeys;
      this.flagCorrelator.initializeDetectors(this._flagKeys);
    }
    const flagArray = this._flagKeys.map(k => (typeof features[k] === 'number' && features[k] >= 0.5) ? 1 : 0);
    let flagWeight = null;
    try {
      this.flagCorrelator.observe(flagArray);
      flagWeight = this.flagCorrelator.computeEvidentialWeight(flagArray);
    } catch (_) { /* advisory only — never block on fusion errors */ }

    // ── Orthogonal Manifold Evasion Bound ────────────────────
    let evasionBound = null;
    if (opts.computeEvasionBound) {
      const featureArray = Object.entries(features)
        .filter(([_, v]) => typeof v === 'number' && isFinite(v));
      const detectorScores = featureArray.map(([id, score], i) => ({
        id: id || `feature_${i}`,
        score: clamp01(score),
        threshold: 0.5,
        coverage: 0.8,
      }));
      evasionBound = computeOrthogonalEvasionBound(detectorScores);
    }

    // Accumulate detector scores for rolling history
    if (opts.computeEvasionBound) {
      for (const [id, score] of Object.entries(features)) {
        if (typeof score === 'number' && isFinite(score)) {
          this._detectorScoreHistory.push({ id, score, ts: Date.now() });
        }
      }
      if (this._detectorScoreHistory.length > this._maxDetectorHistory * Object.keys(features).length) {
        this._detectorScoreHistory = this._detectorScoreHistory.slice(-this._maxDetectorHistory * Object.keys(features).length);
      }
    }

    if (this.calibrator) {
      // Calibrate against history (regime-aware tightening), then observe.
      const cal = this.calibrator.classify(c.composite, { tighten: opts.tighten });
      this.calibrator.observe(c.composite);
      return {
        features, ...c, signal: cal.signal, calibration: cal,
        flagWeight: flagWeight.evidential_weight !== undefined
          ? +flagWeight.evidential_weight.toFixed(4) : null,
        evasionBound: evasionBound ? {
          evasionWorkBits: +evasionBound.evasion_work_bits.toFixed(2),
          complexityClass: evasionBound.evasion_complexity_class,
          isOrthogonal: evasionBound.is_orthogonal,
        } : null,
      };
    }
    return {
      features, ...c,
      flagWeight: flagWeight.evidential_weight !== undefined
        ? +flagWeight.evidential_weight.toFixed(4) : null,
      evasionBound: evasionBound ? {
        evasionWorkBits: +evasionBound.evasion_work_bits.toFixed(2),
        complexityClass: evasionBound.evasion_complexity_class,
        isOrthogonal: evasionBound.is_orthogonal,
      } : null,
    };
  }
}

module.exports = {
  NatureFeatureExtractor,
  ConformalCalibrator,
  extractFeatures,
  composite,
  planetaryMaqsad,
  computeRegenerativeScore,
  computePlanetDrift,
  FEATURE_WEIGHTS,
  PLANETARY_WEIGHT,
  REGENERATIVE_THRESHOLD,
  PLANET_DRIFT_THRESHOLD,
  WARN_THRESHOLD,
  REVIEW_THRESHOLD,
};
