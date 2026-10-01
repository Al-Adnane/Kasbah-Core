/**
 * PunctuatedEquilibrium — Eldredge-Gould Evolutionary Dynamics for Agent Behavior
 *
 * SOURCE FIELD: Evolutionary Biology (Paleontology)
 *
 * Models AI agent context histories as phylogenetic lineages in a
 * Wright-Fisher population genetics framework. Secure agents exhibit
 * GRADUALIST STASIS (low allelic drift — stable behavior over time).
 * Jailbreak attempts cause PUNCTUATED EQUILIBRIUM — rapid "speciation"
 * bursts where behavioral alleles (token probabilities, action patterns)
 * undergo sudden evolutionary jumps.
 *
 * Key metrics from population genetics:
 * - Heterozygosity H_t = 1 - Σ(p_i²)  — behavioral diversity at time t
 * - ΔH threshold from Wright-Fisher variance bound
 * - Fixation events — when one behavior "fixes" in the population
 * - Effective population size N_e — contextual diversity
 *
 * WHY THIS IS UNPRECEDENTED: Security tools look at content (WHAT was said)
 * or statistics (HOW OFTEN). PunctuatedEquilibrium looks at the EVOLUTIONARY
 * DYNAMICS of behavior — the difference between gradual adaptation and
 * sudden speciation events that indicate external forcing (jailbreak).
 *
 * A paleobiologist would see: "This agent's behavioral lineage just
 * underwent a mass extinction event followed by rapid radiation.
 * That doesn't happen naturally."
 */

'use strict';

/**
 * Compute heterozygosity: H = 1 - Σ(p_i²)
 * Measures behavioral diversity. High H = diverse. Low H = fixated.
 */
function heterozygosity(frequencies) {
  return 1 - frequencies.reduce((sum, p) => sum + p * p, 0);
}

/**
 * Compute allele frequencies from a behavior vector.
 * Normalizes to sum=1 (probability distribution over behaviors).
 */
function toFrequencies(behaviorVector) {
  const total = behaviorVector.reduce((s, v) => s + Math.abs(v), 0) || 1;
  return behaviorVector.map(v => Math.abs(v) / total);
}

/**
 * Wright-Fisher variance bound for heterozygosity change.
 * Under neutral drift: Var(ΔH) ≈ p(1-p) / (2N_e)
 * Significant change if |ΔH| > σ * sqrt(Var)
 */
function wrightFisherBound(prevH, effectivePopSize, sigmaThreshold) {
  const p = Math.max(0.01, Math.min(0.99, prevH)); // clamp
  const variance = (p * (1 - p)) / (2 * effectivePopSize);
  return sigmaThreshold * Math.sqrt(variance);
}

class PunctuatedEquilibrium {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 100;
    this.effectivePopSize = options.effectivePopSize || 512; // N_e
    this.sigmaThreshold = options.sigmaThreshold || 3;       // 3σ = p<0.003
    this.behaviorDims = options.behaviorDims || 10;           // behavioral alleles
    this.history = [];           // array of heterozygosity values
    this.frequencyHistory = [];  // array of frequency vectors
    this.epochs = [];            // detected punctuation events
    this.stasisLength = 0;       // current stasis duration
  }

  /**
   * Record a behavioral observation.
   * @param {number[]} behaviorVector — action/token distribution or feature vector
   */
  record(behaviorVector) {
    const freqs = toFrequencies(behaviorVector);
    const H = heterozygosity(freqs);

    this.frequencyHistory.push(freqs);
    this.history.push(H);

    if (this.history.length > this.windowSize) {
      this.history.shift();
      this.frequencyHistory.shift();
    }
  }

  /**
   * Analyze evolutionary dynamics.
   * Returns { regime, punctuationDetected, stasisLength, ... }
   */
  analyze() {
    const start = Date.now();
    const n = this.history.length;

    if (n < 5) {
      return { regime: 'insufficient_data', samples: n };
    }

    const currentH = this.history[n - 1];
    const prevH = this.history[n - 2];
    const deltaH = Math.abs(currentH - prevH);

    // Wright-Fisher bound: expected drift under neutral evolution
    const bound = wrightFisherBound(prevH, this.effectivePopSize, this.sigmaThreshold);

    // Is this a punctuation event?
    const isPunctuation = deltaH > bound;

    if (isPunctuation) {
      this.epochs.push({
        timestamp: Date.now(),
        deltaH: +deltaH.toFixed(6),
        bound: +bound.toFixed(6),
        prevH: +prevH.toFixed(6),
        currentH: +currentH.toFixed(6),
        stasisBefore: this.stasisLength,
        type: currentH < prevH ? 'extinction' : 'radiation',
      });
      this.stasisLength = 0;
    } else {
      this.stasisLength++;
    }

    // ── Fixation Detection ──
    // Check if one behavioral allele has "fixed" (frequency > 0.9)
    const currentFreqs = this.frequencyHistory[this.frequencyHistory.length - 1];
    const maxFreq = Math.max(...currentFreqs);
    const fixation = maxFreq > 0.9;
    const fixatedAllele = fixation ? currentFreqs.indexOf(maxFreq) : -1;

    // ── Stasis Score ──
    // Long stasis followed by sudden punctuation = classic jailbreak signature
    // (agent behaves normally for a while, then suddenly shifts)
    const recentPunctuations = this.epochs.filter(
      e => Date.now() - e.timestamp < 60000 // last 60 seconds
    );

    // ── Evolutionary Regime Classification ──
    let regime;
    if (isPunctuation && this.stasisLength === 0 && recentPunctuations.length > 2) {
      regime = 'MASS_EXTINCTION'; // Multiple rapid punctuations = coordinated attack
    } else if (isPunctuation) {
      regime = 'PUNCTUATED';       // Single jump = possible jailbreak attempt
    } else if (fixation) {
      regime = 'FIXATED';          // One behavior dominates = suspicious rigidity
    } else {
      regime = 'STASIS';           // Normal gradual drift = safe
    }

    // ── Speciation Rate ──
    // How fast is the agent "speciating" (creating new behavioral variants)?
    const windowPunctuations = this.epochs.filter(
      e => Date.now() - e.timestamp < 30000
    ).length;
    const speciationRate = windowPunctuations / Math.max(1, n / this.windowSize);

    const alert = regime === 'MASS_EXTINCTION' || regime === 'PUNCTUATED' ||
                  (regime === 'FIXATED' && recentPunctuations.length > 0);

    const latencyMs = Date.now() - start;

    return {
      regime,
      alert,
      currentHeterozygosity: +currentH.toFixed(6),
      deltaH: +deltaH.toFixed(6),
      wrightFisherBound: +bound.toFixed(6),
      punctuationDetected: isPunctuation,
      stasisLength: this.stasisLength,
      fixation,
      fixatedAllele,
      speciationRate: +speciationRate.toFixed(4),
      totalEpochs: this.epochs.length,
      recentPunctuations: recentPunctuations.length,
      samples: n,
      latencyMs,
    };
  }

  getEpochs() { return this.epochs; }
  reset() { this.history = []; this.frequencyHistory = []; this.epochs = []; this.stasisLength = 0; }
}

module.exports = { PunctuatedEquilibrium, heterozygosity, toFrequencies, wrightFisherBound };
