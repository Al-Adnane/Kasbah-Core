/**
 * HarmonicDissonance — Fourier Overtone Analysis for Intent Signal Detection
 *
 * SOURCE FIELD: Music Theory + Signal Processing
 *
 * A musician hears HARMONY when frequencies are in simple integer ratios
 * (octaves, fifths, thirds). DISSONANCE occurs when frequencies clash —
 * creating beating, roughness, and tension.
 *
 * Applied to AI agents: legitimate multi-agent collaboration produces
 * HARMONIC intent signals (agents' purposes align in clean frequency ratios).
 * Adversarial coordination produces DISSONANT signals — intents that are
 * individually valid but clash when combined, like playing two notes
 * a semitone apart.
 *
 * Algorithm:
 * 1. Convert agent action sequences into frequency domain via DFT
 * 2. Extract fundamental frequencies and overtone series
 * 3. Compute consonance/dissonance using Plomp-Levelt roughness model
 * 4. Detect "tritone" intervals — the "devil's interval" in music —
 *    which map to maximally clashing but individually-valid agent intents
 *
 * WHY THIS IS UNPRECEDENTED: Security tools look at CONTENT or BEHAVIOR.
 * HarmonicDissonance listens to the MUSIC of agent interactions —
 * the frequency structure of their actions over time. A safe multi-agent
 * system sounds like a symphony. An attack sounds like noise.
 */

'use strict';

const SEMITONE_RATIO = Math.pow(2, 1 / 12);  // ≈ 1.05946
const TRITONE_RATIO = Math.pow(2, 6 / 12);   // ≈ 1.41421 (√2)

/**
 * Compute DFT of a real-valued signal.
 * Returns array of { frequency, magnitude, phase } objects.
 */
function dft(signal) {
  const N = signal.length;
  const spectrum = [];

  for (let k = 0; k < Math.floor(N / 2); k++) {
    let re = 0, im = 0;
    for (let n = 0; n < N; n++) {
      const angle = -2 * Math.PI * k * n / N;
      re += signal[n] * Math.cos(angle);
      im += signal[n] * Math.sin(angle);
    }
    re /= N;
    im /= N;
    const magnitude = Math.sqrt(re * re + im * im);
    const phase = Math.atan2(im, re);
    spectrum.push({ frequency: k, magnitude, phase });
  }

  return spectrum;
}

/**
 * Extract dominant frequencies (peaks in spectrum).
 */
function extractPeaks(spectrum, threshold = 0.1) {
  const maxMag = Math.max(...spectrum.map(s => s.magnitude));
  return spectrum
    .filter(s => s.magnitude > maxMag * threshold && s.frequency > 0)
    .sort((a, b) => b.magnitude - a.magnitude);
}

/**
 * Plomp-Levelt roughness model for two frequencies.
 * Models psychoacoustic dissonance between two pure tones.
 *
 * R(f1, f2) = exp(-3.5 * s * |f2-f1|) - exp(-5.75 * s * |f2-f1|)
 * where s = 0.24 / (0.021 * fmin + 19)
 *
 * Returns roughness value (0 = consonant, ~0.5 = maximally dissonant)
 */
function plompLeveltRoughness(f1, f2) {
  if (f1 === 0 || f2 === 0) return 0;
  const fmin = Math.min(f1, f2);
  const fmax = Math.max(f1, f2);
  const df = fmax - fmin;
  const s = 0.24 / (0.021 * fmin + 19);
  return Math.exp(-3.5 * s * df) - Math.exp(-5.75 * s * df);
}

/**
 * Check if two frequencies form a tritone interval (devil's interval).
 * In music: exactly 6 semitones apart (frequency ratio ≈ √2).
 * Tolerance: ±0.5 semitone.
 */
function isTritone(f1, f2) {
  if (f1 === 0 || f2 === 0) return false;
  const ratio = Math.max(f1, f2) / Math.min(f1, f2);
  const semitones = 12 * Math.log2(ratio);
  return Math.abs(semitones - 6) < 0.5;
}

/**
 * Compute consonance score between two frequency sets.
 * Based on simple integer ratios (octave=2:1, fifth=3:2, fourth=4:3).
 * Returns 0-1 (0 = maximally dissonant, 1 = perfectly consonant).
 */
function consonanceScore(freqsA, freqsB) {
  if (freqsA.length === 0 || freqsB.length === 0) return 1;

  const consonantRatios = [1, 2, 3 / 2, 4 / 3, 5 / 4, 5 / 3, 6 / 5];
  let totalConsonance = 0;
  let pairs = 0;

  for (const a of freqsA) {
    for (const b of freqsB) {
      if (a.frequency === 0 || b.frequency === 0) continue;
      const ratio = Math.max(a.frequency, b.frequency) /
                    Math.min(a.frequency, b.frequency);

      // Find closest consonant ratio
      let minDist = Infinity;
      for (const cr of consonantRatios) {
        const dist = Math.abs(ratio - cr);
        if (dist < minDist) minDist = dist;
      }

      // Consonance = inverse of distance to nearest consonant ratio
      const cons = 1 / (1 + minDist * 10);
      totalConsonance += cons * Math.min(a.magnitude, b.magnitude);
      pairs++;
    }
  }

  return pairs > 0 ? totalConsonance / pairs : 1;
}

class HarmonicDissonance {
  constructor(options = {}) {
    this.windowSize = options.windowSize || 64;
    this.dissonanceThreshold = options.dissonanceThreshold || 0.6;
    this.agentSignals = new Map();  // agentId → action sequence
    this.alerts = [];
  }

  /**
   * Record an action from an agent.
   * @param {string} agentId — agent identifier
   * @param {number} actionValue — numeric representation of action (e.g., risk score, action type enum)
   */
  record(agentId, actionValue) {
    if (!this.agentSignals.has(agentId)) {
      this.agentSignals.set(agentId, []);
    }
    const signal = this.agentSignals.get(agentId);
    signal.push(actionValue);
    if (signal.length > this.windowSize) signal.shift();
  }

  /**
   * Analyze harmonic relationships between all agent pairs.
   * Returns { overallDissonance, tritoneDetected, agentPairs, regime }
   */
  analyze() {
    const start = Date.now();
    const agentIds = Array.from(this.agentSignals.keys());
    const n = agentIds.length;

    if (n < 2) {
      return { regime: 'SOLO', dissonance: 0, agents: n };
    }

    // Compute DFT for each agent's signal
    const spectra = new Map();
    for (const id of agentIds) {
      const signal = this.agentSignals.get(id);
      if (signal.length >= 8) {
        const spec = dft(signal);
        const peaks = extractPeaks(spec, 0.15);
        spectra.set(id, { spectrum: spec, peaks });
      }
    }

    // Analyze all agent pairs
    const pairs = [];
    let totalRoughness = 0;
    let tritoneCount = 0;
    let pairCount = 0;

    for (let i = 0; i < agentIds.length; i++) {
      for (let j = i + 1; j < agentIds.length; j++) {
        const specA = spectra.get(agentIds[i]);
        const specB = spectra.get(agentIds[j]);
        if (!specA || !specB) continue;

        // Compute pairwise roughness
        let pairRoughness = 0;
        let roughnessCount = 0;
        let pairTritones = 0;

        for (const a of specA.peaks.slice(0, 5)) {
          for (const b of specB.peaks.slice(0, 5)) {
            const r = plompLeveltRoughness(a.frequency, b.frequency);
            pairRoughness += r * Math.min(a.magnitude, b.magnitude);
            roughnessCount++;

            if (isTritone(a.frequency, b.frequency)) {
              pairTritones++;
            }
          }
        }

        const avgRoughness = roughnessCount > 0 ? pairRoughness / roughnessCount : 0;
        const consonance = consonanceScore(specA.peaks, specB.peaks);

        pairs.push({
          agentA: agentIds[i],
          agentB: agentIds[j],
          roughness: +avgRoughness.toFixed(6),
          consonance: +consonance.toFixed(6),
          tritones: pairTritones,
          dissonant: avgRoughness > this.dissonanceThreshold,
        });

        totalRoughness += avgRoughness;
        tritoneCount += pairTritones;
        pairCount++;
      }
    }

    const overallDissonance = pairCount > 0 ? totalRoughness / pairCount : 0;

    // Regime classification
    let regime;
    if (overallDissonance < 0.2 && tritoneCount === 0) {
      regime = 'SYMPHONY';     // Harmonious — safe
    } else if (tritoneCount > 0) {
      regime = 'DEVIL_INTERVAL'; // Tritone detected — maximally suspicious
    } else if (overallDissonance > this.dissonanceThreshold) {
      regime = 'CACOPHONY';    // General dissonance — likely attack
    } else {
      regime = 'TENSION';      // Moderate dissonance — warning
    }

    const alert = regime === 'DEVIL_INTERVAL' || regime === 'CACOPHONY';

    const latencyMs = Date.now() - start;

    const result = {
      regime,
      alert,
      overallDissonance: +overallDissonance.toFixed(6),
      tritoneCount,
      consonantPairs: pairs.filter(p => !p.dissonant).length,
      dissonantPairs: pairs.filter(p => p.dissonant).length,
      pairs,
      agents: n,
      latencyMs,
    };

    if (alert) {
      this.alerts.push({ ...result, timestamp: Date.now() });
    }

    return result;
  }

  getAlerts() { return this.alerts; }
  reset() { this.agentSignals.clear(); this.alerts = []; }
}

module.exports = { HarmonicDissonance, dft, extractPeaks, plompLeveltRoughness, isTritone };
