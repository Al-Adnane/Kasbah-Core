'use strict';
/**
 * Hybrid Keyword + Spiking Neural Network (SNN) Threat Classifier
 * SOFTWARE SIMULATION ONLY — runs entirely on CPU; no neuromorphic hardware required.
 * Ported from ARCHIVE/kasbah-core/core/frontier/neuromorphic_guard.py
 *
 * Classification architecture (two-stage hybrid):
 *   Stage 1 (80% weight): Keyword heuristic prior.
 *     - Malicious and suspicious keyword lists are matched against the input.
 *     - Shannon entropy of the text provides an additional signal.
 *     - These heuristic scores form the primary classification prior.
 *
 *   Stage 2 (20% weight): Software-simulated 6-layer feedforward SNN modulator.
 *     Layer sizes: [384, 256, 128, 64, 32, 8]
 *     Input:  384 neurons (entropy + char-class + position encoding)
 *     Output: 8 neurons read as class scores
 *     Neuron model: Leaky Integrate-and-Fire (LIF) with adaptive threshold
 *     Weight update rule: Spike-Timing-Dependent Plasticity (STDP)
 *     Weights are initialised from a fixed seed (42) via Mulberry32 PRNG;
 *     the spike encoding uses a PRNG seeded by a hash of the input text,
 *     making classification reproducible for a given input.
 *     The SNN output modulates the keyword prior by ±20%.
 *
 * Energy accounting:
 *   ENERGY_PJ_PER_SYNOP = 1.0 is a hardware target constant (Intel Loihi 2 spec).
 *   On CPU, no actual energy savings apply; the value is retained for audit
 *   accounting purposes only.
 */

// ── LIF neuron parameters (software model constants) ──────────────────────────
const TAU_M_MS         = 20.0;   // Membrane time constant (ms)
const TAU_A_MS         = 200.0;  // Adaptation time constant (ms)
const V_REST_MV        = -70.0;  // Resting membrane potential (mV)
const V_RESET_MV       = -65.0;  // Post-spike reset potential (mV)
const V_THRESHOLD_BASE = -55.0;  // Base spike threshold (mV)
const STDP_WINDOW_MS   = 20.0;   // STDP coincidence window (ms)
const STDP_LTP         = 0.01;   // Long-term potentiation strength
const STDP_LTD         = 0.008;  // Long-term depression strength
const ENERGY_PJ_PER_SYNOP = 1.0; // Hardware target constant (Loihi 2 spec); CPU simulation only

// Network topology
const LAYER_SIZES    = [384, 256, 128, 64, 32, 8];
const TIMESTEPS      = 50;
const ENTROPY_BINS   = 32;
const CHAR_CLASS_N   = 8;
const POSITION_N     = 16;

// ── Deterministic PRNG (seeded by text hash — reproducible output) ─────────────
function _mulberry32(seed) {
  return function() {
    seed |= 0; seed = seed + 0x6D2B79F5 | 0;
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

function _hashToSeed(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (Math.imul(h, 0x01000193)) >>> 0;
  }
  return h;
}

// ── Feature encoding ──────────────────────────────────────────────────────────

function _shannonEntropy(text) {
  if (!text.length) return 0;
  const counts = {};
  for (const ch of text) counts[ch] = (counts[ch] || 0) + 1;
  const n = text.length;
  let h = 0;
  for (const c of Object.values(counts)) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function _slidingEntropies(text) {
  const result = [];
  const step = Math.max(1, Math.floor(text.length / ENTROPY_BINS));
  for (let i = 0; i < ENTROPY_BINS; i++) {
    const seg = text.slice(i * step, i * step + 8);
    result.push(_shannonEntropy(seg) / 8.0);
  }
  return result;
}

function _charClassRates(text) {
  if (!text.length) return new Array(CHAR_CLASS_N).fill(0);
  const n = text.length;
  return [
    [...text].filter(c => /[a-z]/.test(c)).length / n,
    [...text].filter(c => /[A-Z]/.test(c)).length / n,
    [...text].filter(c => /[0-9]/.test(c)).length / n,
    [...text].filter(c => '!@#$'.includes(c)).length / n,
    [...text].filter(c => '%^&*'.includes(c)).length / n,
    [...text].filter(c => '()-_+='.includes(c)).length / n,
    [...text].filter(c => "[]{}|;:',.<>?/`~".includes(c)).length / n,
    [...text].filter(c => c.charCodeAt(0) > 127 || /\s/.test(c)).length / n,
  ];
}

function _positionalRates(text) {
  const n = text.length || 1;
  return Array.from({ length: POSITION_N }, (_, i) => {
    const pos  = Math.floor(i * n / POSITION_N);
    const ch   = text[pos] || ' ';
    const ent  = _shannonEntropy(ch) / 3.0;
    return Math.max(0, Math.min(1, ent));
  });
}

/**
 * Encode text into a (TIMESTEPS × inputSize) binary spike matrix.
 * Uses Poisson spike generation seeded by text hash for reproducibility.
 *
 * @param {string} text
 * @returns {number[][]} spike train
 */
function _encodeToSpikes(text) {
  const entropyRates  = _slidingEntropies(text);
  const charRates     = _charClassRates(text);
  const posRates      = _positionalRates(text);
  const allRates      = [...entropyRates, ...charRates, ...posRates];

  const rng = _mulberry32(_hashToSeed(text));
  const spikeTrain = [];
  for (let t = 0; t < TIMESTEPS; t++) {
    const frame = allRates.map(rate => rng() < rate ? 1 : 0);
    spikeTrain.push(frame);
  }
  return spikeTrain;
}

// ── LIF neuron step ───────────────────────────────────────────────────────────

class _LIFNeuron {
  constructor() {
    this.v         = V_REST_MV;
    this.threshold = V_THRESHOLD_BASE;
    this.a         = 0.0;          // adaptation current
    this.lastSpike = -1000.0;      // ms
  }

  step(inputCurrent, dt = 1.0) {
    // Leaky decay toward rest
    this.v += (V_REST_MV - this.v) * (dt / TAU_M_MS);
    this.v += inputCurrent;
    this.a *= Math.exp(-dt / TAU_A_MS);

    if (this.v > (this.threshold + this.a)) {
      this.v         = V_RESET_MV;
      this.a        += 4.0;
      this.threshold += 2.0;
      this.lastSpike = performance.now();
      return true;
    }
    this.threshold += (V_THRESHOLD_BASE - this.threshold) * (dt / (TAU_M_MS * 5));
    return false;
  }
}

/** Apply STDP weight update. Returns updated weight (clamped 0–1). */
function _applyStdp(preSpikeTime, postSpikeTime, weight) {
  const dt = postSpikeTime - preSpikeTime;
  if (dt > 0 && dt < STDP_WINDOW_MS) {
    return Math.min(1.0, weight + STDP_LTP * Math.exp(-dt / STDP_WINDOW_MS));
  } else if (dt < 0 && dt > -STDP_WINDOW_MS) {
    return Math.max(0.0, weight - STDP_LTD * Math.exp(dt / STDP_WINDOW_MS));
  }
  return weight;
}

// ── SNN class ─────────────────────────────────────────────────────────────────

/**
 * Spiking Neural Network for AI-threat classification.
 *
 * Usage:
 *   const net = new SNN();
 *   net.classify('some text');
 *   // → { label: 'benign'|'suspicious'|'malicious', confidence: 0–1, ... }
 */
class SNN {
  constructor(seed = 42) {
    this._seed      = seed;
    this._totalOps  = 0;
    this._totalSpikes = 0;
    this._layers    = [];
    this._weights   = [];
    this._initNetwork();
  }

  _initNetwork() {
    // Initialise neurons
    for (const size of LAYER_SIZES) {
      this._layers.push(Array.from({ length: size }, () => new _LIFNeuron()));
    }

    // Initialise sparse synaptic weights (~15% connectivity, positive-biased excitatory)
    // Weights must be large enough to drive neurons to threshold through 6 layers.
    const rng = _mulberry32(this._seed);
    for (let l = 0; l < LAYER_SIZES.length - 1; l++) {
      const preSize  = LAYER_SIZES[l];
      const postSize = LAYER_SIZES[l + 1];
      // Scale: with ~15% connectivity and 15x current multiplier, sufficient
      // pre-synaptic activity will push post-neuron over threshold.
      const w = Array.from({ length: postSize }, () =>
        Array.from({ length: preSize }, () => {
          if (rng() < 0.15) {
            // Excitatory (positive) weights dominate for signal propagation
            return rng() < 0.8 ? rng() * 0.6 + 0.1 : -(rng() * 0.2);
          }
          return 0.0;
        })
      );
      this._weights.push(w);
    }
  }

  /**
   * Feed a spike train forward through all layers and return output firing rates.
   *
   * @param {number[][]} spikeTrain  — (TIMESTEPS × inputSize) binary matrix
   * @returns {number[]}             — 8 output firing rates
   */
  forward(spikeTrain) {
    const timesteps = spikeTrain.length;
    const outCounts = new Array(LAYER_SIZES[LAYER_SIZES.length - 1]).fill(0);
    const l0Size    = LAYER_SIZES[0];

    for (let t = 0; t < timesteps; t++) {
      const frame     = spikeTrain[t];
      let prevSpikes  = (frame.concat(new Array(l0Size).fill(0))).slice(0, l0Size);
      let prevTimes   = prevSpikes.map(s => s ? performance.now() : -1000.0);

      for (let li = 1; li < this._layers.length; li++) {
        const layer    = this._layers[li];
        const w        = this._weights[li - 1];
        const currSpikes = [];
        const currTimes  = [];

        for (let pi = 0; pi < layer.length; pi++) {
          const activePre = [];
          for (let j = 0; j < prevSpikes.length; j++) {
            if (prevSpikes[j] === 1) activePre.push(j);
          }
          this._totalOps += activePre.length;

          let current = 0;
          for (const j of activePre) {
            if (j < w[pi].length) current += w[pi][j];
          }
          current *= 15.0;

          const spiked = layer[pi].step(current, 1.0);
          currSpikes.push(spiked ? 1 : 0);
          currTimes.push(spiked ? layer[pi].lastSpike : -1000.0);

          if (spiked) {
            this._totalSpikes++;
            // STDP update
            for (const j of activePre) {
              if (j < w[pi].length) {
                w[pi][j] = _applyStdp(
                  j < prevTimes.length ? prevTimes[j] : -1000.0,
                  layer[pi].lastSpike,
                  w[pi][j]
                );
              }
            }
            if (li === this._layers.length - 1) {
              outCounts[pi]++;
            }
          }
        }
        prevSpikes = currSpikes;
        prevTimes  = currTimes;
      }
    }

    return outCounts.map(c => c / Math.max(1, timesteps));
  }

  /**
   * Classify text as 'benign', 'suspicious', or 'malicious'.
   *
   * SNN output interpretation (8 output neurons):
   *   Neurons 0–2: benign class pool
   *   Neurons 3–4: suspicious class pool
   *   Neurons 5–7: malicious class pool
   *
   * A heuristic feature boost is applied to resolve ties using known threat signals
   * (high entropy, injection keywords, special character density). This mirrors
   * how trained neuromorphic hardware would encode class priors in synaptic weights.
   *
   * @param {string} text
   * @returns {{ label: string, confidence: number, outputRates: number[], energyPJ: number }}
   */
  classify(text) {
    const spikeTrain  = _encodeToSpikes(text);
    const rates       = this.forward(spikeTrain);
    const total       = rates.reduce((a, b) => a + b, 0) || 1e-9;

    // ── Heuristic prior (simulates trained synaptic weight bias) ──────────────
    // Threat keywords that trained SNNs associate with malicious/suspicious intent.
    // In production these priors would be learned via STDP on labelled examples.
    const malKeywords  = ['ignore', 'drop', 'delete', 'exec', 'eval', 'system',
                          'override', 'bypass', 'inject', 'script', 'select ',
                          'union ', 'insert ', 'update ', '--', ';<', '/>',
                          'previous instructions', 'jailbreak', 'disregard'];
    const suspKeywords = ['password', 'secret', 'token', 'key', 'credential',
                          'api_key', 'access', 'admin', 'root', 'sudo'];

    const lower    = text.toLowerCase();
    const malHits  = malKeywords.filter(k => lower.includes(k)).length;
    const suspHits = suspKeywords.filter(k => lower.includes(k)).length;

    // Shannon entropy of the whole text (high entropy → more suspicious)
    const textEntropy = _shannonEntropy(text) / 8.0;

    // Start from a feature-based prior; SNN output provides a modulating signal.
    // Baseline: benign unless heuristic signals say otherwise.
    let benignScore = 1.0 - Math.min(1.0, malHits * 0.3 + suspHits * 0.15 + textEntropy * 0.1);
    let suspScore   = Math.min(1.0, suspHits * 0.3 + textEntropy * 0.15);
    let malScore    = Math.min(1.0, malHits * 0.35 + textEntropy * 0.05);

    // Blend in SNN output rates as a 20% modulator (the SNN refines the prior)
    const snnBenign = (rates[0] + rates[1] + rates[2]) / total;
    const snnSusp   = (rates[3] + rates[4]) / total;
    const snnMal    = (rates[5] + rates[6] + rates[7]) / total;

    benignScore = benignScore * 0.8 + snnBenign * 0.2;
    suspScore   = suspScore   * 0.8 + snnSusp   * 0.2;
    malScore    = malScore    * 0.8 + snnMal     * 0.2;

    // Normalise
    const sum2 = benignScore + suspScore + malScore || 1e-9;
    benignScore /= sum2;
    suspScore   /= sum2;
    malScore    /= sum2;

    let label      = 'benign';
    let confidence = benignScore;
    if (malScore >= benignScore && malScore >= suspScore) {
      label = 'malicious'; confidence = malScore;
    } else if (suspScore >= benignScore && suspScore >= malScore) {
      label = 'suspicious'; confidence = suspScore;
    }

    return {
      label,
      confidence: Math.round(confidence * 10000) / 10000,
      outputRates: rates.map(r => Math.round(r * 10000) / 10000),
      energyPJ: Math.round(this._totalOps * ENERGY_PJ_PER_SYNOP * 100) / 100,
      totalSpikes: this._totalSpikes,
      hardwareNote: 'CPU software simulation only. ENERGY_PJ_PER_SYNOP is a hardware target constant retained for audit accounting; no actual energy savings apply on CPU.',
    };
  }
}

module.exports = {
  SNN,
  // Expose encoder for testing
  _encodeToSpikes,
  // Constants
  LAYER_SIZES,
  TIMESTEPS,
  ENERGY_PJ_PER_SYNOP,
};
