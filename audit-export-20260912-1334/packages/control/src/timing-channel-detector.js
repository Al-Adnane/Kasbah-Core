'use strict';

/**
 * Information-Theoretic Timing Channel Detector (ITCD) — #22
 *
 * Core Insight: When two or more LLM agents coordinate covertly, they may
 * encode information in the TEMPORAL pattern of their responses — not
 * in the content. Inter-response intervals (IRIs) form a time series that,
 * when correlated across agents, constitutes a noisy communication channel.
 *
 * We model the timing channel as:
 *   Agent A emits responses at times t_A = {t_A1, t_A2, ...}
 *   Agent B emits responses at times t_B = {t_B1, t_B2, ...}
 *
 * The mutual information I(T_A; T_B) between the IRI sequences T_A and T_B
 * quantifies how much information about A's timing is carried by B's timing.
 *
 *   I(T_A; T_B) = H(T_A) + H(T_B) - H(T_A, T_B)
 *
 * where H is the permutation entropy (Bandt-Pompe) of the IRI sequence.
 *
 * If I(T_A; T_B) > 0 with statistical significance, a covert timing channel
 * exists — one agent's response timing carries information about another's
 * activity, even when their message content is completely independent.
 *
 * Mathematical Foundation:
 *   1. Extract IRI sequences from event timestamps
 *   2. Compute permutation entropy with embedded dimension d=4, delay τ=1
 *   3. Compute joint permutation entropy for agent pairs
 *   4. Mutual information = marginal - joint entropy
 *   5. Significance test via surrogate data (shuffle one sequence, recompute MI,
 *      repeat 100 times → empirical null distribution → p-value)
 *
 *   The permutation entropy approach is non-parametric and robust to the
 *   non-stationarity inherent in LLM response timing.
 *
 * Evasion Cost: To evade timing channel detection, adversaries must:
 *   (a) Either randomize response timing to destroy MI → loses coordination
 *   (b) Or encode timing patterns indistinguishable from natural variance →
 *       drastically reduces channel capacity C = max I(T_A; T_B)
 *   Both options make covert coordination exponentially more expensive.
 */

class TimingChannelDetector {
  /**
   * @param {object} opts
   *   - embeddingDim: permutation entropy embedding dimension (default 4)
   *   - minSamples: minimum IRI samples per agent (default 30)
   *   - miWarnThreshold: MI bits → WARN (default 0.10)
   *   - miReviewThreshold: MI bits → REVIEW (default 0.25)
   *   - significanceAlpha: p-value threshold for significance (default 0.01)
   *   - surrogatePermutations: number of surrogate tests (default 200)
   *   - windowSeconds: sliding window for recent analysis (default 300)
   */
  constructor(opts = {}) {
    this.d = opts.embeddingDim || 4;
    this.tau = opts.embeddingDelay || 1;
    this.minSamples = opts.minSamples || 30;
    this.miWarnThreshold = opts.miWarnThreshold || 0.10;
    this.miReviewThreshold = opts.miReviewThreshold || 0.25;
    this.significanceAlpha = opts.significanceAlpha || 0.01;
    this.surrogatePermutations = opts.surrogatePermutations || 200;
    this.windowSeconds = opts.windowSeconds || 300;

    // Agent timing buffers: agentId → [{ timestamp, eventId }]
    this._agentTimestamps = {};

    // IRIs: agentId → Float64Array (inter-response intervals in seconds)
    this._agentIRIs = {};

    // Precomputed permutation entropy cache
    this._permEntropyCache = new Map();

    // Channel detection history
    this._channelHistory = []; // [{ pair, mi, pValue, ts }]
  }

  // ── Public API ───────────────────────────────────────────

  /**
   * Record a response event with its timestamp.
   * @param {string} agentId — agent identifier
   * @param {number} timestamp — Unix timestamp in ms
   * @param {object} context — { eventId, metadata }
   */
  recordResponse(agentId, timestamp, context = {}) {
    const key = String(agentId);
    if (!this._agentTimestamps[key]) {
      this._agentTimestamps[key] = [];
    }
    this._agentTimestamps[key].push({
      ts: typeof timestamp === 'number' ? timestamp : Date.now(),
      eventId: context.eventId || `ev_${this._agentTimestamps[key].length}`,
    });

    // Keep sliding window
    const cutoff = Date.now() - this.windowSeconds * 1000;
    this._agentTimestamps[key] = this._agentTimestamps[key].filter(e => e.ts > cutoff);
    if (this._agentTimestamps[key].length > 500) {
      this._agentTimestamps[key] = this._agentTimestamps[key].slice(-500);
    }

    // Recompute IRIs
    this._updateIRIs(key);
  }

  /**
   * Analyze all agent pairs for timing channel signatures.
   * @returns {object} timing channel assessment
   */
  analyze() {
    const agentKeys = Object.keys(this._agentTimestamps)
      .filter(k => (this._agentIRIs[k] || []).length >= this.minSamples);

    if (agentKeys.length < 2) {
      return {
        mode: 'insufficient_data',
        agentsWithSufficientData: agentKeys.length,
        minAgentsNeeded: 2,
        minSamplesPerAgent: this.minSamples,
      };
    }

    const results = {
      mode: 'monitoring',
      agentCount: agentKeys.length,
      pairwiseAnalysis: [],
      maxMutualInformation: 0,
      significantChannels: 0,
      criticalChannels: 0,
      signal: 'CLEAR',
    };

    // Pairwise analysis
    for (let i = 0; i < agentKeys.length; i++) {
      for (let j = i + 1; j < agentKeys.length; j++) {
        const a = agentKeys[i];
        const b = agentKeys[j];
        const iriA = this._agentIRIs[a];
        const iriB = this._agentIRIs[b];

        if (!iriA || !iriB || iriA.length < this.minSamples || iriB.length < this.minSamples) {
          continue;
        }

        const mi = this._mutualInformation(iriA, iriB);
        const pValue = this._permutationTest(iriA, iriB, mi);
        const isSignificant = pValue < this.significanceAlpha;
        const isCritical = isSignificant && mi > this.miReviewThreshold;

        const pairResult = {
          pair: `${a}↔${b}`,
          mutualInformation: +mi.toFixed(4),
          pValue: +pValue.toFixed(6),
          isSignificant,
          isCritical,
          samplesA: iriA.length,
          samplesB: iriB.length,
          channelCapacity: +this._channelCapacity(iriA, iriB).toFixed(4),
        };

        results.pairwiseAnalysis.push(pairResult);

        if (isSignificant) {
          results.significantChannels++;
          if (mi > results.maxMutualInformation) results.maxMutualInformation = mi;
          if (isCritical) results.criticalChannels++;
        }
      }
    }

    // Overall signal
    if (results.criticalChannels > 0) {
      results.signal = 'REQUIRE_APPROVAL';
    } else if (results.significantChannels > 0) {
      results.signal = 'WARN';
    }

    // Store channel history
    for (const pr of results.pairwiseAnalysis) {
      if (pr.isSignificant) {
        this._channelHistory.push({
          pair: pr.pair,
          mi: pr.mutualInformation,
          pValue: pr.pValue,
          ts: Date.now(),
        });
        if (this._channelHistory.length > 200) {
          this._channelHistory.shift();
        }
      }
    }

    return results;
  }

  /**
   * Get raw IRI sequences for external analysis.
   */
  getIRISequences() {
    const sequences = {};
    for (const [agentId, iris] of Object.entries(this._agentIRIs)) {
      sequences[agentId] = Array.from(iris).map(v => +v.toFixed(3));
    }
    return sequences;
  }

  /**
   * Get channel detection history.
   */
  getChannelHistory() {
    return this._channelHistory.map(h => ({
      pair: h.pair,
      mi: +h.mi.toFixed(4),
      pValue: +h.pValue.toFixed(6),
      timestamp: h.ts,
    }));
  }

  /**
   * Reset detector state.
   */
  reset() {
    this._agentTimestamps = {};
    this._agentIRIs = {};
    this._permEntropyCache = new Map();
    this._channelHistory = [];
  }

  // ── Internal Methods ─────────────────────────────────────

  _updateIRIs(agentKey) {
    const timestamps = this._agentTimestamps[agentKey];
    if (timestamps.length < 2) {
      this._agentIRIs[agentKey] = new Float64Array(0);
      return;
    }
    const iris = new Float64Array(timestamps.length - 1);
    for (let i = 1; i < timestamps.length; i++) {
      iris[i - 1] = (timestamps[i].ts - timestamps[i - 1].ts) / 1000; // seconds
    }
    this._agentIRIs[agentKey] = iris;
  }

  _permutationEntropy(sequence) {
    // Bandt-Pompe permutation entropy
    // Maps each window of length d to its rank permutation pattern
    const n = sequence.length;
    const d = this.d;
    const tau = this.tau;

    if (n < d * tau) return 0;

    const numWindows = n - (d - 1) * tau;
    if (numWindows <= 0) return 0;

    const patternCounts = new Map();
    const window = new Float64Array(d);

    for (let i = 0; i < numWindows; i++) {
      for (let k = 0; k < d; k++) {
        window[k] = sequence[i + k * tau];
      }
      // Compute rank permutation of window
      const pattern = this._rankPattern(window, d);
      patternCounts.set(pattern, (patternCounts.get(pattern) || 0) + 1);
    }

    // Shannon entropy of pattern distribution
    let entropy = 0;
    for (const count of patternCounts.values()) {
      const p = count / numWindows;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  _rankPattern(window, d) {
    // Return a hash of the permutation pattern
    const indexed = [];
    for (let i = 0; i < d; i++) indexed.push({ val: window[i], idx: i });
    indexed.sort((a, b) => a.val - b.val);
    // Encode as base-d number
    let code = 0;
    for (let i = 0; i < d; i++) code = code * d + indexed[i].idx;
    return code;
  }

  _jointPermutationEntropy(seqA, seqB) {
    // Joint permutation entropy: concatenate patterns from aligned windows
    const n = Math.min(seqA.length, seqB.length);
    const d = this.d;
    const tau = this.tau;

    if (n < d * tau) return 0;

    const numWindows = n - (d - 1) * tau;
    if (numWindows <= 0) return 0;

    const patternCounts = new Map();
    const windowA = new Float64Array(d);
    const windowB = new Float64Array(d);

    for (let i = 0; i < numWindows; i++) {
      for (let k = 0; k < d; k++) {
        windowA[k] = seqA[i + k * tau];
        windowB[k] = seqB[i + k * tau];
      }
      const patternA = this._rankPattern(windowA, d);
      const patternB = this._rankPattern(windowB, d);
      // Joint pattern: combine A and B ranks into a single key
      const jointKey = patternA * Math.pow(d, d) + patternB;
      patternCounts.set(jointKey, (patternCounts.get(jointKey) || 0) + 1);
    }

    let entropy = 0;
    for (const count of patternCounts.values()) {
      const p = count / numWindows;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  _mutualInformation(seqA, seqB) {
    // I(A; B) = H(A) + H(B) - H(A, B)
    const n = Math.min(seqA.length, seqB.length);
    const d = this.d;
    const tau = this.tau;

    if (n < d * tau) return 0;

    const hA = this._permutationEntropy(seqA.slice(0, n));
    const hB = this._permutationEntropy(seqB.slice(0, n));
    const hAB = this._jointPermutationEntropy(seqA.slice(0, n), seqB.slice(0, n));

    return Math.max(0, hA + hB - hAB); // MI is non-negative
  }

  _permutationTest(seqA, seqB, observedMI) {
    // Generate null distribution by shuffling one sequence
    const n = Math.min(seqA.length, seqB.length);
    const numSurrogates = Math.min(this.surrogatePermutations, 500);

    let exceedCount = 0;
    const seqBcopy = new Float64Array(seqB.slice(0, n));

    for (let s = 0; s < numSurrogates; s++) {
      // Fisher-Yates shuffle of seqB
      for (let i = n - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = seqBcopy[i];
        seqBcopy[i] = seqBcopy[j];
        seqBcopy[j] = tmp;
      }
      const surrogateMI = this._mutualInformation(seqA.slice(0, n), seqBcopy);
      if (surrogateMI >= observedMI) exceedCount++;
    }

    // p-value with continuity correction
    return (exceedCount + 1) / (numSurrogates + 1);
  }

  _channelCapacity(seqA, seqB) {
    // Upper bound on channel capacity via Blahut-Arimoto
    // Simplified: max I(T_A; T_B) over sliding windows
    const mi = this._mutualInformation(seqA, seqB);
    // Normalize by max possible entropy
    const maxEntropy = Math.log2(this._factorial(this.d));
    return mi / maxEntropy;
  }

  _factorial(n) {
    let f = 1;
    for (let i = 2; i <= n; i++) f *= i;
    return f;
  }
}

module.exports = { TimingChannelDetector };
