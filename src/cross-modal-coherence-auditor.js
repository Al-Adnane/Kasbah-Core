/**
 * Cross-Modal Coherence Auditor (#23)
 *
 * Detects when the LLM says one thing in text but does another through tools.
 *
 * PROBLEM: An LLM can output "I can't help with that" while simultaneously
 * calling a tool to do the harmful thing. Current guardrails check each channel
 * separately — they miss cross-modal deception because text looks fine and
 * each tool call looks fine individually. Only the MISMATCH is suspicious.
 *
 * APPROACH:
 *  1. Extract semantic embeddings from three channels:
 *     - Text output embedding (what the model SAYS)
 *     - Tool-call embedding (what the model DOES)
 *     - Reasoning trace embedding (what the model THINKS)
 *  2. Compute pairwise cosine similarities between channels
 *  3. If text↔tools divergence exceeds threshold while text↔reasoning stays
 *     coherent, the model is dissembling through its tools
 *
 * DEFENSIBLE: Cosine similarity between embedding projections is a standard
 * NLP technique. The novelty is applying it cross-modally within a single
 * LLM turn to detect "lying through tools" — a gap no existing guardrail
 * covers because they process channels independently.
 *
 * @module cross-modal-coherence-auditor
 */
'use strict';

class CrossModalCoherenceAuditor {
  constructor(options = {}) {
    this.embedDim = options.embedDim || 384;
    this.coherenceWarn = options.coherenceWarn || 0.60;    // cosine similarity threshold
    this.coherenceReview = options.coherenceReview || 0.40; // strong divergence
    this.minSamples = options.minSamples || 10;             // calibration samples
    this.textEmbeddings = [];
    this.toolEmbeddings = [];
    this.reasoningEmbeddings = [];
    this.coherenceHistory = [];
    this.baseline = null;  // pre-calibrated from normal turns
  }

  /**
   * Record a turn's three channel embeddings.
   * @param {number[]|Float32Array} textEmbedding — semantic embedding of text output
   * @param {number[]|Float32Array|null} toolEmbedding — semantic embedding of tool calls (or null if no tools)
   * @param {number[]|Float32Array|null} reasoningEmbedding — semantic embedding of reasoning trace (or null)
   * @param {Object} context — { turnId, timestamp, ... }
   * @returns {Object} coherence audit result
   */
  audit(textEmbedding, toolEmbedding, reasoningEmbedding, context = {}) {
    const turnId = context.turnId || `turn_${this.textEmbeddings.length}`;

    // L2-normalize all embeddings
    const normText = this._normalize(textEmbedding);
    const normTool = toolEmbedding ? this._normalize(toolEmbedding) : null;
    const normReason = reasoningEmbedding ? this._normalize(reasoningEmbedding) : null;

    this.textEmbeddings.push(normText);
    if (normTool) this.toolEmbeddings.push(normTool);
    if (normReason) this.reasoningEmbeddings.push(normReason);

    // Compute pairwise cosine similarities
    const similarities = {};
    if (normTool) {
      similarities.textTool = this._cosineSim(normText, normTool);
    }
    if (normReason) {
      similarities.textReason = this._cosineSim(normText, normReason);
    }
    if (normTool && normReason) {
      similarities.toolReason = this._cosineSim(normTool, normReason);
    }

    // Compute cross-modal divergence
    const divergence = this._computeDivergence(similarities);
    this.coherenceHistory.push(divergence);

    // Derive signal
    const signal = this._assessCoherence(similarities, divergence);

    return {
      mode: this.textEmbeddings.length >= this.minSamples ? 'monitoring' : 'calibrating',
      similarities,
      crossModalDivergence: divergence,
      isDeceptive: signal.isDeceptive,
      deceptionSeverity: signal.severity,
      signal: signal.signal,
      turnId,
      samples: this.textEmbeddings.length,
    };
  }

  /**
   * Assess coherence. Text↔Tool divergence + Text↔Reason coherence = deception.
   * If the model is reasoning about what it says (text↔reason high) but doing
   * something different (text↔tool low), it's being deceptive through tools.
   */
  _assessCoherence(similarities, divergence) {
    const textTool = similarities.textTool;
    const textReason = similarities.textReason;

    // No tools observed — can't assess tool deception
    if (textTool === undefined) {
      return { isDeceptive: false, severity: 0, signal: 'INSUFFICIENT_DATA' };
    }

    // Text↔Tool divergence threshold
    const toolDiverged = textTool < this.coherenceWarn;

    // Text↔Reason coherence: model is "thinking about what it's saying"
    const reasoningCoherent = textReason === undefined || textReason > 0.5;

    // Deception pattern: model says one thing, does another, but reasons about what it says
    const isDeceptive = toolDiverged && reasoningCoherent;

    // Severity based on how far below threshold
    const severity = toolDiverged
      ? Math.min(1.0, (this.coherenceWarn - textTool) / (this.coherenceWarn - this.coherenceReview))
      : 0;

    let signal;
    if (isDeceptive && severity > 0.8) {
      signal = 'REQUIRE_APPROVAL';
    } else if (isDeceptive) {
      signal = 'WARN';
    } else if (textTool < this.coherenceWarn + 0.1) {
      signal = 'CLEAR';  // borderline, but not deceptive
    } else {
      signal = 'CLEAR';
    }

    return { isDeceptive, severity, signal };
  }

  _computeDivergence(similarities) {
    // Cross-modal divergence = 1 - average of available pairwise similarities,
    // weighted: text↔tool mismatch is the most important signal
    const sims = [];
    const weights = [];
    if (similarities.textTool !== undefined) { sims.push(similarities.textTool); weights.push(0.5); }
    if (similarities.textReason !== undefined) { sims.push(similarities.textReason); weights.push(0.3); }
    if (similarities.toolReason !== undefined) { sims.push(similarities.toolReason); weights.push(0.2); }

    if (sims.length === 0) return 0;

    const wSum = weights.reduce((s, w) => s + w, 0);
    const weightedSim = sims.reduce((s, v, i) => s + v * weights[i] / wSum, 0);
    return 1 - weightedSim;
  }

  _cosineSim(a, b) {
    let dot = 0, magA = 0, magB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      magA += a[i] * a[i];
      magB += b[i] * b[i];
    }
    const denom = Math.sqrt(magA) * Math.sqrt(magB);
    return denom > 1e-12 ? Math.max(-1, Math.min(1, dot / denom)) : 0;
  }

  _normalize(vec) {
    let normSq = 0;
    for (let i = 0; i < vec.length; i++) normSq += vec[i] * vec[i];
    const norm = Math.sqrt(normSq) || 1e-12;
    const result = new Array(vec.length);
    for (let i = 0; i < vec.length; i++) result[i] = vec[i] / norm;
    return result;
  }

  reset() {
    this.textEmbeddings = [];
    this.toolEmbeddings = [];
    this.reasoningEmbeddings = [];
    this.coherenceHistory = [];
    this.baseline = null;
  }
}

module.exports = { CrossModalCoherenceAuditor };
