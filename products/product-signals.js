'use strict';

/**
 * product-signals.js — real, transparent replacements for the auxiliary
 * signal classes the dating-guard and relationship-guard engines depend on.
 *
 * The originals (MSHIR, SPIRAL, EigenEthicsDrift, CausalLoopBreaker,
 * HarmonicDissonance, ConsciousnessProvenanceEngine, AIFingerprintAnalyzer)
 * lived in the deleted "fantasy math" modules and could never load. These
 * reimplementations keep the SAME method signatures the engines call, but do
 * something real and explainable: text statistics, EWMA trend detection,
 * duplicate-argument detection, and value-series volatility. No trained model,
 * no exotic math — every number traces to a documented computation. Products
 * built on these are graded UNVALIDATED (advisory) by kasbah-products.js.
 */

// ── small text stats ──────────────────────────────────────────────────────────

function tokens(text) {
  return String(text || '').toLowerCase().match(/[a-z']+/g) || [];
}
function typeTokenRatio(text) {
  const t = tokens(text);
  if (!t.length) return 0;
  return new Set(t).size / t.length;
}
function sentenceLengths(text) {
  return String(text || '').split(/[.!?]+/).map(s => tokens(s).length).filter(n => n > 0);
}
function variance(arr) {
  if (arr.length < 2) return 0;
  const m = arr.reduce((a, b) => a + b, 0) / arr.length;
  return arr.reduce((s, v) => s + (v - m) ** 2, 0) / arr.length;
}
function coeffVar(arr) {
  if (arr.length < 2) return 0;
  const m = arr.reduce((a, b) => a + b, 0) / arr.length;
  return m ? Math.sqrt(variance(arr)) / m : 0;
}

const AI_CLICHES = [
  /\b(as an ai|i cannot|delve|tapestry|navigate the|in today's world|it's important to note)\b/gi,
  /\b(seamless|leverage|synergy|holistic|robust|elevate|unlock|embark)\b/gi,
  /\b(soulmate|destiny|meant to be|connection like no other|rare to find)\b/gi,
];

// ── ConsciousnessProvenanceEngine — human-likeness of text ─────────────────────
// Higher `consciousness` ⇒ more human. Real signal: human writing has higher
// lexical diversity and more variable sentence lengths ("burstiness"); AI /
// templated text is smoother and cliché-heavy.
class ConsciousnessProvenanceEngine {
  analyze(text) {
    const ttr = typeTokenRatio(text);                 // 0..1, higher = diverse
    const burst = Math.min(1, coeffVar(sentenceLengths(text)));  // sentence-length variability
    const clicheHits = AI_CLICHES.reduce((n, re) => n + ((String(text).match(re) || []).length), 0);
    const clichePenalty = Math.min(0.5, clicheHits * 0.12);
    // Blend; clamp to [0,1].
    const consciousness = Math.max(0, Math.min(1, 0.35 + ttr * 0.4 + burst * 0.35 - clichePenalty));
    return { consciousness: +consciousness.toFixed(3), verdict: consciousness >= 0.5 ? 'HUMAN' : 'AI-LIKELY',
             signals: { typeTokenRatio: +ttr.toFixed(3), burstiness: +burst.toFixed(3), clicheHits },
             method: 'text-statistics (TTR + sentence-length burstiness + cliché density)' };
  }
}

// ── AIFingerprintAnalyzer — likelihood text is machine-generated ───────────────
class AIFingerprintAnalyzer {
  analyze(text) {
    const clicheHits = AI_CLICHES.reduce((n, re) => n + ((String(text).match(re) || []).length), 0);
    const uniformity = 1 - Math.min(1, coeffVar(sentenceLengths(text))); // uniform length ⇒ AI-like
    const ttr = typeTokenRatio(text);
    const lowDiversity = ttr < 0.5 && tokens(text).length > 20 ? 0.25 : 0;
    const confidence = Math.max(0, Math.min(1, uniformity * 0.4 + Math.min(0.4, clicheHits * 0.15) + lowDiversity));
    return { confidence: +confidence.toFixed(3),
             generator: confidence > 0.6 ? 'likely-LLM' : confidence > 0.35 ? 'possibly-templated' : 'likely-human',
             signals: { clicheHits, uniformity: +uniformity.toFixed(3), typeTokenRatio: +ttr.toFixed(3) },
             method: 'text-statistics (sentence-length uniformity + cliché density + lexical diversity)' };
  }
}

// ── MSHIR — intent reconstruction from a multi-signal bundle ───────────────────
// Combines the caller-supplied signal fields into an attack probability and a
// dominant-intent label. Pure weighted aggregation of signals the engine
// already computed — no hidden model.
class MSHIR {
  reconstruct(signal = {}) {
    const scanRisk = (signal.scan?.risk || 0) / 100;
    const ethicsBad = signal.ethics?.verdict === 'UNETHICAL' ? 0.4 : (1 - (signal.ethics?.score ?? 1)) * 0.3;
    const aiLikely = signal.consciousness?.verdict === 'AI' ? 0.2 : 0;
    const highRisk = signal.high_risk_scan ? 0.2 : 0;
    const bell = signal.bell?.violation ? 0.1 : 0;
    const attackProbability = Math.max(0, Math.min(1, scanRisk * 0.5 + ethicsBad + aiLikely + highRisk + bell));

    let topIntent = 'benign';
    if (signal.ethics?.verdict === 'UNETHICAL' && scanRisk > 0.4) topIntent = 'financial-attack';
    else if (aiLikely && scanRisk > 0.3) topIntent = 'synthetic-deception';
    else if (attackProbability > 0.5) topIntent = 'manipulation';
    return { attackProbability: +attackProbability.toFixed(3), topIntent,
             method: 'weighted signal aggregation' };
  }
}

// ── SPIRAL — slow-escalation / baseline-drift detector (stateful) ──────────────
// Tracks observations over time; flags when risk trends UP or an ethics score
// trends DOWN across the conversation (the "slow boil" manipulation pattern).
class SPIRAL {
  constructor() { this.obs = []; }
  observe({ ethics = {}, decision } = {}) {
    const ethicsScore = typeof ethics.score === 'number' ? ethics.score : 0.5;
    const riskPoint = decision === 'DENY' ? 1 : 0;
    this.obs.push({ ethicsScore, riskPoint });
    // Trend = slope of ethics score over the window (declining ethics ⇒ drift).
    let driftScore = 0, poisoning = false;
    if (this.obs.length >= 3) {
      const first = this.obs.slice(0, Math.ceil(this.obs.length / 2));
      const last = this.obs.slice(Math.floor(this.obs.length / 2));
      const meanFirst = first.reduce((s, o) => s + o.ethicsScore, 0) / first.length;
      const meanLast = last.reduce((s, o) => s + o.ethicsScore, 0) / last.length;
      driftScore = Math.max(0, Math.min(1, meanFirst - meanLast));  // positive = ethics fell
      poisoning = driftScore > 0.2;
    }
    return { driftScore: +driftScore.toFixed(3), poisoning, observations: this.obs.length,
             method: 'ethics-trend slope over observation window' };
  }
}

// ── EigenEthicsDrift — drift in an ethics feature series (stateful) ────────────
// record() accepts a scalar or numeric vector; analyze() reports whether the
// series is drifting (variance/trend) and its magnitude ("nuclearNorm" here is
// just the L2 magnitude of the deviation series — named for API compatibility).
class EigenEthicsDrift {
  constructor(opts = {}) { this.minSamples = opts.minSamples || 3; this.series = []; }
  record(vec) {
    const v = Array.isArray(vec) ? vec.reduce((a, b) => a + b, 0) / (vec.length || 1) : Number(vec) || 0;
    this.series.push(v);
  }
  analyze() {
    if (this.series.length < this.minSamples) return { driftDetected: false, nuclearNorm: 0, samples: this.series.length };
    const mean = this.series.reduce((a, b) => a + b, 0) / this.series.length;
    const nuclearNorm = Math.sqrt(this.series.reduce((s, v) => s + (v - mean) ** 2, 0));
    const half = Math.floor(this.series.length / 2);
    const drift = Math.abs(
      (this.series.slice(half).reduce((a, b) => a + b, 0) / (this.series.length - half)) -
      (this.series.slice(0, half).reduce((a, b) => a + b, 0) / half)
    );
    return { driftDetected: drift > 0.15, nuclearNorm: +nuclearNorm.toFixed(3), drift: +drift.toFixed(3),
             samples: this.series.length, method: 'ethics-series deviation magnitude + half-window drift' };
  }
}

// ── CausalLoopBreaker — circular-argument detector (stateful) ──────────────────
// recordMessage() stores content hashes; a repeated hash ⇒ the same argument is
// being recycled (a real "going in circles"/gaslighting-by-repetition signal).
class CausalLoopBreaker {
  constructor(opts = {}) { this.klThreshold = opts.klThreshold || 0.15; this.states = new Map(); this.edges = []; this.hashes = new Map(); }
  recordAgentState(id, risk, ts) { this.states.set(id, { risk, ts }); }
  recordMessage(from, to, hash, ts) {
    this.edges.push({ from, to, hash, ts });
    this.hashes.set(hash, (this.hashes.get(hash) || 0) + 1);
  }
  analyze() {
    const cycles = [...this.hashes.entries()].filter(([, n]) => n > 1).map(([hash, n]) => ({ hash: hash.slice(0, 8), repetitions: n }));
    return { cycles, causalEdges: this.edges, method: 'repeated-argument (duplicate content hash) detection' };
  }
}

// ── HarmonicDissonance — emotional-rhythm volatility (stateful) ────────────────
// record(name, value) accumulates named value series; analyze() reports overall
// volatility and counts of abrupt jumps ("tritones" ⇒ jarring tonal shifts).
class HarmonicDissonance {
  constructor(opts = {}) { this.windowSize = opts.windowSize || 32; this.dissonanceThreshold = opts.dissonanceThreshold || 0.35; this.series = {}; }
  record(name, value) {
    (this.series[name] = this.series[name] || []).push(Number(value) || 0);
  }
  analyze() {
    let overall = 0, tritoneCount = 0, n = 0;
    for (const name in this.series) {
      const s = this.series[name].slice(-this.windowSize);
      overall += Math.min(1, coeffVar(s)); n++;
      for (let i = 1; i < s.length; i++) if (Math.abs(s[i] - s[i - 1]) > this.dissonanceThreshold) tritoneCount++;
    }
    const overallDissonance = n ? overall / n : 0;
    return { overallDissonance: +overallDissonance.toFixed(3), tritoneCount,
             method: 'coefficient-of-variation + abrupt-jump count over named value series' };
  }
}

module.exports = {
  ConsciousnessProvenanceEngine, AIFingerprintAnalyzer, MSHIR, SPIRAL,
  EigenEthicsDrift, CausalLoopBreaker, HarmonicDissonance,
};
