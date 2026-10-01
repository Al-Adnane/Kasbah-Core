'use strict';

/**
 * Lightweight, dependency-free AI-text heuristic.
 *
 * This is NOT a model-based DetectGPT (which needs log-probs from an LLM).
 * It is a fast statistical screen over surface features that correlate with
 * machine-generated text: low burstiness (uniform sentence length), low
 * lexical diversity, over-regular punctuation, and low rate of contractions
 * / disfluencies. It returns a calibrated 0..1 score and a boolean.
 *
 * Use it as ONE signal among many — never as a sole authority.
 */

function sentences(text) {
  return text.split(/(?<=[.!?])\s+/).map(s => s.trim()).filter(Boolean);
}
function words(text) {
  return text.toLowerCase().match(/\b[a-z']+\b/g) || [];
}
function stddev(xs) {
  if (xs.length < 2) return 0;
  const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  const v = xs.reduce((a, b) => a + (b - m) ** 2, 0) / xs.length;
  return Math.sqrt(v);
}

function detectAIText(text) {
  if (!text || typeof text !== 'string' || text.length < 40) {
    return { score: 0, isAI: false, confidence: 0, signals: {} };
  }

  const sents = sentences(text);
  const w = words(text);
  if (sents.length < 2 || w.length < 20) {
    return { score: 0, isAI: false, confidence: 0, signals: {} };
  }

  // 1. Burstiness — human writing varies sentence length more.
  const lengths = sents.map(s => words(s).length);
  const meanLen = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const burstiness = meanLen > 0 ? stddev(lengths) / meanLen : 0; // CV
  const burstSignal = clamp01(1 - burstiness / 0.6); // low CV => AI-like

  // 2. Lexical diversity (type/token ratio) — AI tends slightly lower on long text.
  const ttr = new Set(w).size / w.length;
  const diversitySignal = clamp01((0.55 - ttr) / 0.25);

  // 3. Contractions / disfluencies — humans use more.
  const contractions = (text.match(/\b\w+'(s|t|re|ve|ll|d|m)\b/gi) || []).length;
  const contractionRate = contractions / sents.length;
  const disfluencySignal = clamp01(1 - contractionRate / 0.5);

  // 4. Punctuation regularity — AI commas/sentence are tightly clustered.
  const commasPer = sents.map(s => (s.match(/,/g) || []).length);
  const commaStd = stddev(commasPer);
  const punctSignal = clamp01(1 - commaStd / 1.2);

  const signals = {
    burstiness: round(burstiness),
    typeTokenRatio: round(ttr),
    contractionRate: round(contractionRate),
    commaRegularity: round(1 - clamp01(commaStd / 1.2))
  };

  // Weighted blend.
  const score =
    0.40 * burstSignal +
    0.25 * diversitySignal +
    0.20 * disfluencySignal +
    0.15 * punctSignal;

  const isAI = score >= 0.6;
  // Confidence = distance from the decision boundary, normalized.
  const confidence = round(Math.min(1, Math.abs(score - 0.5) * 2));

  return { score: round(score), isAI, confidence, signals };
}

function clamp01(x) { return Math.max(0, Math.min(1, x)); }
function round(x) { return Number(x.toFixed(4)); }

module.exports = { detectAIText };
