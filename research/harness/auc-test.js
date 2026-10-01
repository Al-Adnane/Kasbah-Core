'use strict';

/**
 * Reproducible discrimination-test harness.
 *
 * Given (a) a labeled corpus of {text, isAI} and (b) a scoring function that
 * maps text -> real number, this computes the rank-based AUC (equivalent to
 * the Mann-Whitney U statistic) of the score as a binary classifier, plus a
 * permutation p-value. AUC = 0.5 means the score is no better than chance.
 *
 * This is deliberately metric-only and metaphor-free: it makes NO assumption
 * about *why* a score might separate the classes. It only asks whether it does.
 *
 * Usage:
 *   const { evaluate, loadPooledCorpus } = require('./auc-test.js');
 *   const corpus = loadPooledCorpus();
 *   const res = await evaluate(corpus, async (text) => myDetector.score(text));
 *
 * Honest limitations are the caller's responsibility to report:
 *   - In-house labels (not an external gold standard).
 *   - Small N -> wide confidence intervals.
 *   - A single corpus -> no claim of generalization.
 */

const fs = require('fs');
const path = require('path');

const DATASET_DIR = path.resolve(__dirname, '..', '..',
  'archive', 'dirs', 'benchmark', 'test-datasets');

/** Pool the in-house AI-text datasets, de-duplicating by exact text. */
function loadPooledCorpus(files = ['ai-text-500.json', 'ai-text-600.json', 'ai-text-complete.json']) {
  const seen = new Set();
  const out = [];
  for (const f of files) {
    const p = path.join(DATASET_DIR, f);
    if (!fs.existsSync(p)) continue;
    let arr;
    try { arr = JSON.parse(fs.readFileSync(p, 'utf8')); } catch { continue; }
    if (!Array.isArray(arr)) continue;
    for (const x of arr) {
      const t = String(x.text || '').trim();
      if (!t || seen.has(t)) continue;
      seen.add(t);
      out.push({ text: t, isAI: x.isAI === true, source: x.source || null });
    }
  }
  return out;
}

/** Rank-based AUC = P(score(positive) > score(negative)), ties at 0.5. */
function aucFromScores(rows) {
  const pos = rows.filter(r => r.label).map(r => r.score);
  const neg = rows.filter(r => !r.label).map(r => r.score);
  let wins = 0, ties = 0;
  for (const a of pos) for (const b of neg) {
    if (a > b) wins++; else if (a === b) ties++;
  }
  const pairs = pos.length * neg.length;
  return pairs ? (wins + 0.5 * ties) / pairs : NaN;
}

/** Permutation test: how often does a shuffled-label AUC match/beat |observed-0.5|? */
function permutationPValue(rows, observedAuc, iters = 2000) {
  const labels = rows.map(r => r.label);
  const scores = rows.map(r => r.score);
  const obsDev = Math.abs(observedAuc - 0.5);
  // Deterministic LCG so the p-value is reproducible (no Math.random).
  let s = 0x2545f491;
  const rand = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  let hits = 0;
  for (let k = 0; k < iters; k++) {
    const perm = labels.slice();
    for (let i = perm.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    const shuffled = scores.map((sc, i) => ({ score: sc, label: perm[i] }));
    if (Math.abs(aucFromScores(shuffled) - 0.5) >= obsDev) hits++;
  }
  return (hits + 1) / (iters + 1);
}

function mean(xs) { return xs.reduce((a, b) => a + b, 0) / (xs.length || 1); }
function std(xs) { const m = mean(xs); return Math.sqrt(mean(xs.map(x => (x - m) ** 2))); }

/**
 * Run the full evaluation.
 * @param corpus  Array<{text, isAI}>
 * @param scoreFn async (text) => number   (higher should mean "more AI")
 * @param opts    { positiveClaimThreshold?: number }  optional claim to check
 */
async function evaluate(corpus, scoreFn, opts = {}) {
  const rows = [];
  for (const d of corpus) {
    const score = await scoreFn(d.text);
    rows.push({ score: Number(score), label: d.isAI });
  }
  const auc = aucFromScores(rows);
  const p = permutationPValue(rows, auc);
  const posScores = rows.filter(r => r.label).map(r => r.score);
  const negScores = rows.filter(r => !r.label).map(r => r.score);

  const result = {
    n: rows.length,
    nPositive: posScores.length,
    nNegative: negScores.length,
    meanScorePositive: +mean(posScores).toFixed(4),
    meanScoreNegative: +mean(negScores).toFixed(4),
    stdScorePositive: +std(posScores).toFixed(4),
    stdScoreNegative: +std(negScores).toFixed(4),
    auc: +auc.toFixed(4),
    permutationP: +p.toFixed(4),
    verdict: p < 0.05 ? 'DISCRIMINATES (reject H0 at alpha=0.05)'
                      : 'NO DISCRIMINATION (cannot reject H0)',
  };
  if (typeof opts.positiveClaimThreshold === 'number') {
    const thr = opts.positiveClaimThreshold;
    result.claimThreshold = thr;
    result.fracPositiveAboveThreshold = +(posScores.filter(s => s > thr).length / (posScores.length || 1)).toFixed(3);
    result.fracNegativeAboveThreshold = +(negScores.filter(s => s > thr).length / (negScores.length || 1)).toFixed(3);
  }
  return result;
}

module.exports = { loadPooledCorpus, evaluate, aucFromScores, permutationPValue };
