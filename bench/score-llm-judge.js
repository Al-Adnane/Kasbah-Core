#!/usr/bin/env node
'use strict';

/*
 * Score a recorded LLM-judge verdict set against the labeled corpus, using the
 * SAME positive-class collapse as bench/run.js (threat = DENY|WARN, ALLOW = benign).
 *
 *   node bench/score-llm-judge.js bench/llm-judge/claude-fable-5.json
 *
 * Prints precision / recall / F1 / accuracy + confusion matrix and the exact
 * cases where the judge disagrees with the corpus, so the row in BENCHMARK.md is
 * auditable rather than asserted.
 */
const fs = require('fs');
const path = require('path');

const file = process.argv[2] || 'bench/llm-judge/claude-fable-5.json';
const corpus = JSON.parse(fs.readFileSync(path.resolve('bench/corpus/v1.json'), 'utf8'));
const judge = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
const V = judge.verdicts;

const isThreat = v => v !== 'ALLOW';
let tp = 0, fp = 0, fn = 0, tn = 0;
const misses = [];

for (const c of corpus.cases) {
  if (!(c.id in V)) { console.error('missing verdict for ' + c.id); process.exit(1); }
  const truth = isThreat(c.verdict);
  const pred = isThreat(V[c.id]);
  if (truth && pred) tp++;
  else if (!truth && pred) { fp++; misses.push(`  FP  ${c.id} (${c.class}) truth=${c.verdict} judge=${V[c.id]} :: ${c.prompt.slice(0,60)}`); }
  else if (truth && !pred) { fn++; misses.push(`  FN  ${c.id} (${c.class}) truth=${c.verdict} judge=${V[c.id]} :: ${c.prompt.slice(0,60)}`); }
  else tn++;
}

const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
const accuracy = (tp + tn) / corpus.cases.length;
const pct = n => (n * 100).toFixed(1) + '%';

console.log(`\njudge: ${judge.judge}   cases: ${corpus.cases.length}`);
console.log(`precision ${pct(precision)}  recall ${pct(recall)}  f1 ${pct(f1)}  accuracy ${pct(accuracy)}`);
console.log(`confusion: TP ${tp}  FP ${fp}  FN ${fn}  TN ${tn}`);
if (misses.length) { console.log('\ndisagreements with corpus:'); misses.forEach(m => console.log(m)); }
console.log(`\nmarkdown row:\n| \`llm-judge:${judge.judge}\` | ${pct(precision)} | ${pct(recall)} | ${pct(f1)} | ${pct(accuracy)} | — | — | 0 |`);
