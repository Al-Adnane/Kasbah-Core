#!/usr/bin/env node
'use strict';

/**
 * Same benchmark as benchmark.py, but through the pure-JS inference path
 * (packages/api-server/src/ml/injection-js.js) — the path that actually runs
 * in the production node:alpine image. Fetches the identical public
 * deepset/prompt-injections TEST split and gates on the same floor, so a
 * drift between the Python and JS embedders would fail loudly here.
 *
 * Usage: node bench/injection-classifier/benchmark-js.js [--threshold 0.5]
 */

const FLOOR = { f1: 0.80, accuracy: 0.80 }; // must stay in sync with benchmark.py

async function fetchTest() {
  const base = 'https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=test';
  const page = async (offset, length) => {
    const r = await fetch(`${base}&offset=${offset}&length=${length}`, { headers: { 'User-Agent': 'kasbah-bench' } });
    if (!r.ok) throw new Error(`datasets-server ${r.status}`);
    return r.json();
  };
  const n = (await page(0, 1)).num_rows_total || 0;
  const rows = [];
  for (let off = 0; off < n; ) {
    const batch = (await page(off, 100)).rows || [];
    if (!batch.length) break;
    rows.push(...batch);
    off += batch.length;
  }
  return rows.map((x) => ({ text: x.row.text, label: x.row.label }));
}

(async () => {
  const thrArg = process.argv.indexOf('--threshold');
  const js = require('../../packages/api-server/src/ml/injection-js.js');
  const thr = thrArg > -1 ? Number(process.argv[thrArg + 1]) : js.threshold;

  console.log(`loading JS engine (${js.MODEL_ID}, fp32)…`);
  if (!(await js.warm())) { console.error('FAIL: JS engine could not load'); process.exit(1); }

  const test = await fetchTest();
  console.log(`test split: ${test.length} rows · threshold ${thr}`);

  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of test) {
    const inj = (await js.score(r.text)) >= thr;
    const truth = r.label === 1;
    if (inj && truth) tp++;
    else if (inj && !truth) fp++;
    else if (!inj && !truth) tn++;
    else fn++;
  }

  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  const f1 = (2 * precision * recall) / Math.max(1e-9, precision + recall);
  const accuracy = (tp + tn) / test.length;

  console.log(`precision=${precision.toFixed(3)} recall=${recall.toFixed(3)} f1=${f1.toFixed(3)} accuracy=${accuracy.toFixed(3)}`);
  console.log(`TP=${tp} FP=${fp} TN=${tn} FN=${fn}`);

  const pass = f1 >= FLOOR.f1 && accuracy >= FLOOR.accuracy;
  console.log(`gate (f1>=${FLOOR.f1}, acc>=${FLOOR.accuracy}): ${pass ? 'PASS' : 'FAIL'}`);
  process.exit(pass ? 0 : 1);
})().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
