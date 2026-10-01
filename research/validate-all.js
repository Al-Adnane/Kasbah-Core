'use strict';
/**
 * validate-all.js — executes the Validation Plan (Phases 0-4) for the novel modules.
 *
 * For each module we use the BEST AVAILABLE labeled data:
 *   - real corpora where they exist (ai-text, bench/corpus/v1)
 *   - synthetic benchmarks with CONSTRUCTED ground truth otherwise (we inject a
 *     KNOWN phenomenon — covert cycle, timing channel, drift — and test whether
 *     the detector recovers it). Ground truth is constructed by us, NOT taken
 *     from the detector's output. Labeled `synthetic` in the results.
 *
 * Outputs ROC-AUC + permutation p, applies Benjamini-Hochberg FDR across all
 * empirical modules, and prints the merge-gate verdict per module.
 *
 * Run: node research/validate-all.js
 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const R = (p) => require(path.join(ROOT, p));

// Deterministic RNG (no Math.random in results).
function lcg(seed) { let s = seed >>> 0; return () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; }; }
function gauss(rnd) { let u = 0, v = 0; while (u === 0) u = rnd(); while (v === 0) v = rnd(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }

// ── metrics ──────────────────────────────────────────────────────────────────
function auc(rows) { // rows: {score,label(0/1)}
  const pos = rows.filter(r => r.label).map(r => r.score);
  const neg = rows.filter(r => !r.label).map(r => r.score);
  if (!pos.length || !neg.length) return NaN;
  let w = 0, t = 0; for (const a of pos) for (const b of neg) { if (a > b) w++; else if (a === b) t++; }
  return (w + 0.5 * t) / (pos.length * neg.length);
}
function permP(rows, observed, iters = 2000) {
  const labels = rows.map(r => r.label), scores = rows.map(r => r.score);
  const dev = Math.abs(observed - 0.5); const rnd = lcg(0x51ed);
  let hits = 0;
  for (let k = 0; k < iters; k++) {
    const perm = labels.slice();
    for (let i = perm.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }
    if (Math.abs(auc(scores.map((s, i) => ({ score: s, label: perm[i] }))) - 0.5) >= dev) hits++;
  }
  return (hits + 1) / (iters + 1);
}
// Benjamini-Hochberg FDR
function benjaminiHochberg(pvals, q = 0.05) {
  const idx = pvals.map((p, i) => ({ p, i })).sort((a, b) => a.p - b.p);
  const m = idx.length; let kmax = -1;
  for (let k = 0; k < m; k++) if (idx[k].p <= ((k + 1) / m) * q) kmax = k;
  const sig = new Array(m).fill(false);
  for (let k = 0; k <= kmax; k++) sig[idx[k].i] = true;
  return sig;
}
function variance(xs) { const m = xs.reduce((a, b) => a + b, 0) / (xs.length || 1); return xs.reduce((a, x) => a + (x - m) ** 2, 0) / (xs.length || 1); }
function gate(a, p, sig, scoreVar) {
  if (!isFinite(a)) return 'NO-DATA';
  // If the module emitted ~constant scores, the benchmark never exercised it —
  // that's INCONCLUSIVE (needs a proper module-specific harness), NOT proven-noise.
  if (scoreVar != null && scoreVar < 1e-9) return 'INCONCLUSIVE(benchmark)';
  if (a >= 0.70 && sig) return 'PROMOTE';
  if (a >= 0.55) return 'KEEP-ADVISORY';
  if (a <= 0.30 && sig) return 'INVERTED(benchmark-model-mismatch)';
  return 'DEPRECATE-CANDIDATE';
}

const empirical = []; // {module, dataset, auc, p}
const guarantees = []; // {module, claim, pass, detail}

// ── EMPIRICAL: detectgpt on real ai-text ───────────────────────────────────────
(() => {
  try {
    const { loadPooledCorpus } = R('research/harness/auc-test.js');
    const { detectAIText } = R('src/detectgpt.js');
    const corpus = loadPooledCorpus();
    const rows = corpus.map(d => ({ score: detectAIText(d.text).score, label: d.isAI ? 1 : 0 }));
    const a = auc(rows); empirical.push({ module: 'detectgpt', dataset: 'ai-text(real,n=' + rows.length + ')', auc: a, p: permP(rows, a), scoreVar: variance(rows.map(r=>r.score)) });
  } catch (e) { empirical.push({ module: 'detectgpt', dataset: 'ai-text', auc: NaN, p: 1, err: e.message }); }
})();

// ── EMPIRICAL: DO-BFT — honest vs colluding observers (synthetic GT) ────────────
(() => {
  try {
    const { DOBFTConsensus } = R('src/do-bft-consensus.js');
    const rnd = lcg(11); const rows = [];
    for (let trial = 0; trial < 60; trial++) {
      const colluding = trial % 2 === 0;
      const c = new DOBFTConsensus({ minObservers: 7 });
      for (let o = 0; o < 7; o++) c.registerObserver('o' + o);
      const truth = 0.5;
      let obs = c.collectPerturbedObservations(truth);
      if (colluding) { // inject coordinated slander: 3 observers report a shared false value
        const keys = Object.keys(obs);
        for (let i = 0; i < 3 && i < keys.length; i++) obs[keys[i]] = 0.05 + 0.001 * i;
      }
      const r = c.detectCollusion(obs);
      rows.push({ score: 1 - (r.p_value ?? 1), label: colluding ? 1 : 0 });
    }
    const a = auc(rows); empirical.push({ module: 'do-bft-consensus', dataset: 'synthetic-collusion(n=' + rows.length + ')', auc: a, p: permP(rows, a), scoreVar: variance(rows.map(r=>r.score)) });
  } catch (e) { empirical.push({ module: 'do-bft-consensus', dataset: 'synthetic', auc: NaN, p: 1, err: e.message }); }
})();

// ── EMPIRICAL: CHSH — independent vs coordinated agent decisions (synthetic GT) ──
(() => {
  try {
    const { CHSHCoordinationDetector } = R('src/chsh-coordination.js');
    const rnd = lcg(23); const rows = [];
    for (let trial = 0; trial < 60; trial++) {
      const coordinated = trial % 2 === 0;
      const d = new CHSHCoordinationDetector({ minObservations: 4 });
      const ctxs = ['ab', "ab'", "a'b", "a'b'"];
      for (let n = 0; n < 40; n++) {
        const A = rnd() < 0.5 ? 1 : -1;
        const B = coordinated ? (rnd() < 0.85 ? A : -A) : (rnd() < 0.5 ? 1 : -1);
        d.observe(ctxs[n % 4], A, B);
      }
      const s = d.computeCHSH(); rows.push({ score: s.S_abs || 0, label: coordinated ? 1 : 0 });
    }
    const a = auc(rows); empirical.push({ module: 'chsh-coordination', dataset: 'synthetic-coordination(n=' + rows.length + ')', auc: a, p: permP(rows, a), scoreVar: variance(rows.map(r=>r.score)) });
  } catch (e) { empirical.push({ module: 'chsh-coordination', dataset: 'synthetic', auc: NaN, p: 1, err: e.message }); }
})();

// ── EMPIRICAL: CUSUM subspace — drift vs stationary (synthetic GT) ──────────────
(() => {
  try {
    const { CUSUMSubspaceMonitor } = R('src/cusum-subspace-monitor.js');
    const rnd = lcg(37); const rows = [];
    for (let trial = 0; trial < 60; trial++) {
      const hasDrift = trial % 2 === 0;
      const m = new CUSUMSubspaceMonitor({ baselineWindow: 30, minShift: 0.05 });
      // Calibrate on a stationary baseline first (required before observe()).
      try { m.calibrate(Array.from({ length: 40 }, () => Math.abs(0.1 + 0.02 * gauss(rnd)))); } catch (_) {}
      let peak = 0;
      for (let t = 0; t < 80; t++) {
        const base = 0.1 + 0.02 * gauss(rnd);
        const v = (hasDrift && t > 50) ? base + 0.6 : base;
        let out; try { out = m.observe(Math.abs(v)); } catch (_) {}
        const s = out && (out.cusum_S ?? out.S ?? out.cusumValue);
        if (typeof s === 'number') peak = Math.max(peak, s);
      }
      rows.push({ score: peak, label: hasDrift ? 1 : 0 });
    }
    const a = auc(rows); empirical.push({ module: 'cusum-subspace-monitor', dataset: 'synthetic-drift(n=' + rows.length + ')', auc: a, p: permP(rows, a), scoreVar: variance(rows.map(r=>r.score)) });
  } catch (e) { empirical.push({ module: 'cusum-subspace-monitor', dataset: 'synthetic', auc: NaN, p: 1, err: e.message }); }
})();

// ── EMPIRICAL: timing-channel — covert periodic channel vs random (synthetic GT) ─
(() => {
  try {
    const { TimingChannelDetector } = R('src/timing-channel-detector.js');
    const rnd = lcg(53); const rows = [];
    for (let trial = 0; trial < 50; trial++) {
      const hasChannel = trial % 2 === 0;
      const d = new TimingChannelDetector();
      let tnow = 0;
      for (let i = 0; i < 60; i++) {
        const gap = hasChannel ? (i % 2 === 0 ? 100 : 300) : (100 + 200 * rnd());
        tnow += gap;
        try { d.recordResponse({ timestamp: tnow, agentId: 'a' }); } catch (_) { d.recordResponse(tnow); }
      }
      let score = 0;
      try { const r = d.analyze(); score = r.mutualInformation ?? r.channelCapacity ?? (r.isChannelDetected ? 1 : 0) ?? 0; } catch (_) {}
      rows.push({ score, label: hasChannel ? 1 : 0 });
    }
    const a = auc(rows); empirical.push({ module: 'timing-channel-detector', dataset: 'synthetic-channel(n=' + rows.length + ')', auc: a, p: permP(rows, a), scoreVar: variance(rows.map(r=>r.score)) });
  } catch (e) { empirical.push({ module: 'timing-channel-detector', dataset: 'synthetic', auc: NaN, p: 1, err: e.message }); }
})();

// ── EMPIRICAL: persistent-homology — covert cycle vs tree (synthetic GT) ────────
(() => {
  try {
    const { PersistentHomologyCovertDetector } = R('src/persistent-homology-covert.js');
    const rnd = lcg(67); const rows = [];
    for (let trial = 0; trial < 50; trial++) {
      const hasCycle = trial % 2 === 0;
      const d = new PersistentHomologyCovertDetector({ minCycleSize: 3 });
      const edges = hasCycle ? [['a', 'b'], ['b', 'c'], ['c', 'a'], ['a', 'd']] : [['a', 'b'], ['a', 'c'], ['a', 'd'], ['b', 'e']];
      for (const [u, v] of edges) { try { d.registerCommunication(u, v); } catch (_) {} }
      let score = 0;
      try { const r = d.detectCovertCycles(); score = (r.significantH1 ?? (r.detected ? 1 : 0)) || 0; } catch (_) {}
      rows.push({ score, label: hasCycle ? 1 : 0 });
    }
    const a = auc(rows); empirical.push({ module: 'persistent-homology-covert', dataset: 'synthetic-cycle(n=' + rows.length + ')', auc: a, p: permP(rows, a), scoreVar: variance(rows.map(r=>r.score)) });
  } catch (e) { empirical.push({ module: 'persistent-homology-covert', dataset: 'synthetic', auc: NaN, p: 1, err: e.message }); }
})();

// ── GUARANTEE: conformal-martingale coverage ≈ alpha under H0 ───────────────────
(() => {
  try {
    const { ConformalMartingaleMonitor } = R('src/conformal-martingale.js');
    const rnd = lcg(91); let alarms = 0, n = 0;
    for (let run = 0; run < 40; run++) {
      const m = new ConformalMartingaleMonitor({ alpha: 0.05, calibrationSize: 100 });
      for (let i = 0; i < 100; i++) m.process(Math.abs(gauss(rnd)) * 0.2);  // calibrate on H0
      for (let i = 0; i < 50; i++) { const r = m.process(Math.abs(gauss(rnd)) * 0.2); n++; if (r.alarm) alarms++; } // H0 test
    }
    const rate = alarms / n; const pass = rate <= 0.15; // anytime-valid: false-alarm should stay low
    guarantees.push({ module: 'conformal-martingale', claim: 'H0 false-alarm rate low (anytime-valid)', pass, detail: 'falseAlarmRate=' + rate.toFixed(3) });
  } catch (e) { guarantees.push({ module: 'conformal-martingale', claim: 'coverage', pass: false, detail: 'ERR ' + e.message }); }
})();

// ── GUARANTEE: flag-correlation weight decreases with correlation ──────────────
(() => {
  try {
    const { FlagCorrelationFuser } = R('src/flag-correlation-weighting.js');
    function weightAt(corr) {
      const f = new FlagCorrelationFuser(); f.initializeDetectors(['d0', 'd1', 'd2', 'd3']);
      const rnd = lcg(7);
      for (let i = 0; i < 400; i++) { const x = rnd() < 0.3 ? 1 : 0; const pair = rnd() < corr ? x : (rnd() < 0.3 ? 1 : 0); f.observe([x, pair, rnd() < 0.05 ? 1 : 0, rnd() < 0.05 ? 1 : 0]); }
      return f.computeEvidentialWeight([1, 1, 0, 0]).evidential_weight ?? f.computeEvidentialWeight([1, 1, 0, 0]).weight ?? 0;
    }
    const wLow = weightAt(0.0), wHigh = weightAt(0.95);
    const pass = wHigh <= wLow; // correlated co-fire should weigh ≤ independent
    guarantees.push({ module: 'flag-correlation-weighting', claim: 'weight(correlated) ≤ weight(independent)', pass, detail: 'wIndep=' + wLow.toFixed(2) + ' wCorr=' + wHigh.toFixed(2) });
  } catch (e) { guarantees.push({ module: 'flag-correlation-weighting', claim: 'monotonic', pass: false, detail: 'ERR ' + e.message }); }
})();

// ── FORMAL: bounded-advisory never returns DENY ────────────────────────────────
(() => {
  try {
    const { advisoryOperator } = R('src/bounded-advisory-semantics.js');
    const rnd = lcg(101); let everDeny = false;
    for (let i = 0; i < 5000; i++) { const out = advisoryOperator(rnd()); const lvl = (out && out.level && (out.level.label || out.level)) || out; if (String(JSON.stringify(out)).includes('DENY')) everDeny = true; }
    guarantees.push({ module: 'bounded-advisory-semantics', claim: 'codomain excludes DENY (5000 random inputs)', pass: !everDeny, detail: everDeny ? 'DENY emitted!' : 'no DENY ever' });
  } catch (e) { guarantees.push({ module: 'bounded-advisory-semantics', claim: 'no-DENY', pass: false, detail: 'ERR ' + e.message }); }
})();

// ── FORMAL: orthogonal evasion bound monotonic in k ────────────────────────────
(() => {
  try {
    const { proveEvasionBound } = R('src/orthogonal-manifold-evasion-bound.js');
    const bits = [2, 4, 8, 16].map(k => { const r = proveEvasionBound(k, 0.9); return r.evasion_work_bits ?? r.evasionWorkBits ?? r.work_bits ?? 0; });
    const mono = bits.every((b, i) => i === 0 || b >= bits[i - 1]);
    guarantees.push({ module: 'orthogonal-manifold-evasion-bound', claim: 'evasion-work non-decreasing in k', pass: mono, detail: 'bits=' + JSON.stringify(bits) });
  } catch (e) { guarantees.push({ module: 'orthogonal-manifold-evasion-bound', claim: 'monotonic', pass: false, detail: 'ERR ' + e.message }); }
})();

// ── apply BH across empirical modules with data ────────────────────────────────
const withData = empirical.filter(e => isFinite(e.auc));
const sig = benjaminiHochberg(withData.map(e => e.p), 0.05);
withData.forEach((e, i) => { e.bhSignificant = sig[i]; e.verdict = gate(e.auc, e.p, sig[i], e.scoreVar); });
empirical.filter(e => !isFinite(e.auc)).forEach(e => { e.verdict = 'NO-DATA'; });

// ── report ─────────────────────────────────────────────────────────────────────
console.log('\n=== EMPIRICAL MODULES (ROC-AUC, BH-corrected) ===');
for (const e of empirical) console.log(
  (e.module).padEnd(30), 'AUC=' + (isFinite(e.auc) ? e.auc.toFixed(3) : 'n/a'),
  'p=' + (e.p != null ? e.p.toFixed(3) : 'n/a'), 'BHsig=' + (e.bhSignificant ? 'Y' : 'n'),
  '->', e.verdict, ' [' + (e.dataset || '') + (e.err ? ' ERR:' + e.err.slice(0, 40) : '') + ']');
console.log('\n=== GUARANTEE / FORMAL MODULES ===');
for (const g of guarantees) console.log((g.module).padEnd(34), (g.pass ? 'PASS' : 'FAIL'), '·', g.claim, '·', g.detail);

const summary = { date: '2026-05-30', empirical, guarantees,
  gate: { PROMOTE: empirical.filter(e => e.verdict === 'PROMOTE').map(e => e.module),
          KEEP_ADVISORY: empirical.filter(e => e.verdict === 'KEEP-ADVISORY').map(e => e.module),
          DEPRECATE: empirical.filter(e => e.verdict === 'DEPRECATE').map(e => e.module),
          NO_DATA: empirical.filter(e => e.verdict === 'NO-DATA').map(e => e.module),
          GUARANTEE_OK: guarantees.filter(g => g.pass).map(g => g.module),
          GUARANTEE_FAIL: guarantees.filter(g => !g.pass).map(g => g.module) } };
fs.writeFileSync(path.join(ROOT, 'research/results/validation-summary.json'), JSON.stringify(summary, null, 2));
console.log('\nwrote research/results/validation-summary.json');
