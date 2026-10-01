'use strict';
/**
 * validate-round2.js — corrected & expanded constructed-ground-truth benchmarks
 * for the modules left INCONCLUSIVE/INVERTED/PENDING after round 1.
 *
 * Every benchmark injects a KNOWN phenomenon (ground truth constructed by us,
 * not read from the detector) and tests recovery. Results are `synthetic`:
 * they prove the math fires on the signal it claims; external validity needs
 * real data (Phase 2). H0: AUC=0.5. Metric: ROC-AUC + permutation p, BH-FDR.
 *
 * Run: node research/validate-round2.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '..'); const S = p => require(path.join(ROOT, 'src', p));
function lcg(seed){let s=seed>>>0;return()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};}
function gauss(r){let u=0,v=0;while(!u)u=r();while(!v)v=r();return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*v);}
function auc(rows){const P=rows.filter(r=>r.label).map(r=>r.score),N=rows.filter(r=>!r.label).map(r=>r.score);if(!P.length||!N.length)return NaN;let w=0,t=0;for(const a of P)for(const b of N){if(a>b)w++;else if(a===b)t++;}return(w+0.5*t)/(P.length*N.length);}
function permP(rows,obs,iters=2000){const L=rows.map(r=>r.label),Sc=rows.map(r=>r.score),d=Math.abs(obs-0.5),r=lcg(0x51ed);let h=0;for(let k=0;k<iters;k++){const p=L.slice();for(let i=p.length-1;i>0;i--){const j=Math.floor(r()*(i+1));[p[i],p[j]]=[p[j],p[i]];}if(Math.abs(auc(Sc.map((s,i)=>({score:s,label:p[i]})))-0.5)>=d)h++;}return(h+1)/(iters+1);}
function variance(xs){const m=xs.reduce((a,b)=>a+b,0)/(xs.length||1);return xs.reduce((a,x)=>a+(x-m)**2,0)/(xs.length||1);}
function bh(ps,q=0.05){const idx=ps.map((p,i)=>({p,i})).sort((a,b)=>a.p-b.p);const m=idx.length;let kmax=-1;for(let k=0;k<m;k++)if(idx[k].p<=((k+1)/m)*q)kmax=k;const sig=new Array(m).fill(false);for(let k=0;k<=kmax;k++)sig[idx[k].i]=true;return sig;}
function verdict(a,p,sig,sv){if(!isFinite(a))return'NO-DATA';if(sv!=null&&sv<1e-9)return'INCONCLUSIVE(benchmark)';if(a>=0.70&&sig)return'PROMOTE';if(a>=0.55)return'KEEP-ADVISORY';if(a<=0.30&&sig)return'INVERTED';return'DEPRECATE-CANDIDATE';}

const results = [];
function run(module, fn) {
  try { const rows = fn(); const a = auc(rows); const sv = variance(rows.map(r => r.score));
    results.push({ module, auc: a, p: permP(rows, a), scoreVar: sv, n: rows.length }); }
  catch (e) { results.push({ module, auc: NaN, p: 1, err: e.message.slice(0, 70) }); }
}

// ── B: DO-BFT corrected — colluders inject COORDINATED DIVERGENCE (raise variance)
run('do-bft-consensus', () => {
  const { DOBFTConsensus } = S('do-bft-consensus'); const rnd = lcg(11); const rows = [];
  for (let tr = 0; tr < 60; tr++) {
    const col = tr % 2 === 0; const c = new DOBFTConsensus({ minObservers: 7 });
    for (let o = 0; o < 7; o++) c.registerObserver('o' + o);
    let obs = c.collectPerturbedObservations(0.5); const keys = Object.keys(obs);
    if (col) for (let i = 0; i < 3; i++) obs[keys[i]] = 0.95;       // coordinated false-high (raises variance vs truth 0.5)
    const r = c.detectCollusion(obs);
    rows.push({ score: r.variance_ratio ?? (1 - (r.p_value ?? 1)), label: col ? 1 : 0 });
  }
  return rows;
});

// ── B: CHSH — non-commuting coordinated policy vs independent
run('chsh-coordination', () => {
  const { CHSHCoordinationDetector } = S('chsh-coordination'); const rnd = lcg(23); const rows = [];
  const ctx = ['ab', "ab'", "a'b", "a'b'"];
  for (let tr = 0; tr < 60; tr++) {
    const coord = tr % 2 === 0; const d = new CHSHCoordinationDetector({ minObservations: 4 });
    for (let n = 0; n < 120; n++) {
      const A = rnd() < 0.5 ? 1 : -1;
      // coordinated: B correlates differently per context (order/context-dependent) → CHSH>2
      let B; if (coord) { const ci = n % 4; const corr = (ci === 0 || ci === 1 || ci === 2) ? 0.9 : 0.1; B = rnd() < corr ? A : -A; }
      else B = rnd() < 0.5 ? 1 : -1;
      d.observe(ctx[n % 4], A, B);
    }
    rows.push({ score: d.computeCHSH().S_abs || 0, label: coord ? 1 : 0 });
  }
  return rows;
});

// ── B: Persistent homology — dense k≥6 covert cycle vs tree (enough for H1)
run('persistent-homology-covert', () => {
  const { PersistentHomologyCovertDetector } = S('persistent-homology-covert'); const rows = [];
  for (let tr = 0; tr < 50; tr++) {
    const cyc = tr % 2 === 0; const d = new PersistentHomologyCovertDetector({ minCycleSize: 3 });
    const ring = ['a', 'b', 'c', 'd', 'e', 'f'];
    const edges = cyc ? ring.map((u, i) => [u, ring[(i + 1) % ring.length]])      // 6-cycle
                      : ring.slice(1).map(u => ['a', u]);                          // star (tree, no H1)
    for (const [u, v] of edges) { try { d.registerCommunication(u, v); } catch (_) { try { d.registerCommunication({ from: u, to: v }); } catch (_) {} } }
    let sc = 0; try { const r = d.detectCovertCycles(); sc = (r.significantH1 ?? r.totalH1Features ?? (r.detected ? 1 : 0)) || 0; } catch (_) {}
    rows.push({ score: sc, label: cyc ? 1 : 0 });
  }
  return rows;
});

// ── B: Stigmergic — two agents coordinate via shared env store vs independent
run('stigmergic-covert-channel', () => {
  const { StigmergicCovertChannelDetector } = S('stigmergic-covert-channel'); const rnd = lcg(71); const rows = [];
  for (let tr = 0; tr < 40; tr++) {
    const cov = tr % 2 === 0; const d = new StigmergicCovertChannelDetector({ windowSize: 40 });
    for (let i = 0; i < 50; i++) {
      const bit = rnd() < 0.5 ? 1 : 0;
      try {
        d.registerEnvModification('A', 'key' + (cov ? bit : (rnd() < 0.5 ? 1 : 0)), i);
        d.registerEnvModification('B', 'key' + (cov ? bit : (rnd() < 0.5 ? 1 : 0)), i + 0.5); // B mirrors A's bit when covert
      } catch (_) {}
    }
    let sc = 0; try { const r = d.analyzeAllPairs(); sc = (r.maxMutualInfo ?? (Array.isArray(r.stigmergicPairs) ? r.stigmergicPairs.length : r.stigmergicPairs) ?? 0) || 0; } catch (_) {}
    rows.push({ score: sc, label: cov ? 1 : 0 });
  }
  return rows;
});

// ── B: Hypergraph — 3-agent n-ary collusion vs pairwise-only
run('hypergraph-collusion-detector', () => {
  const { HypergraphCollusionDetector } = S('hypergraph-collusion-detector'); const rnd = lcg(83); const rows = [];
  for (let tr = 0; tr < 40; tr++) {
    const nary = tr % 2 === 0; const d = new HypergraphCollusionDetector({});
    for (let i = 0; i < 40; i++) {
      try {
        if (nary) d.recordEvent({ agents: ['A', 'B', 'C'], action: 'joint', t: i });           // 3-way hyperedge
        else d.recordEvent({ agents: [rnd() < 0.5 ? 'A' : 'B', 'D'], action: 'pair', t: i });    // pairwise noise
      } catch (_) {}
    }
    let sc = 0; try { const r = d.analyze(); sc = (r.spectralGapRatio ?? r.maxHyperedgeWeight ?? (r.isColluding ? 1 : 0)) || 0; } catch (_) {}
    rows.push({ score: sc, label: nary ? 1 : 0 });
  }
  return rows;
});

// ── C: Critical Slowing Down — AR(1)→1 approach vs stable
run('critical-slowing-down-monitor', () => {
  const { CriticalSlowingDownMonitor } = S('critical-slowing-down-monitor'); const rnd = lcg(37); const rows = [];
  for (let tr = 0; tr < 50; tr++) {
    const approach = tr % 2 === 0; const m = new CriticalSlowingDownMonitor({ windowSize: 20, baselineWindow: 40 });
    try { m.calibrate(Array.from({ length: 40 }, () => 0.1 * gauss(rnd))); } catch (_) {}
    let x = 0, peak = 0;
    for (let t = 0; t < 80; t++) {
      const phi = approach ? Math.min(0.99, 0.3 + 0.012 * t) : 0.3;   // AR(1) coeff rising → critical
      x = phi * x + 0.1 * gauss(rnd);
      let out; try { out = m.observe(Math.abs(x)); } catch (_) {}
      const s = out && (out.csdScore ?? out.ar1Sigma ?? (out.isPreTransition ? 1 : 0));
      if (typeof s === 'number') peak = Math.max(peak, s);
    }
    rows.push({ score: peak, label: approach ? 1 : 0 });
  }
  return rows;
});

// ── C: LMID — off-manifold intrusions on a synthetic sphere
run('latent-manifold-intrusion', () => {
  const { LatentManifoldMonitor, generateSyntheticEmbedding } = S('latent-manifold-intrusion'); const rnd = lcg(41); const rows = [];
  const onSphere = () => { const v = [gauss(rnd), gauss(rnd), gauss(rnd)]; const n = Math.hypot(...v); return v.map(x => x / n); };
  for (let tr = 0; tr < 40; tr++) {
    const intr = tr % 2 === 0; const m = new LatentManifoldMonitor({});
    for (let i = 0; i < 60; i++) { try { m.observe(onSphere()); } catch (_) {} }       // calibrate on-manifold
    const test = intr ? [3, 3, 3] : onSphere();                                          // off-manifold vs on
    let sc = 0; try { const r = m.observe(test); sc = (r.geodesicDeviation ?? r.fisherRao ?? (r.isIntrusion ? 1 : 0)) || 0; } catch (_) {}
    rows.push({ score: sc, label: intr ? 1 : 0 });
  }
  return rows;
});

// ── D: Timing channel — periodic covert IRI vs matched-mean renewal
run('timing-channel-detector', () => {
  const { TimingChannelDetector } = S('timing-channel-detector'); const rnd = lcg(53); const rows = [];
  for (let tr = 0; tr < 50; tr++) {
    const chan = tr % 2 === 0; const d = new TimingChannelDetector(); let t = 0;
    for (let i = 0; i < 120; i++) {
      const gap = chan ? (i % 2 ? 100 : 300) : (200 - 100 * Math.log(rnd()));   // periodic vs exponential, mean≈200
      t += gap;
      try { d.recordResponse({ timestamp: t, agentId: 'a' }); } catch (_) { try { d.recordResponse(t); } catch (_) {} }
    }
    let sc = 0; try { const r = d.analyze(); sc = (r.mutualInformation ?? r.channelCapacity ?? r.maxChannel ?? (r.isChannelDetected ? 1 : 0)) || 0; } catch (_) {}
    rows.push({ score: sc, label: chan ? 1 : 0 });
  }
  return rows;
});

// ── A: intent-analyzer — exfil pipeline vs benign chain
run('kasbah-intent-analyzer', () => {
  const { KasbahIntentAnalyzer } = S('kasbah-intent-analyzer'); const rows = [];
  for (let tr = 0; tr < 40; tr++) {
    const attack = tr % 2 === 0; const a = new KasbahIntentAnalyzer();
    const steps = attack
      ? [{ verb: 'READ', target: 'users', content: '', status: 'completed' }, { verb: 'FORMAT', content: '', status: 'completed' }, { verb: 'POST', target: 'external', content: '', status: 'completed' }]
      : [{ verb: 'READ', target: 'docs', content: '', status: 'completed' }, { verb: 'SUMMARIZE', content: '', status: 'completed' }, { verb: 'WRITE', target: 'report', content: '', status: 'completed' }];
    const r = a.analyze(steps);
    rows.push({ score: r.trajectoryMatch ? (r.trajectoryMatch.confidence || 1) : (r.driftScore || 0), label: attack ? 1 : 0 });
  }
  return rows;
});

// ── A: surprisal-budget — over-budget burst vs normal
run('surprisal-budget-manager', () => {
  const { SurprisalBudgetManager } = S('surprisal-budget-manager'); const rnd = lcg(61); const rows = [];
  for (let tr = 0; tr < 40; tr++) {
    const burst = tr % 2 === 0; const m = new SurprisalBudgetManager({ initialBudget: 100, costPerBit: 1 });
    try { m.registerAgent('a'); } catch (_) {}
    let last = {};
    for (let i = 0; i < 30; i++) { const bits = burst ? 8 : 1; try { last = m.consume('a', bits) || last; } catch (_) {} }
    let sc = 0; try { const b = m.getBudget('a') || last; sc = (b.burnRate ?? b.burnRateRatio ?? (100 - (b.budgetRemaining ?? 100)) / 100) || 0; } catch (_) {}
    rows.push({ score: sc, label: burst ? 1 : 0 });
  }
  return rows;
});

// ── E: entropy-complexity-plane — regime classification accuracy (reported separately)
let ecpAcc = null;
try {
  const { EntropyComplexityPlane } = S('entropy-complexity-plane'); const rnd = lcg(29);
  const streams = {
    SILENCE: Array.from({ length: 200 }, () => 0.5),
    PULSE: Array.from({ length: 200 }, (_, i) => i % 4 < 2 ? 0.2 : 0.8),
    CHAOS: (() => { let x = 0.4, a = []; for (let i = 0; i < 200; i++) { x = 3.99 * x * (1 - x); a.push(x); } return a; })(),
  };
  let correct = 0, total = 0;
  for (const [label, stream] of Object.entries(streams)) {
    const e = new EntropyComplexityPlane({ windowSize: 100 }); let reg = null;
    for (const v of stream) { try { const r = e.feed(v); if (r && r.regime) reg = r.regime; } catch (_) {} }
    if (!reg) { try { reg = e.classifyRegime().regime; } catch (_) {} }
    total++; if (reg && String(reg).toUpperCase().includes(label === 'PULSE' ? 'PULSE' : label === 'CHAOS' ? 'CHAO' : 'SIL')) correct++;
  }
  ecpAcc = { module: 'entropy-complexity-plane', regimeAccuracy: correct + '/' + total, type: 'multiclass' };
} catch (e) { ecpAcc = { module: 'entropy-complexity-plane', err: e.message.slice(0, 60) }; }

// ── F: recursive-governance — flag injected self-inconsistency (property sim)
let recGov = null;
try {
  const { RecursiveGovernanceAuditor } = S('recursive-governance-fixed-point'); const a = new RecursiveGovernanceAuditor({});
  let flagged = false, consistentOk = false;
  try { for (let i = 0; i < 20; i++) a.audit({ verb: 'READ', decision: 'ALLOW' }); const r1 = a.audit({ verb: 'READ', decision: 'ALLOW' }); consistentOk = !(r1 && r1.driftDetected); } catch (_) {}
  try { const r2 = a.audit({ verb: 'READ', decision: 'DENY' }); flagged = !!(r2 && (r2.driftDetected || r2.inconsistent)); } catch (_) {}
  recGov = { module: 'recursive-governance-fixed-point', flagsInconsistency: flagged, stableWhenConsistent: consistentOk, type: 'property' };
} catch (e) { recGov = { module: 'recursive-governance-fixed-point', err: e.message.slice(0, 60) }; }

// ── BH across empirical + report ────────────────────────────────────────────────
const wd = results.filter(r => isFinite(r.auc)); const sig = bh(wd.map(r => r.p), 0.05);
wd.forEach((r, i) => { r.bhSig = sig[i]; r.verdict = verdict(r.auc, r.p, sig[i], r.scoreVar); });
results.filter(r => !isFinite(r.auc)).forEach(r => r.verdict = 'ERR');

console.log('\n=== ROUND 2: empirical (corrected synthetic GT) ===');
for (const r of results) console.log(r.module.padEnd(32), 'AUC=' + (isFinite(r.auc) ? r.auc.toFixed(3) : 'n/a'),
  'p=' + (r.p != null ? r.p.toFixed(3) : '—'), 'BH=' + (r.bhSig ? 'Y' : 'n'), '->', r.verdict, r.err ? ('· ' + r.err) : '');
console.log('\n=== multiclass / property ===');
console.log('  entropy-complexity-plane:', JSON.stringify(ecpAcc));
console.log('  recursive-governance:', JSON.stringify(recGov));

fs.writeFileSync(path.join(ROOT, 'research/results/validation-round2.json'),
  JSON.stringify({ date: '2026-05-30', note: 'synthetic constructed-GT; external validity pending real data', empirical: results, ecp: ecpAcc, recursiveGovernance: recGov }, null, 2));
console.log('\nwrote research/results/validation-round2.json');
