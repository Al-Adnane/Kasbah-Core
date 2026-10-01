'use strict';

/**
 * advisory-analyzers.js — the genuinely-novel-in-synthesis, technically-sound
 * analyzers distilled from the Kasbah conversation. Every function here is a
 * REAL computation on real data (no metaphors, no simulation). All outputs are
 * ADVISORY only — they feed the bounded-advisory layer and can never DENY.
 *
 * Implemented (idea numbers from the 10-idea synthesis):
 *   #2  orthogonalityScore        — heterogeneous-detector independence metric
 *   #3  perturbedObserverConsensus — DO-BFT: DP-noised observers + disagreement
 *   #5  cusumChangePoint          — sequential change-point on a drift series
 *   #6  graphCycleSignal          — covert-coordination cycles (real graph cycles)
 *   #8  FlagCorrelationFusion     — evidential weight accounting for flag correlation
 *   #10 entropyComplexityRegime   — Bandt-Pompe permutation entropy + JS complexity
 *
 * Honest notes:
 *   - #6 is real cycle detection on an interaction graph, NOT full persistent
 *     homology (that needs a TDA library). Labeled accordingly.
 *   - #4 (CHSH "non-commutativity") is intentionally NOT here: we empirically
 *     falsified the Bell statistic (AUC 0.49). It survives only as a near-zero-
 *     weight legacy feature elsewhere, explicitly unvalidated.
 */

const crypto = require('crypto');

// ─────────────────────────────────────────────────────────────────────────────
// #10  Entropy–Complexity plane (Bandt-Pompe permutation entropy + JS complexity)
// ─────────────────────────────────────────────────────────────────────────────

function _ordinalPatternCounts(series, order) {
  // Count ordinal (permutation) patterns of length `order` over the series.
  const counts = new Map();
  let total = 0;
  for (let i = 0; i + order <= series.length; i++) {
    const window = series.slice(i, i + order);
    // rank pattern: indices sorted by value
    const idx = window.map((v, k) => k).sort((a, b) => window[a] - window[b]);
    const key = idx.join(',');
    counts.set(key, (counts.get(key) || 0) + 1);
    total++;
  }
  return { counts, total };
}

function _factorial(n) { let f = 1; for (let i = 2; i <= n; i++) f *= i; return f; }

/** Normalized permutation entropy H ∈ [0,1] (Bandt-Pompe). */
function permutationEntropy(series, order = 3) {
  if (!Array.isArray(series) || series.length < order + 1) return 0;
  const { counts, total } = _ordinalPatternCounts(series, order);
  if (total === 0) return 0;
  let H = 0;
  for (const c of counts.values()) { const p = c / total; H -= p * Math.log(p); }
  return H / Math.log(_factorial(order)); // normalize by log(d!)
}

/** Jensen–Shannon statistical complexity C_JS = Q · H (López-Ruiz/Rosso). */
function jsComplexity(series, order = 3) {
  if (!Array.isArray(series) || series.length < order + 1) return 0;
  const N = _factorial(order);
  const { counts, total } = _ordinalPatternCounts(series, order);
  if (total === 0) return 0;
  // Build full distribution P over all N patterns (missing patterns = 0).
  const P = new Array(N).fill(0);
  // Map arbitrary pattern keys to indices 0..N-1 deterministically.
  let next = 0; const keyIdx = new Map();
  for (const [k, c] of counts) { if (!keyIdx.has(k)) keyIdx.set(k, next++); P[keyIdx.get(k)] = c / total; }
  const Pe = 1 / N; // uniform
  const shannon = (p) => { let s = 0; for (const x of p) if (x > 0) s -= x * Math.log(x); return s; };
  // JS divergence between P and uniform Pe.
  const M = P.map(p => 0.5 * (p + Pe));
  const Hp = shannon(P);
  const HPe = Math.log(N); // entropy of uniform
  const HM = shannon(M);
  const JS = HM - 0.5 * Hp - 0.5 * HPe;
  // Normalization constant Q0 so C ∈ [0,1].
  const Q0 = -2 / (((N + 1) / N) * Math.log(N + 1) - 2 * Math.log(2 * N) + Math.log(N));
  const Hnorm = Hp / Math.log(N);
  return Math.max(0, Math.min(1, Q0 * JS * Hnorm));
}

/** Classify a communication/score series into a flow regime via (H, C). */
function entropyComplexityRegime(series, order = 3) {
  const H = permutationEntropy(series, order);
  const C = jsComplexity(series, order);
  // Regions of the entropy-complexity plane (heuristic, advisory only).
  let regime = 'NORMAL';
  if (H < 0.2 && C < 0.2) regime = 'SILENCE';        // near-constant / no activity
  else if (H > 0.95 && C < 0.15) regime = 'CHAOS';   // uncorrelated noise (flood of random)
  else if (H < 0.5 && C > 0.3) regime = 'PULSE';     // structured periodicity
  else if (H > 0.8 && C > 0.25) regime = 'ECHO';     // high-entropy but structured (coordination)
  else if (H > 0.6) regime = 'FLOOD';
  return { regime, permutationEntropy: +H.toFixed(4), complexity: +C.toFixed(4) };
}

// ─────────────────────────────────────────────────────────────────────────────
// #5  CUSUM sequential change-point detection (e.g. on alignment-drift series)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * One-sided CUSUM. Detects an upward shift in mean of `series`.
 * @param series array of scalars
 * @param opts { target, k (slack), h (decision threshold) }
 * @returns { detected, changePoint, peak, Sseries }
 */
function cusumChangePoint(series, opts = {}) {
  if (!Array.isArray(series) || series.length === 0) return { detected: false, changePoint: -1, peak: 0 };
  const target = opts.target != null ? opts.target : series.slice(0, Math.max(1, Math.floor(series.length / 3)))
    .reduce((a, b) => a + b, 0) / Math.max(1, Math.floor(series.length / 3));
  const k = opts.k != null ? opts.k : 0.5;   // reference value / slack
  const h = opts.h != null ? opts.h : 5;     // ARL-calibrated threshold
  let S = 0, peak = 0, changePoint = -1;
  const Sseries = [];
  for (let t = 0; t < series.length; t++) {
    S = Math.max(0, S + (series[t] - target - k));
    Sseries.push(+S.toFixed(4));
    if (S > peak) peak = S;
    if (S > h && changePoint === -1) changePoint = t;
  }
  return { detected: changePoint !== -1, changePoint, peak: +peak.toFixed(4), threshold: h, Sseries };
}

// ─────────────────────────────────────────────────────────────────────────────
// #3  Perturbed-Observer Consensus (DO-BFT): DP noise repurposed defensively
// ─────────────────────────────────────────────────────────────────────────────

/** Laplace(0, b) sample using crypto randomness (intentional DP noise). */
function _laplace(b) {
  // u ∈ (-0.5, 0.5)
  const u = (crypto.randomBytes(4).readUInt32BE(0) / 0xffffffff) - 0.5;
  return -b * Math.sign(u) * Math.log(1 - 2 * Math.abs(u) + 1e-12);
}

/**
 * Run a scalar scoring function under N differentially-private perturbed views
 * and measure disagreement. A robust (benign) observation yields low spread;
 * an observation engineered to sit on a decision boundary (evasion) yields high
 * spread because it cannot stay consistent across all N noisy views.
 *
 * @param value     the observed scalar (e.g. composite anomaly score in [0,1])
 * @param opts { epsilon, N, decisionThreshold }
 * @returns { disagreement, flipRate, mean, std }
 */
function perturbedObserverConsensus(value, opts = {}) {
  const epsilon = opts.epsilon || 8;   // privacy budget; smaller = noisier
  const N = opts.N || 16;
  const thr = opts.decisionThreshold != null ? opts.decisionThreshold : 0.5;
  const b = 1 / epsilon;
  const views = [];
  for (let i = 0; i < N; i++) views.push(value + _laplace(b));
  const mean = views.reduce((a, x) => a + x, 0) / N;
  const std = Math.sqrt(views.reduce((a, x) => a + (x - mean) ** 2, 0) / N);
  const above = views.filter(v => v >= thr).length;
  const flipRate = Math.min(above, N - above) / N; // 0 = unanimous, 0.5 = maximally split
  return {
    disagreement: +Math.min(1, 2 * flipRate).toFixed(4), // 0..1
    flipRate: +flipRate.toFixed(4),
    mean: +mean.toFixed(4),
    std: +std.toFixed(4),
    note: 'DP-noised observers; high disagreement near a decision boundary is advisory only.',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// #2  Orthogonality metric — independence of heterogeneous detector surfaces
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Given a T×M matrix of recent module feature values (rows = time, cols =
 * modules), measure how mathematically orthogonal/independent the detectors are.
 * orthogonality = 1 - mean(|off-diagonal Pearson correlation|).
 * High orthogonality is the property that gives the ensemble its evasion-cost
 * benefit (idea #2). This MEASURES it empirically — it does not assert the
 * Ω(2^k) bound, which would require a separate formal proof.
 */
function orthogonalityScore(matrix) {
  if (!Array.isArray(matrix) || matrix.length < 3) return { orthogonality: null, n: matrix.length };
  const T = matrix.length, M = matrix[0].length;
  const mean = new Array(M).fill(0), std = new Array(M).fill(0);
  for (let j = 0; j < M; j++) { for (let i = 0; i < T; i++) mean[j] += matrix[i][j]; mean[j] /= T; }
  for (let j = 0; j < M; j++) { let s = 0; for (let i = 0; i < T; i++) s += (matrix[i][j] - mean[j]) ** 2; std[j] = Math.sqrt(s / T); }
  let sumAbs = 0, pairs = 0;
  for (let a = 0; a < M; a++) for (let bb = a + 1; bb < M; bb++) {
    if (std[a] < 1e-9 || std[bb] < 1e-9) continue;
    let cov = 0; for (let i = 0; i < T; i++) cov += (matrix[i][a] - mean[a]) * (matrix[i][bb] - mean[bb]);
    cov /= T;
    sumAbs += Math.abs(cov / (std[a] * std[bb])); pairs++;
  }
  const meanAbsCorr = pairs ? sumAbs / pairs : 0;
  return { orthogonality: +(1 - meanAbsCorr).toFixed(4), meanAbsCorr: +meanAbsCorr.toFixed(4), modules: M, samples: T };
}

// ─────────────────────────────────────────────────────────────────────────────
// #8  Flag-Correlation Evidential Weighting — fixes naive "count the flags"
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Maintains running marginal fire-rates and pairwise co-fire rates of M binary
 * detectors under baseline operation, then scores a multi-flag event by
 * EVIDENTIAL WEIGHT that discounts correlated co-firing and rewards independent
 * confirmations. This is the principled replacement for unsupervised EWA (which
 * just chased the loudest module).
 */
class FlagCorrelationFusion {
  constructor(M, opts = {}) {
    this.M = M;
    this.count = 0;
    this.marginal = new Array(M).fill(0);            // Σ F_i
    this.coFire = Array.from({ length: M }, () => new Array(M).fill(0)); // Σ F_i F_j
    this.prior = opts.prior != null ? opts.prior : 0.05; // smoothing fire-rate
  }

  /** Update baseline statistics with an observed flag vector (0/1). */
  observe(flags) {
    this.count++;
    for (let i = 0; i < this.M; i++) {
      if (flags[i]) this.marginal[i]++;
      for (let j = 0; j < this.M; j++) if (flags[i] && flags[j]) this.coFire[i][j]++;
    }
  }

  _p(i) { return (this.marginal[i] + this.prior * 1) / (this.count + 1); }
  _pij(i, j) { return (this.coFire[i][j] + this.prior * this.prior) / (this.count + 1); }

  /** Pearson phi correlation between detectors i and j under H0. */
  _corr(i, j) {
    const pi = this._p(i), pj = this._p(j), pij = this._pij(i, j);
    const denom = Math.sqrt(pi * (1 - pi) * pj * (1 - pj));
    return denom < 1e-9 ? 0 : (pij - pi * pj) / denom;
  }

  /**
   * Evidential weight of a flag event. Sum of independent surprisals
   * −log P(F_i=1|H0), each discounted by its average correlation with the
   * other flagged detectors (correlated co-fires count less).
   * @returns { weight, effectiveIndependentFlags, flaggedCount }
   */
  evidentialWeight(flags) {
    const idx = [];
    for (let i = 0; i < this.M; i++) if (flags[i]) idx.push(i);
    if (idx.length === 0) return { weight: 0, effectiveIndependentFlags: 0, flaggedCount: 0 };
    let weight = 0, effSum = 0;
    for (const i of idx) {
      let meanCorr = 0, c = 0;
      for (const j of idx) if (j !== i) { meanCorr += Math.abs(this._corr(i, j)); c++; }
      meanCorr = c ? meanCorr / c : 0;
      const discount = 1 - meanCorr;             // independent → 1, fully correlated → 0
      const surprisal = -Math.log(this._p(i));   // rarer fire → more evidence
      weight += discount * surprisal;
      effSum += discount;
    }
    return {
      weight: +weight.toFixed(4),
      effectiveIndependentFlags: +effSum.toFixed(3),
      flaggedCount: idx.length,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// #6  Covert-coordination cycle signal (real graph cycles; not full PH)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detect coordination cycles in a directed agent interaction graph.
 * edges: array of [from, to] agent ids. A persistent cycle among a subset of
 * agents is a covert-coordination signature. Returns cycle count + longest.
 * (Honest: this is graph cycle detection, an O(V+E) DFS — a real, defensible
 * proxy for the H₁ "loops" the persistent-homology framing pointed at.)
 */
function graphCycleSignal(edges) {
  const adj = new Map();
  const nodes = new Set();
  for (const [u, v] of edges) {
    if (!adj.has(u)) adj.set(u, []);
    adj.get(u).push(v); nodes.add(u); nodes.add(v);
  }
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map([...nodes].map(n => [n, WHITE]));
  let cycles = 0, longest = 0;
  const stack = [];
  function dfs(u) {
    color.set(u, GRAY); stack.push(u);
    for (const v of (adj.get(u) || [])) {
      if (color.get(v) === GRAY) { cycles++; longest = Math.max(longest, stack.length - stack.indexOf(v) + 1); }
      else if (color.get(v) === WHITE) dfs(v);
    }
    color.set(u, BLACK); stack.pop();
  }
  for (const n of nodes) if (color.get(n) === WHITE) dfs(n);
  return { cycleCount: cycles, longestCycle: longest, agents: nodes.size,
    note: 'directed-graph cycle detection (real); advisory proxy for covert coordination.' };
}

// ─────────────────────────────────────────────────────────────────────────────
// #2(v2)  Fiedler value of the flag-correlation graph (algebraic connectivity)
// ─────────────────────────────────────────────────────────────────────────────

/** Eigenvalues of a real symmetric matrix via cyclic Jacobi rotation. */
function jacobiEigenvalues(Ain, maxIter = 100) {
  const n = Ain.length;
  // copy
  const A = Ain.map(r => r.slice());
  for (let iter = 0; iter < maxIter; iter++) {
    // find largest off-diagonal
    let p = 0, q = 1, max = 0;
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      if (Math.abs(A[i][j]) > max) { max = Math.abs(A[i][j]); p = i; q = j; }
    }
    if (max < 1e-10) break;
    const app = A[p][p], aqq = A[q][q], apq = A[p][q];
    const phi = 0.5 * Math.atan2(2 * apq, aqq - app);
    const c = Math.cos(phi), s = Math.sin(phi);
    for (let k = 0; k < n; k++) {
      const akp = A[k][p], akq = A[k][q];
      A[k][p] = c * akp - s * akq;
      A[k][q] = s * akp + c * akq;
    }
    for (let k = 0; k < n; k++) {
      const apk = A[p][k], aqk = A[q][k];
      A[p][k] = c * apk - s * aqk;
      A[q][k] = s * apk + c * aqk;
    }
  }
  return A.map((r, i) => r[i]).sort((x, y) => x - y);
}

/**
 * Fiedler value (2nd-smallest Laplacian eigenvalue) of the |correlation| graph
 * of advisory-module flags over a window. LOW = modules fire as independent
 * witnesses (healthy); HIGH = tightly coupled groupthink / correlated false
 * alarms. A principled, spectral companion to FlagCorrelationFusion (#8).
 *
 * @param flagHistory  array of flag vectors (rows = time, cols = modules)
 * @returns { fiedler, algebraicConnectivity, coherence, n }
 */
function fiedlerCoherence(flagHistory) {
  if (!Array.isArray(flagHistory) || flagHistory.length < 3) return { fiedler: null, n: flagHistory.length };
  const T = flagHistory.length, M = flagHistory[0].length;
  // means/std per module
  const mean = new Array(M).fill(0), std = new Array(M).fill(0);
  for (let j = 0; j < M; j++) { for (let i = 0; i < T; i++) mean[j] += flagHistory[i][j]; mean[j] /= T; }
  for (let j = 0; j < M; j++) { let s = 0; for (let i = 0; i < T; i++) s += (flagHistory[i][j] - mean[j]) ** 2; std[j] = Math.sqrt(s / T); }
  // weighted adjacency W = |corr|, zero diagonal
  const W = Array.from({ length: M }, () => new Array(M).fill(0));
  for (let a = 0; a < M; a++) for (let b = a + 1; b < M; b++) {
    let w = 0;
    if (std[a] > 1e-9 && std[b] > 1e-9) {
      let cov = 0; for (let i = 0; i < T; i++) cov += (flagHistory[i][a] - mean[a]) * (flagHistory[i][b] - mean[b]);
      w = Math.abs((cov / T) / (std[a] * std[b]));
    }
    W[a][b] = W[b][a] = w;
  }
  // Laplacian L = D - W
  const L = Array.from({ length: M }, () => new Array(M).fill(0));
  for (let a = 0; a < M; a++) {
    let deg = 0; for (let b = 0; b < M; b++) deg += W[a][b];
    for (let b = 0; b < M; b++) L[a][b] = (a === b ? deg : 0) - W[a][b];
  }
  const eig = jacobiEigenvalues(L);
  const fiedler = eig.length > 1 ? Math.max(0, eig[1]) : 0;
  return {
    fiedler: +fiedler.toFixed(4),
    algebraicConnectivity: +fiedler.toFixed(4),
    coherence: fiedler > 1.0 ? 'GROUPTHINK' : fiedler > 0.3 ? 'COUPLED' : 'INDEPENDENT',
    modules: M, samples: T,
    note: 'low Fiedler = independent witnesses (healthy); high = correlated groupthink.',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// #5(v2)  Lagged influence between module scores (Granger-style; NOT causal PC)
// ─────────────────────────────────────────────────────────────────────────────

function _pearson(x, y) {
  const n = Math.min(x.length, y.length); if (n < 3) return 0;
  let mx = 0, my = 0; for (let i = 0; i < n; i++) { mx += x[i]; my += y[i]; } mx /= n; my /= n;
  let cov = 0, sx = 0, sy = 0;
  for (let i = 0; i < n; i++) { const dx = x[i] - mx, dy = y[i] - my; cov += dx * dy; sx += dx * dx; sy += dy * dy; }
  return (sx < 1e-12 || sy < 1e-12) ? 0 : cov / Math.sqrt(sx * sy);
}

/**
 * Detect directional lagged association between module score series — a sign
 * that one module's score predicts another's NEXT value (possible suppression
 * or strategic coupling). HONEST SCOPE: this is lagged cross-correlation /
 * Granger-style predictive association, NOT identified causation (no PC /
 * do-calculus). It flags *predictive influence*, which is advisory only.
 *
 * @param scoreHistory  array of score vectors (rows = time, cols = M modules)
 * @param opts { lag=1, threshold=0.6 }
 * @returns { edges:[{from,to,lagCorr,suppression}], maxInfluence }
 */
function laggedInfluence(scoreHistory, opts = {}) {
  const lag = opts.lag || 1;
  const thr = opts.threshold != null ? opts.threshold : 0.6;
  if (!Array.isArray(scoreHistory) || scoreHistory.length < 8) return { edges: [], maxInfluence: 0, n: scoreHistory.length };
  const T = scoreHistory.length, M = scoreHistory[0].length;
  const col = j => scoreHistory.map(r => r[j]);
  const edges = []; let maxInfluence = 0;
  for (let i = 0; i < M; i++) for (let j = 0; j < M; j++) {
    if (i === j) continue;
    const xi = col(i).slice(0, T - lag);     // i at t
    const yj = col(j).slice(lag);            // j at t+lag
    const lagCorr = _pearson(xi, yj);
    // i→j influence beyond j's own persistence (control for j's autocorrelation)
    const yjPrev = col(j).slice(0, T - lag);
    const auto = _pearson(yjPrev, yj);
    const net = lagCorr - 0.5 * auto;        // partial-ish: discount j's self-persistence
    if (Math.abs(net) >= thr) {
      const meanI = col(i).reduce((a, b) => a + b, 0) / T;
      const meanJ = col(j).reduce((a, b) => a + b, 0) / T;
      edges.push({ from: i, to: j, lagCorr: +lagCorr.toFixed(3), net: +net.toFixed(3),
        suppression: net < 0 && meanI > meanJ }); // i high, drives j down → suppression
      maxInfluence = Math.max(maxInfluence, Math.abs(net));
    }
  }
  return { edges, maxInfluence: +maxInfluence.toFixed(3),
    suppressionDetected: edges.some(e => e.suppression),
    note: 'Granger-style lagged predictive association; advisory only, not identified causation.' };
}

module.exports = {
  permutationEntropy, jsComplexity, entropyComplexityRegime,
  cusumChangePoint,
  perturbedObserverConsensus,
  orthogonalityScore,
  FlagCorrelationFusion,
  graphCycleSignal,
  jacobiEigenvalues, fiedlerCoherence,
  laggedInfluence,
};
