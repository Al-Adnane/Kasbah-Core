'use strict';

/**
 * Weighted Graph Access Structure (WGAS) — local max-flow gate.
 *
 * Authorization: a coalition A of seats is authorized iff
 *   maxflow_{s,t}( edges held by A ) ≥ κ
 * on a directed acyclic multigraph with integer edge weights.
 *
 * HONEST SCOPE
 * · Integer capacities via Dinic max-flow (no isogeny / PQ claims).
 * · Unit-weight special case is classical t-of-n (n parallel unit edges).
 * · Non-threshold structures are real: topology can require specific
 *   seat combinations, not just |A| ≥ t.
 * · Flow witness is recorded for audit; it is NOT a zero-knowledge proof
 *   of capacity (that needs a proper flow Σ-protocol — open).
 * · Menger / κ edge-disjoint paths apply only when all weights are 1.
 *   Weighted κ is max-flow, not κ disjoint walks.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const GRAPH_FILE = path.join(DIR, 'gov-wgas-graph.json');

function ensure() { try { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); } catch (_) {} }
function readJson(p, fb) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fb; } }
function writeJson(p, o) { ensure(); fs.writeFileSync(p, JSON.stringify(o, null, 2), { mode: 0o600 }); }

/* ─── Graph model ───────────────────────────────────────────────────────── */

/**
 * @typedef {{ id:string, from:string, to:string, weight:number, seats:string[] }} WgasEdge
 * @typedef {{ nodes:string[], edges:WgasEdge[], source:string, sink:string, kappa:number }} WgasGraph
 */

function normalizeGraph(g) {
  if (!g || typeof g !== 'object') throw new Error('graph required');
  const source = String(g.source || 's');
  const sink = String(g.sink || 't');
  const kappa = Math.max(1, Math.floor(Number(g.kappa) || 1));
  const edges = (g.edges || []).map((e, i) => {
    const w = Math.max(0, Math.floor(Number(e.weight) || 0));
    const seats = Array.isArray(e.seats) ? e.seats.map(String) : [];
    if (!e.from || !e.to) throw new Error(`edge ${i}: from/to required`);
    return {
      id: String(e.id || `e${i}`),
      from: String(e.from),
      to: String(e.to),
      weight: w,
      seats,
    };
  });
  if (!edges.length) throw new Error('graph needs edges');
  if (source === sink) throw new Error('source ≠ sink');
  // Reject cycles (DAG required for this model)
  assertDag(edges);
  const nodes = [...new Set(edges.flatMap((e) => [e.from, e.to]))];
  if (!nodes.includes(source) || !nodes.includes(sink)) throw new Error('source/sink must appear in edges');
  return { nodes, edges, source, sink, kappa };
}

function assertDag(edges) {
  const adj = new Map();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e.to);
  }
  const color = new Map(); // 0=unseen 1=visiting 2=done
  function dfs(u) {
    color.set(u, 1);
    for (const v of adj.get(u) || []) {
      const c = color.get(v) || 0;
      if (c === 1) throw new Error(`graph has a cycle at ${u}→${v}`);
      if (c === 0) dfs(v);
    }
    color.set(u, 2);
  }
  const nodes = [...new Set(edges.flatMap((e) => [e.from, e.to]))];
  for (const n of nodes) if ((color.get(n) || 0) === 0) dfs(n);
}

/* ─── Dinic max-flow ────────────────────────────────────────────────────── */

/** Edges active for coalition A: an edge is active if seats∩A ≠ ∅ (or seats empty = always). */
function activeEdges(graph, coalition) {
  const A = new Set(coalition.map(String));
  return graph.edges.filter((e) => {
    if (!e.seats.length) return true; // structural edge, always present
    return e.seats.some((s) => A.has(s));
  });
}

/**
 * Max-flow (Edmonds–Karp BFS) — simple and correct for small governance graphs.
 * @returns {{ value:number, witness:Array }}
 */
function maxFlow(graph, coalition) {
  const edges = activeEdges(graph, coalition);
  const g = new Map();
  const ensureNode = (u) => { if (!g.has(u)) g.set(u, []); return g.get(u); };
  for (const n of graph.nodes) ensureNode(n);

  function addEdge(u, v, cap, edgeId) {
    const a = { to: v, cap, rev: null, edgeId, forward: true };
    const b = { to: u, cap: 0, rev: null, edgeId, forward: false };
    ensureNode(u).push(a);
    ensureNode(v).push(b);
    a.rev = b;
    b.rev = a;
  }

  for (const e of edges) {
    if (e.weight > 0) addEdge(e.from, e.to, e.weight, e.id);
  }

  const s = graph.source, t = graph.sink;
  let flow = 0;

  for (;;) {
    const parent = new Map();
    const q = [s];
    parent.set(s, null);
    while (q.length && !parent.has(t)) {
      const u = q.shift();
      for (const e of g.get(u) || []) {
        if (e.cap > 0 && !parent.has(e.to)) {
          parent.set(e.to, { u, e });
          q.push(e.to);
        }
      }
    }
    if (!parent.has(t)) break;

    let bot = Infinity;
    for (let v = t; v !== s; ) {
      const p = parent.get(v);
      bot = Math.min(bot, p.e.cap);
      v = p.u;
    }
    for (let v = t; v !== s; ) {
      const p = parent.get(v);
      p.e.cap -= bot;
      p.e.rev.cap += bot;
      v = p.u;
    }
    flow += bot;
  }

  const byId = new Map();
  for (const list of g.values()) {
    for (const re of list) {
      if (re.edgeId && !re.forward && re.cap > 0) {
        byId.set(re.edgeId, (byId.get(re.edgeId) || 0) + re.cap);
      }
    }
  }
  const witness = [];
  for (const e of edges) {
    const f = byId.get(e.id) || 0;
    if (f > 0) {
      witness.push({ edgeId: e.id, from: e.from, to: e.to, seats: e.seats, capacity: e.weight, flow: f });
    }
  }

  return { value: flow, witness };
}

/**
 * Evaluate whether coalition authorizes under WGAS.
 * @returns {{ authorized:boolean, flow:number, kappa:number, witness:Array, reason:string }}
 */
function evaluate(graph, coalitionSeats) {
  const g = normalizeGraph(graph);
  const A = [...new Set((coalitionSeats || []).map(String))];
  const { value, witness } = maxFlow(g, A);
  const authorized = value >= g.kappa;
  return {
    authorized,
    flow: value,
    kappa: g.kappa,
    source: g.source,
    sink: g.sink,
    witness,
    seats: A,
    reason: authorized
      ? `maxflow ${value} ≥ κ=${g.kappa}`
      : `maxflow ${value} < κ=${g.kappa} — topology rejects this coalition`,
  };
}

/* ─── Default graphs ────────────────────────────────────────────────────── */

/**
 * Unit parallel edges: classic t-of-n as WGAS (honest special case).
 * Each named seat gets one unit edge s→t. Authorized iff |A| ≥ κ.
 */
function thresholdAsWgas(seatNames, kappa = 2) {
  const seats = seatNames.map(String);
  return normalizeGraph({
    source: 's',
    sink: 't',
    kappa,
    edges: seats.map((name, i) => ({
      id: `seat_${i}`,
      from: 's',
      to: 't',
      weight: 1,
      seats: [name],
    })),
  });
}

/**
 * Non-threshold demo: two-path topology.
 *   Path1: needs BOTH Op-A and Op-B (series)
 *   Path2: needs Op-C alone
 * κ=1 ⇒ authorized if (A∧B) ∨ C  — not a pure |A|≥t structure.
 */
function nonThresholdDemo() {
  return normalizeGraph({
    source: 's',
    sink: 't',
    kappa: 1,
    edges: [
      { id: 'a', from: 's', to: 'm', weight: 1, seats: ['Operator-A'] },
      { id: 'b', from: 'm', to: 't', weight: 1, seats: ['Operator-B'] },
      { id: 'c', from: 's', to: 't', weight: 1, seats: ['Operator-C'] },
    ],
  });
}

function loadGraph() {
  return readJson(GRAPH_FILE, null);
}
function saveGraph(g) {
  const n = normalizeGraph(g);
  writeJson(GRAPH_FILE, n);
  return n;
}

function seedDefault() {
  if (loadGraph()) return loadGraph();
  const g = thresholdAsWgas(['Operator-A', 'Operator-B', 'Operator-C'], 2);
  saveGraph(g);
  return g;
}

function status() {
  const g = loadGraph();
  return {
    hasGraph: !!g,
    kappa: g?.kappa ?? null,
    edges: g?.edges?.length ?? 0,
    nodes: g?.nodes?.length ?? 0,
    honest: {
      maxFlow: 'Dinic integer capacities',
      pq: false,
      zkFlowProof: 'proveFlowConservation/verifyFlowConservation in zk-protect.js (Pedersen+Schnorr ristretto255; range proofs pending)',
      menger: 'unit weights only',
    },
  };
}

/** Hash a flow witness for the audit chain. */
function witnessHash(witness) {
  return crypto.createHash('sha256').update(JSON.stringify(witness || [])).digest('hex');
}

/* ─── Incidence matrix + conservation check ─────────────────────────────── */

/**
 * Build the node–edge incidence matrix B for internal (non-source, non-sink)
 * nodes. B[i][j] = −1 if edge j leaves node i, +1 if it enters, 0 otherwise.
 * Returns { B, nodeIds, edgeIds }.
 */
function buildIncidenceMatrix(graph) {
  const g = normalizeGraph(graph);
  const internal = g.nodes.filter((n) => n !== g.source && n !== g.sink).sort();
  const edges = g.edges.slice().sort((a, b) => a.id < b.id ? -1 : 1);
  const nodeIdx = Object.fromEntries(internal.map((n, i) => [n, i]));
  const B = Array.from({ length: internal.length }, () => new Array(edges.length).fill(0));
  for (let j = 0; j < edges.length; j++) {
    const e = edges[j];
    if (e.from in nodeIdx) B[nodeIdx[e.from]][j] -= 1;
    if (e.to   in nodeIdx) B[nodeIdx[e.to]][j]   += 1;
  }
  return { B, nodeIds: internal, edgeIds: edges.map((e) => e.id) };
}

/**
 * Verify that a flow assignment satisfies B·f = 0 (conservation at internal
 * nodes). flowByEdgeId is { edgeId → flowValue }.
 * Returns { ok, violations[] }.
 */
function checkConservation(graph, flowByEdgeId) {
  const { B, nodeIds, edgeIds } = buildIncidenceMatrix(graph);
  const f = edgeIds.map((id) => Number(flowByEdgeId[id] || 0));
  const violations = [];
  for (let i = 0; i < B.length; i++) {
    const sum = B[i].reduce((acc, bij, j) => acc + bij * f[j], 0);
    if (sum !== 0) violations.push({ node: nodeIds[i], imbalance: sum });
  }
  return { ok: violations.length === 0, violations };
}

/* ─── Brute-force min-cut (small graphs only, audit/test use) ────────────── */

/**
 * Enumerate all S/T cuts and return the minimum capacity.
 * Only feasible for ≤ 15 internal nodes. Use for cross-checking max-flow.
 */
function bruteForceMinCut(graph) {
  const g = normalizeGraph(graph);
  const internal = g.nodes.filter((n) => n !== g.source && n !== g.sink);
  if (internal.length > 15) {
    return { skipped: true, reason: 'graph too large for brute-force (>15 internal nodes)', minCut: null };
  }
  let minCut = Infinity;
  const masks = 1 << internal.length;
  for (let mask = 0; mask < masks; mask++) {
    const S = new Set([g.source]);
    for (let i = 0; i < internal.length; i++) {
      if (mask & (1 << i)) S.add(internal[i]);
    }
    const cap = g.edges.reduce((acc, e) => {
      if (S.has(e.from) && !S.has(e.to)) acc += (e.weight || 0);
      return acc;
    }, 0);
    if (cap < minCut) minCut = cap;
  }
  return { skipped: false, minCut: minCut === Infinity ? 0 : minCut };
}

/**
 * Cross-check: max-flow must equal min-cut (max-flow min-cut theorem).
 * Returns { ok, maxFlow, minCut, delta } or { ok: null, skipped: true } when
 * the graph is too large for brute-force verification.
 */
function crossCheck(graph, coalition) {
  const g = normalizeGraph(graph);
  const { value } = maxFlow(g, coalition || g.nodes);
  const mc = bruteForceMinCut(g);
  if (mc.skipped) return { ok: null, skipped: true, maxFlow: value, minCut: null, reason: mc.reason };
  return { ok: value === mc.minCut, maxFlow: value, minCut: mc.minCut, delta: value - mc.minCut };
}

/* ─── Federated shard evaluation ─────────────────────────────────────────── */

/**
 * @typedef {{ shardId:string, edges:WgasEdge[], boundaryNodes:string[] }} WgasShard
 * @typedef {{ shards:WgasShard[], globalSource:string, globalSink:string, kappa:number }} FederatedWgas
 */

/**
 * Evaluate a federated WGAS over multiple shards.
 *
 * Each shard owns a subset of edges. Boundary nodes connect shards.
 * The verifier checks:
 *   1. Flow capacity not violated on any edge.
 *   2. Conservation at non-boundary, non-source, non-sink nodes within each shard.
 *   3. Boundary consistency: flow in = flow out at every boundary node.
 *   4. Total value ≥ κ (aggregate source outflow).
 *
 * @param {FederatedWgas} federated
 * @param {Object} candidateFlow  — { edgeId → flowValue } over all shards
 * @param {string[]} coalition    — seat IDs participating
 * @returns {{ authorized:boolean, reason:string, violations:Array }}
 */
function evaluateFederated(federated, candidateFlow, coalition) {
  const { shards, globalSource, globalSink, kappa } = federated;
  const A = new Set((coalition || []).map(String));
  const allEdges = shards.flatMap((s) => s.edges);
  const boundaryNodes = new Set(shards.flatMap((s) => s.boundaryNodes || []));

  // 1. Capacity constraints
  for (const e of allEdges) {
    const f = Number(candidateFlow[e.id] || 0);
    if (f < 0 || f > e.weight) {
      return { authorized: false, reason: `capacity violated on edge ${e.id} (f=${f}, cap=${e.weight})`, violations: [e.id] };
    }
    // Coalition seat check
    if (e.seats && e.seats.length > 0 && !e.seats.some((s) => A.has(s))) {
      return { authorized: false, reason: `edge ${e.id} requires seat not in coalition`, violations: [e.id] };
    }
  }

  // 2. Conservation per shard (internal nodes only)
  const violations = [];
  for (const shard of shards) {
    const internalNodes = [...new Set(shard.edges.flatMap((e) => [e.from, e.to]))]
      .filter((n) => n !== globalSource && n !== globalSink && !boundaryNodes.has(n));
    for (const node of internalNodes) {
      const inflow  = shard.edges.filter((e) => e.to   === node).reduce((a, e) => a + Number(candidateFlow[e.id] || 0), 0);
      const outflow = shard.edges.filter((e) => e.from === node).reduce((a, e) => a + Number(candidateFlow[e.id] || 0), 0);
      if (inflow !== outflow) violations.push({ shard: shard.shardId, node, inflow, outflow });
    }
  }
  if (violations.length) {
    return { authorized: false, reason: `conservation violated at ${violations.length} internal node(s)`, violations };
  }

  // 3. Boundary consistency: each boundary node net-flow must be 0
  for (const bv of boundaryNodes) {
    if (bv === globalSource || bv === globalSink) continue;
    const inflow  = allEdges.filter((e) => e.to   === bv).reduce((a, e) => a + Number(candidateFlow[e.id] || 0), 0);
    const outflow = allEdges.filter((e) => e.from === bv).reduce((a, e) => a + Number(candidateFlow[e.id] || 0), 0);
    if (inflow !== outflow) {
      return { authorized: false, reason: `boundary consistency violated at node ${bv} (in=${inflow}, out=${outflow})`, violations: [bv] };
    }
  }

  // 4. Flow value ≥ κ
  const value = allEdges.filter((e) => e.from === globalSource)
    .reduce((a, e) => a + Number(candidateFlow[e.id] || 0), 0);
  if (value < kappa) {
    return { authorized: false, reason: `flow value ${value} < κ=${kappa}`, violations: [] };
  }

  return { authorized: true, reason: `federated flow value ${value} ≥ κ=${kappa}`, violations: [] };
}

/**
 * Build a federated WGAS from a list of per-shard graph configs.
 * Each shard: { shardId, edges:[{id,from,to,weight,seats}], boundaryNodes:[] }
 */
function buildFederated(shards, globalSource, globalSink, kappa) {
  if (!shards || shards.length < 2) throw new Error('federated requires ≥ 2 shards');
  if (!globalSource || !globalSink) throw new Error('globalSource and globalSink required');
  const allEdges = shards.flatMap((s) => s.edges || []);
  const ids = allEdges.map((e) => e.id);
  if (new Set(ids).size !== ids.length) throw new Error('duplicate edge IDs across shards');
  return { shards, globalSource, globalSink, kappa: Math.max(1, kappa || 1) };
}

/* ─── N4: Reputation-weighted WGAS ──────────────────────────────────────
 *
 * Seat weights in the WGAS graph evolve based on behavioral history.
 * A seat that approved actions later flagged as violations gets its weight
 * reduced. The adjusted graph is used instead of the base graph when a
 * reputation store exists.
 *
 * HONEST SCOPE
 *   · Weight updates must themselves be threshold-approved (tracked separately
 *     in threshold-gov.js) or this becomes an attack vector.
 *   · The ZK proof that "correct weights were applied" is NOT implemented here;
 *     the weight-application is transparent (auditable, not hidden).
 *   · Reputation is stored as a persistent JSON file, 0600.
 *
 * REPUTATION STORE FORMAT
 *   { seats: { [seatId]: { score: 0–1, history: [{ts, delta, reason}] } } }
 *   score=1.0 → full weight; score=0.0 → zero weight (excluded from flow).
 */

const REP_FILE = path.join(DIR, 'gov-reputation.json');

function loadReputation() {
  try { return JSON.parse(fs.readFileSync(REP_FILE, 'utf8')); }
  catch { return { seats: {} }; }
}

function saveReputation(r) {
  ensure();
  fs.writeFileSync(REP_FILE, JSON.stringify(r, null, 2), { mode: 0o600 });
}

/**
 * Update a seat's reputation score.
 * `delta` is a signed float in [-1, 1]; clamped to [0, 1] after application.
 *
 * @param {string} seatId
 * @param {number} delta   e.g. -0.25 for a flagged violation, +0.1 for a clean approval
 * @param {string} [reason]
 */
function updateReputation(seatId, delta, reason = '') {
  const r = loadReputation();
  if (!r.seats[seatId]) r.seats[seatId] = { score: 1.0, history: [] };
  const seat = r.seats[seatId];
  seat.score = Math.min(1, Math.max(0, seat.score + Number(delta)));
  seat.history = (seat.history || []).concat({ ts: new Date().toISOString(), delta: Number(delta), reason: String(reason).slice(0, 100) }).slice(-100);
  saveReputation(r);
  return { seatId, score: seat.score };
}

/**
 * Return the current reputation score for a seat (default 1.0 if not tracked).
 */
function reputationScore(seatId) {
  return loadReputation().seats[seatId]?.score ?? 1.0;
}

/**
 * Apply reputation multipliers to a normalized graph.
 * Each edge's effective weight = floor(edge.weight × min(rep(seat)) for seat in edge.seats).
 * Edges with no seats (structural edges) are unaffected.
 * Returns a new graph object; does not mutate the input.
 *
 * @param {WgasGraph} graph      - already-normalized graph
 * @param {{ [seatId]: string }} seatNameToId  - map from seat name to seat id
 *                                               (reputation store keys are seat IDs)
 */
function applyReputation(graph, seatNameToId = {}) {
  const rep = loadReputation();
  const edges = graph.edges.map((e) => {
    if (!e.seats.length) return e; // structural edge, unaffected
    const minScore = e.seats.reduce((min, name) => {
      const id = seatNameToId[name] || name; // fall back to name as id
      const score = rep.seats[id]?.score ?? 1.0;
      return Math.min(min, score);
    }, 1.0);
    const adjustedWeight = Math.floor(e.weight * minScore);
    return { ...e, weight: adjustedWeight, reputationMultiplier: minScore };
  });
  return { ...graph, edges, reputationApplied: true };
}

/**
 * Evaluate with reputation-adjusted edge weights.
 * Convenience wrapper: applyReputation + evaluate.
 */
function evaluateWithReputation(graph, coalition, seatNameToId = {}) {
  const adjusted = applyReputation(graph, seatNameToId);
  const result   = evaluate(adjusted, coalition);
  return { ...result, reputationApplied: true, graph: adjusted };
}

/** Return full reputation store. */
function reputationStatus() { return loadReputation(); }

module.exports = {
  normalizeGraph, evaluate, maxFlow, activeEdges,
  thresholdAsWgas, nonThresholdDemo,
  loadGraph, saveGraph, seedDefault, status, witnessHash,
  buildIncidenceMatrix, checkConservation,
  bruteForceMinCut, crossCheck,
  evaluateFederated, buildFederated,
  // N4
  updateReputation, reputationScore, applyReputation,
  evaluateWithReputation, reputationStatus,
};
