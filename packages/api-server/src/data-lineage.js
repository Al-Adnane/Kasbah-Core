'use strict';

/**
 * data-lineage.js — foundational chain-of-custody tracking for agentic data.
 *
 * Every governed interaction (scan/govern/MCP call) records a lineage edge:
 *   keyId → surface → verdict → receipt (verify URL) → ts
 *
 * This is the queryable proof of WHERE any piece of data an agent touched
 * came from, what Kasbah decided about it, and which cryptographic receipt
 * attests the decision — the Nightfall-class capability, implemented as a
 * bounded in-memory ring (no unbounded growth).
 *
 * Honest scope: lineage edges are per-key and per-surface with a capped ring
 * per key (last 500 edges). Persistence is in-memory (matching the gateway's
 * current store); a durable sink should read the SIEM feed or the audit log.
 */

const RING_LIMIT = 500;

const _lineage = new Map(); // keyId → [edges, newest first]
const _stats = { edges: 0, denies: 0, surfaces: new Set() };

/**
 * Record one lineage edge.
 * @param {{keyId?:string, surface?:string, verdict?:string, intervention?:string,
 *          risk?:number, receiptUrl?:string, threats?:Array, kind?:string}} ev
 */
function record(ev) {
  try {
    const keyId = ev.keyId || 'anonymous';
    const edge = {
      ts: ev.ts || new Date().toISOString(),
      kind: ev.kind || 'interaction',
      surface: ev.surface || 'unknown',
      verdict: ev.verdict || null,
      intervention: ev.intervention || null,
      risk: ev.risk != null ? +Number(ev.risk).toFixed(4) : null,
      threats: (ev.threats || []).slice(0, 8),
      receiptUrl: ev.receiptUrl || null,
    };
    let ring = _lineage.get(keyId);
    if (!ring) { ring = []; _lineage.set(keyId, ring); }
    ring.unshift(edge);
    if (ring.length > RING_LIMIT) ring.length = RING_LIMIT;
    _stats.edges++;
    if (edge.verdict === 'DENY' || edge.intervention === 'hard_block') _stats.denies++;
    _stats.surfaces.add(edge.surface);
    return true;
  } catch (_) { return false; }
}

/** Lineage chain for one key (newest first), optionally filtered by surface. */
function chain(keyId, { surface, limit = 100 } = {}) {
  const ring = _lineage.get(keyId || 'anonymous') || [];
  const filtered = surface ? ring.filter(e => e.surface === surface) : ring;
  return filtered.slice(0, Math.max(1, Math.min(500, limit)));
}

/** Aggregate lineage stats — surfaces the data has flowed through. */
function stats() {
  return {
    keys: _lineage.size,
    edges: _stats.edges,
    denies: _stats.denies,
    surfaces: [..._stats.surfaces],
    ringLimit: RING_LIMIT,
  };
}

/** Provenance summary for one key — plain-English "where your data went". */
function provenance(keyId) {
  const ring = _lineage.get(keyId || 'anonymous') || [];
  const bySurface = {};
  ring.forEach(e => { bySurface[e.surface] = (bySurface[e.surface] || 0) + 1; });
  const lastDeny = ring.find(e => e.verdict === 'DENY');
  return {
    keyId: keyId ? String(keyId).slice(0, 8) : 'anonymous',
    totalTracked: ring.length,
    surfaces: Object.entries(bySurface).map(([s, n]) => ({ surface: s, count: n })),
    lastDeny: lastDeny || null,
    receipts: ring.filter(e => e.receiptUrl).length,
  };
}

module.exports = { record, chain, stats, provenance };