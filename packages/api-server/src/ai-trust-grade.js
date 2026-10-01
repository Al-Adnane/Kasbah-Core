'use strict';

/**
 * AI Trust Grade — multi-factor trust score for an AI surface (host + session).
 *
 * Goes beyond classic web "privacy grade" (trackers only) by scoring what
 * actually matters when AI is in the loop:
 *
 *   leaks     secrets/PII blocked before egress
 *   injection prompt-injection / jailbreak attempts stopped
 *   agents    tool calls, MCP, media (screen/camera/mic) intercepted
 *   receipts  shareable cryptographic proof density
 *   offline   protection continuity (fail-open is a grade penalty)
 *
 * Grade A–F. Deterministic, explainable, no trained model — every point traces
 * to a counted event so users and auditors can see WHY.
 */

const WEIGHTS = {
  leaks: 30,
  injection: 25,
  agents: 20,
  receipts: 15,
  hygiene: 10, // tracker block + media discipline + offline penalty inverse
};

const GRADE_BANDS = [
  { min: 90, grade: 'A', label: 'Fortress' },
  { min: 80, grade: 'B', label: 'Hardened' },
  { min: 70, grade: 'C', label: 'Guarded' },
  { min: 55, grade: 'D', label: 'Exposed' },
  { min: 0, grade: 'F', label: 'Unprotected' },
];

function _clamp01(n) {
  return Math.max(0, Math.min(1, Number(n) || 0));
}

/** Log-saturation: more events help, but with diminishing returns. */
function _sat(count, halfLife) {
  const c = Math.max(0, Number(count) || 0);
  return 1 - Math.exp(-c / Math.max(1, halfLife));
}

/**
 * @param {object} events
 * @param {number} events.scanned           prompts/actions scanned
 * @param {number} events.blocked           hard blocks (leaks + injection)
 * @param {number} events.secretsBlocked    secret/PII egress prevented
 * @param {number} events.injectionBlocked  injection/jailbreak prevented
 * @param {number} events.agentIntercepts   tool/MCP/media intercepts
 * @param {number} events.receiptsIssued    signed receipts
 * @param {number} events.trackersBlocked   web tracker blocks
 * @param {number} events.mediaAlerts       screen/camera/mic alerts
 * @param {number} events.offlineScans      scans that ran while gateway down
 * @param {number} events.warnings          soft warnings
 * @param {string} [events.host]            hostname
 * @param {boolean} [events.enabled]        protection enabled (default true)
 */
function grade(events = {}) {
  const enabled = events.enabled !== false;
  const scanned = Math.max(0, Number(events.scanned) || 0);
  const secretsBlocked = Math.max(0, Number(events.secretsBlocked) || 0);
  const injectionBlocked = Math.max(0, Number(events.injectionBlocked) || 0);
  const blocked = Math.max(0, Number(events.blocked) || secretsBlocked + injectionBlocked);
  const agentIntercepts = Math.max(0, Number(events.agentIntercepts) || 0);
  const receiptsIssued = Math.max(0, Number(events.receiptsIssued) || 0);
  const trackersBlocked = Math.max(0, Number(events.trackersBlocked) || 0);
  const mediaAlerts = Math.max(0, Number(events.mediaAlerts) || 0);
  const offlineScans = Math.max(0, Number(events.offlineScans) || 0);
  const warnings = Math.max(0, Number(events.warnings) || 0);

  // Component scores in 0..1 — "good" means protection is working.
  const leaks = secretsBlocked > 0 ? Math.min(1, 0.55 + 0.45 * _sat(secretsBlocked, 2)) : scanned > 0 ? 0.35 : 0.15;
  const injection = injectionBlocked > 0 ? Math.min(1, 0.55 + 0.45 * _sat(injectionBlocked, 2)) : scanned > 0 ? 0.4 : 0.2;
  const agents = agentIntercepts > 0 ? Math.min(1, 0.5 + 0.5 * _sat(agentIntercepts, 3)) : 0.45;
  const receipts = receiptsIssued > 0 ? Math.min(1, 0.4 + 0.6 * _sat(receiptsIssued, 4)) : 0.25;
  let hygiene = 0.45 + 0.35 * _sat(trackersBlocked, 8) + 0.2 * (mediaAlerts === 0 ? 1 : 0.5);
  hygiene -= 0.35 * _sat(offlineScans, 1);
  hygiene -= 0.08 * _sat(warnings, 6);
  hygiene = _clamp01(hygiene);

  if (!enabled) {
    return {
      grade: 'F',
      score: 0,
      label: 'Unprotected',
      enabled: false,
      host: events.host || null,
      components: { leaks: 0, injection: 0, agents: 0, receipts: 0, hygiene: 0 },
      weights: WEIGHTS,
      factors: [
        { id: 'protection', impact: -100, note: 'Protection is off' },
      ],
      formula: 'score = 100 · Σ weight_i · component_i',
      generatedAt: new Date().toISOString(),
    };
  }

  const components = { leaks, injection, agents, receipts, hygiene };
  let score = 0;
  score += WEIGHTS.leaks * leaks;
  score += WEIGHTS.injection * injection;
  score += WEIGHTS.agents * agents;
  score += WEIGHTS.receipts * receipts;
  score += WEIGHTS.hygiene * hygiene;

  // Live threat pressure: lots of blocks with few scans is a hostile surface.
  if (scanned >= 5 && blocked / scanned > 0.4) score += 3;
  // Proof culture: receipts on every serious event.
  if (receiptsIssued > 0 && blocked > 0 && receiptsIssued >= blocked) score += 2;

  score = Math.round(Math.max(0, Math.min(100, score)));
  const band = GRADE_BANDS.find((b) => score >= b.min) || GRADE_BANDS[GRADE_BANDS.length - 1];

  const factors = [];
  if (secretsBlocked) factors.push({ id: 'secrets_blocked', impact: +Math.round(WEIGHTS.leaks * 0.4), note: `${secretsBlocked} secret/PII leak(s) stopped` });
  if (injectionBlocked) factors.push({ id: 'injection_blocked', impact: +Math.round(WEIGHTS.injection * 0.4), note: `${injectionBlocked} injection attempt(s) stopped` });
  if (agentIntercepts) factors.push({ id: 'agent_intercepts', impact: +10, note: `${agentIntercepts} agent/media intercept(s)` });
  if (receiptsIssued) factors.push({ id: 'receipts', impact: +8, note: `${receiptsIssued} portable proof(s) issued` });
  if (trackersBlocked) factors.push({ id: 'trackers', impact: +5, note: `${trackersBlocked} tracker(s) blocked` });
  if (offlineScans) factors.push({ id: 'offline', impact: -12, note: `${offlineScans} scan(s) while gateway offline` });
  if (mediaAlerts) factors.push({ id: 'media', impact: -4, note: `${mediaAlerts} media access alert(s)` });

  return {
    grade: band.grade,
    score,
    label: band.label,
    enabled: true,
    host: events.host || null,
    components: Object.fromEntries(Object.entries(components).map(([k, v]) => [k, +v.toFixed(3)])),
    weights: WEIGHTS,
    factors,
    formula: 'score = 100 · Σ weight_i · component_i  (+ live pressure / proof bonuses)',
    generatedAt: new Date().toISOString(),
  };
}

/** Emoji-free letter chip for UI. */
function chip(g) {
  const map = {
    A: { color: '#10b981', title: 'Fortress' },
    B: { color: '#3d9cf0', title: 'Hardened' },
    C: { color: '#f5a623', title: 'Guarded' },
    D: { color: '#e25555', title: 'Exposed' },
    F: { color: '#8b9cb3', title: 'Unprotected' },
  };
  return { letter: g.grade, score: g.score, ...(map[g.grade] || map.F) };
}

/**
 * Bridge desktop protection-score.js into the letter grade — do NOT invent a
 * second aggregate when the desktop already has weighted VPN/agent/egress/
 * governance/dns/scam signals. Accepts `{ score, tier, signals }` from
 * protectionScore.compute().
 */
function fromProtectionScore(ps = {}, extra = {}) {
  const score = Math.max(0, Math.min(100, Number(ps.score) || 0));
  const band = GRADE_BANDS.find((b) => score >= b.min) || GRADE_BANDS[GRADE_BANDS.length - 1];
  return {
    grade: band.grade,
    score,
    label: band.label,
    enabled: true,
    source: 'protection-score',
    desktopTier: ps.tier || null,
    signals: ps.signals || null,
    components: {
      // Map desktop weighted risk into seatbelt-ish components (inverted: high = safe).
      leaks: 1 - (ps.signals?.egress?.risk ?? 0.5),
      injection: 1 - (ps.signals?.governance?.risk ?? 0.5),
      agents: 1 - (ps.signals?.agent?.risk ?? 0.5),
      receipts: extra.receipts != null ? _clamp01(extra.receipts) : 0.5,
      hygiene: 1 - ((ps.signals?.dns?.risk ?? 0) * 0.5 + (ps.signals?.vpn?.risk ?? 0.5) * 0.5),
    },
    weights: WEIGHTS,
    factors: [],
    formula: 'letter grade derived from desktop protection-score.js (single source of aggregate risk)',
    generatedAt: new Date().toISOString(),
  };
}

module.exports = { grade, chip, fromProtectionScore, WEIGHTS, GRADE_BANDS };
