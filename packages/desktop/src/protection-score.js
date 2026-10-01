'use strict';

/**
 * Unified protection score — aggregates all Kasbah desktop signals into a
 * single [0, 100] score and a color-coded severity tier.
 *
 * Consumed by:
 *   - Tray icon (color badge)
 *   - Desktop dashboard (overall status ring)
 *   - IPC: 'protection:score' → renderer
 *
 * Signals (each normalised to [0, 1] contribution):
 *   vpn        — tunnel up/down, kill-switch status
 *   agent      — agent-guard lock state
 *   egress     — last egress-classifier risk score
 *   governance — last governance pipeline risk score
 *   dns        — DNS-leak check result
 *   scam       — last scam-shield verdict
 *
 * The score is DEFENSIVE: higher = better protected.
 * score = 100 − weighted_risk × 100
 *
 * Weights are intentionally asymmetric: VPN and agent-guard carry the most
 * weight because they gate actual execution; egress and governance carry
 * detection risk; DNS is informational.
 */

const WEIGHTS = {
  vpn:        0.30,
  agent:      0.25,
  egress:     0.20,
  governance: 0.15,
  dns:        0.05,
  scam:       0.05,
};

const DEFAULT_STATE = {
  vpn:        { risk: 0.5,  detail: 'unknown' },
  agent:      { risk: 0,    detail: 'ok' },
  egress:     { risk: 0,    detail: 'clean' },
  governance: { risk: 0,    detail: 'clean' },
  dns:        { risk: 0,    detail: 'ok' },
  scam:       { risk: 0,    detail: 'clean' },
};

const _state = Object.assign({}, DEFAULT_STATE);
let _listeners = [];

// ─── public API ───────────────────────────────────────────────────────────────

function update(signal, value) {
  if (!(signal in _state)) return;
  if (typeof value === 'number') {
    _state[signal] = { risk: Math.max(0, Math.min(1, value)), detail: _state[signal].detail };
  } else if (value && typeof value === 'object') {
    _state[signal] = { risk: Math.max(0, Math.min(1, value.risk ?? 0)), detail: value.detail || '' };
  }
  _emit();
}

function compute() {
  let weightedRisk = 0;
  for (const [k, w] of Object.entries(WEIGHTS)) {
    weightedRisk += (_state[k]?.risk ?? 0) * w;
  }
  const score = Math.round(100 - weightedRisk * 100);
  const tier = score >= 85 ? 'protected'
    : score >= 60 ? 'degraded'
    : score >= 35 ? 'at-risk'
    : 'critical';
  const color = { protected: '#22c55e', degraded: '#f59e0b', 'at-risk': '#ef4444', critical: '#7c3aed' }[tier];
  return { score, tier, color, signals: Object.fromEntries(Object.entries(_state).map(([k, v]) => [k, { ...v }])) };
}

function subscribe(fn) {
  _listeners.push(fn);
  return () => { _listeners = _listeners.filter((f) => f !== fn); };
}

function _emit() {
  const result = compute();
  for (const fn of _listeners) { try { fn(result); } catch (_) {} }
}

// ─── VPN signal helpers ───────────────────────────────────────────────────────

function onVpnUp(location) {
  update('vpn', { risk: 0, detail: `connected:${location || 'unknown'}` });
}

function onVpnDown(reason) {
  update('vpn', { risk: 1, detail: `down:${reason || 'unknown'}` });
}

function onVpnDegraded() {
  update('vpn', { risk: 0.5, detail: 'degraded:health-check-failed' });
}

// ─── Agent signal helpers ─────────────────────────────────────────────────────

function onAgentLock(locked, reason) {
  update('agent', { risk: locked ? 0.9 : 0, detail: locked ? `locked:${reason || ''}` : 'ok' });
}

// ─── Governance signal helper ─────────────────────────────────────────────────

function onGovernance(riskFloat) {
  update('governance', { risk: riskFloat, detail: riskFloat >= 0.7 ? 'high-risk' : riskFloat >= 0.35 ? 'warn' : 'clean' });
}

// ─── Egress signal helper ─────────────────────────────────────────────────────

function onEgress(riskFloat) {
  update('egress', { risk: riskFloat, detail: riskFloat > 0 ? 'secret-detected' : 'clean' });
}

// ─── DNS signal helper ────────────────────────────────────────────────────────

function onDns(leakDetected) {
  update('dns', { risk: leakDetected ? 0.8 : 0, detail: leakDetected ? 'leak-detected' : 'ok' });
}

// ─── Scam signal helper ───────────────────────────────────────────────────────

function onScam(score100) {
  update('scam', { risk: Math.min(1, score100 / 100), detail: score100 >= 55 ? 'likely-scam' : score100 >= 25 ? 'suspicious' : 'clean' });
}

module.exports = {
  update,
  compute,
  subscribe,
  onVpnUp,
  onVpnDown,
  onVpnDegraded,
  onAgentLock,
  onGovernance,
  onEgress,
  onDns,
  onScam,
};
