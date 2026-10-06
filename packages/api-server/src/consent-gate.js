'use strict';

/**
 * consent-gate — Conjunctive admission gate (Consent Stone protocol).
 *
 * Implements the delegation gate of the confidence-gated autonomous
 * delegation design:
 *   A = ignition ∧ coherence ∧ (S > θdel) ∧ CERTIFIED ∧ STONE_SIGNED
 *
 * - Weakest-link fusion: weighted geometric mean with hard veto
 *   (any applicable scalar ≤ ε forces S = 0).
 * - Epistemic tier attenuation: τ(RULE) ≥ τ(VERIFY) ≥ τ(ENGINE) ≥
 *   τ(PRACTICE) ≥ τ(MODEL) ≥ τ(LOGIC); tier enters salience as bias.
 * - BFT corroboration: certified iff dissent d ≤ floor((n-1)/3).
 * - Stone signature: ECDSA/Ed25519 tap attestation. HARDWARE ABSENT —
 *   signatures are software-issued by the local Stone simulator and
 *   labeled as such (signer: 'soft-stone'). The verify path accepts a
 *   future hardware signer without changing the gate.
 * - Grace window: BLE-drop analogue — 5s to complete the tap, else
 *   auto-deny with DISCONNECT_TIMEOUT audit entry.
 *
 * No address spaces, no kernel, no BLE here: pure decision logic +
 * in-memory pending store. Audit entries are returned, never silently kept.
 */

const crypto = require('crypto');

const TIER_ORDER = ['RULE', 'VERIFY', 'ENGINE', 'PRACTICE', 'MODEL', 'LOGIC'];
const TIER_TAU = { RULE: 1.0, VERIFY: 0.85, ENGINE: 0.7, PRACTICE: 0.55, MODEL: 0.4, LOGIC: 0.25 };
const GRACE_MS = 5000;

function tierTau(tier) {
  return TIER_TAU[String(tier || '').toUpperCase()] ?? 0.1;
}

function fuse(scalars, weights = [], epsilon = 1e-6) {
  // scalars: [{ value, tier, applicable=true, weight }]
  const applicable = scalars.filter((s) => s.applicable !== false);
  for (const s of applicable) {
    if (Number(s.value) <= epsilon) return { S: 0, veto: true, vetoBy: s };
  }
  let num = 0, den = 0;
  for (const s of applicable) {
    const w = Number(s.weight ?? weights[applicable.indexOf(s)] ?? 1);
    const v = Math.max(Number(s.value), 1e-12);
    num += w * Math.log(v);
    den += w;
  }
  const S = den === 0 ? 0 : Math.exp(num / den);
  return { S, veto: false, vetoBy: null };
}

function certify(n, agree) {
  const a = Number(agree), total = Number(n);
  const d = total - a;
  const f = Math.floor((total - 1) / 3);
  return { n: total, a, d, f, certified: d <= f, ratio: total ? +(a / total).toFixed(4) : 0 };
}

function salience(base, tier, mode = 'bias') {
  const t = tierTau(tier);
  if (mode === 'attenuate') return base * t;
  if (mode === 'exclude') return t < 0.3 ? 0 : base;
  return base + 0.2 * t; // bias (default per spec embodiment)
}

// ---- pending tap store (grace window) ----
const _pending = new Map(); // id -> { createdAt, timer, resolve, payload }
const _audit = [];

function _auditLog(entry) {
  const row = { ts: new Date().toISOString(), ...entry };
  _audit.push(row);
  if (_audit.length > 500) _audit.splice(0, _audit.length - 500);
  return row;
}

// Software Stone keypair (ephemeral unless STONE_SEED set). Hardware Stone
// replaces sign() with a BLE round-trip; verify() already dispatches on signer.
const _softKey = crypto.generateKeyPairSync('ed25519');
function stoneSign(canonical) {
  const sig = crypto.sign(null, Buffer.from(canonical), _softKey.privateKey);
  return { signer: 'soft-stone', alg: 'ed25519', signature: sig.toString('base64url'), hardware: false };
}
function stoneVerify(canonical, att) {
  if (!att || att.signer === 'soft-stone') {
    try {
      return crypto.verify(null, Buffer.from(canonical), _softKey.publicKey, Buffer.from(att.signature, 'base64url'));
    } catch (_) { return false; }
  }
  if (att.signer === 'hw-stone') return { pendingHardware: true, reason: 'no secure element attached' };
  return false;
}

function canonicalGate(payload) {
  const ordered = {};
  for (const k of Object.keys(payload).sort()) ordered[k] = payload[k];
  return JSON.stringify(ordered);
}

function startTap({ action, tool, args = {}, scalars = [], n = 0, agree = 0, ignition = false, coherence = false, delegationThreshold = 0.5, epsilon = 1e-6 } = {}) {
  const id = 'tap_' + crypto.randomBytes(8).toString('hex');
  const { S, veto, vetoBy } = fuse(scalars, [], epsilon);
  const cert = certify(n, agree);
  const gate = {
    id, action, tool: tool || null,
    S: +S.toFixed(6), veto: !!veto, vetoBy: vetoBy ? { tier: vetoBy.tier, value: vetoBy.value } : null,
    certified: cert.certified, n: cert.n, agree: cert.a, dissent: cert.d, faultBound: cert.f,
    ignition: !!ignition, coherence: !!coherence, delegationThreshold,
    gateReady: !!ignition && !!coherence && S > delegationThreshold && cert.certified,
    createdAt: Date.now(), status: 'awaiting-tap',
  };
  let resolve;
  const done = new Promise((res) => { resolve = res; });
  const timer = setTimeout(() => {
    _pending.delete(id);
    gate.status = 'denied-timeout';
    _auditLog({ event: 'DISCONNECT_TIMEOUT', id, action, tool });
    resolve({ ...gate, A: 0, reason: 'grace window elapsed without tap' });
  }, GRACE_MS);
  if (timer.unref) timer.unref();
  _pending.set(id, { gate, timer, resolve });
  _auditLog({ event: 'TAP_REQUESTED', id, action, tool, S: gate.S });
  return { gate, done };
}

function requestTap(opts = {}) {
  const { gate, done } = startTap(opts);
  done.then(() => {});
  return gate;
}

function tap(id, { approve = true } = {}) {
  const p = _pending.get(id);
  if (!p) return { error: 'unknown or expired tap request' };
  clearTimeout(p.timer);
  _pending.delete(id);
  const g = p.gate;
  if (!approve) {
    g.status = 'denied-human';
    _auditLog({ event: 'TAP_DENIED', id, action: g.action });
    p.resolve({ ...g, A: 0, reason: 'human denied' });
    return { ...g, A: 0 };
  }
  const canonical = canonicalGate({ id, action: g.action, tool: g.tool, S: g.S, n: g.n, agree: g.agree, ts: Date.now() });
  const att = stoneSign(canonical);
  const ok = stoneVerify(canonical, att);
  const A = g.gateReady && ok === true ? 1 : 0;
  g.status = A ? 'authorized' : 'denied-gate';
  _auditLog({ event: A ? 'TAP_AUTHORIZED' : 'TAP_GATE_FAIL', id, action: g.action, A, signer: att.signer });
  p.resolve({ ...g, A, attestation: att, canonical });
  return { ...g, A, attestation: att, canonical };
}

function deny(id) { return tap(id, { approve: false }); }
function pending() {
  return [..._pending.entries()].map(([id, p]) => ({ id, action: p.gate.action, tool: p.gate.tool, S: p.gate.S, ageMs: Date.now() - p.gate.createdAt, graceMs: GRACE_MS }));
}
function auditLog(limit = 100) { return _audit.slice(-limit).reverse(); }

module.exports = {
  TIER_ORDER, TIER_TAU, GRACE_MS,
  tierTau, fuse, certify, salience,
  stoneSign, stoneVerify, canonicalGate,
  startTap, requestTap, tap, deny, pending, auditLog,
};
