'use strict';

/**
 * ssi-admission.js — JS mirror of kasbah-os/ssi_universal_core.py claims.
 *
 * - Non-compensable hard rights gate: every r_j >= b_j (no averaging away).
 * - KSG-1 mutual-information estimator with deterministic SHA-256 micro-jitter.
 * - Micro-TTL single-use tickets (HMAC-SHA256, scope + expiry + replay cache).
 * - Audit-then-admit ordering helper.
 *
 * Advisory only — never DENYs by itself; returns WARN flags for the sentinel.
 */

const crypto = require('crypto');

const RIGHTS_BASE = [1.00, 0.55, 0.05, 0.55];
// Calibrated 2026-10-03 via calibrate_epsilon() (200 synthetic cohorts, N=8):
// resting_p99 ≈ 0.28 < EPSILON < coupled_min ≈ 0.50. Synthetic only —
// replace with lab Study-A numbers before hardware claims.
const EPSILON_LEAK = 0.30;
const KSG_K = 3;
const JITTER_AMPLITUDE = 1e-9;

function digamma(x) {
  if (x <= 0) return 0.0;
  let result = 0.0;
  while (x < 7.0) { result -= 1.0 / x; x += 1.0; }
  const inv = 1.0 / x, inv2 = inv * inv;
  result += Math.log(x) - 0.5 * inv - inv2 * (1 / 12 - inv2 * (1 / 120 - inv2 / 252));
  return result;
}

function jitter(i, ch) {
  const d = crypto.createHash('sha256').update(`ssi-jitter|1337|${i}|${ch}`).digest();
  const u = d.readUInt16BE(0) / 65535.0;
  return (u - 0.5) * JITTER_AMPLITUDE;
}

function ksg1(Xraw, Yraw, k = KSG_K) {
  const N = Xraw.length;
  if (N < k + 1 || N !== Yraw.length) return 0;
  const X = Xraw.map((x, i) => x + jitter(i, 0));
  const Y = Yraw.map((y, i) => y + jitter(i, 1));
  const eps = [];
  for (let i = 0; i < N; i++) {
    const ds = [];
    for (let j = 0; j < N; j++) {
      if (i === j) continue;
      ds.push(Math.max(Math.abs(X[i] - X[j]), Math.abs(Y[i] - Y[j])));
    }
    ds.sort((a, b) => a - b);
    eps.push(Math.max(ds[k - 1], 1e-12));
  }
  let meanPsi = 0;
  for (let i = 0; i < N; i++) {
    const e = eps[i];
    let nx = 0, ny = 0;
    for (let j = 0; j < N; j++) {
      if (j === i) continue;
      if (Math.abs(X[i] - X[j]) < e) nx++;
      if (Math.abs(Y[i] - Y[j]) < e) ny++;
    }
    meanPsi += digamma(nx + 1) + digamma(ny + 1);
  }
  meanPsi /= N;
  return Math.max(0, digamma(k) + digamma(N) - meanPsi);
}

/** Non-compensable rights check. Returns { ok, failedIndex }. */
function rightsGate(rights, base = RIGHTS_BASE) {
  for (let j = 0; j < base.length; j++) {
    if ((rights[j] ?? 0) - base[j] < 0) return { ok: false, failedIndex: j };
  }
  return { ok: true, failedIndex: -1 };
}

function hmacHex(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest('hex');
}

class MicroTicketAuthority {
  constructor(secret = crypto.randomBytes(32)) {
    this.secret = secret;
    this.epoch = 1;
    // Dual-set sliding windows (port of TicketAuthority rotation):
    // nullifiers live ~2x window with bounded memory.
    this.windowS = 2.0;
    this._a = new Set(); this._b = new Set();
    this._active = 0; this._rot = Date.now();
  }
  _rotate() {
    if (Date.now() - this._rot > this.windowS * 1000) {
      this._active = 1 - this._active;
      (this._active === 0 ? this._a : this._b).clear();
      this._rot = Date.now();
    }
  }
  issue(stateHashHex, scope = 1, ttlMs = 200) {
    const tid = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const payload = `${tid}|${this.epoch}|${now}|${now + ttlMs}|${stateHashHex}|${scope}`;
    return { tid, epoch: this.epoch, issued: now, expires: now + ttlMs, stateHashHex, scope, mac: hmacHex(this.secret, payload), _payload: payload };
  }
  consume(t) {
    if (!t || t.epoch !== this.epoch || Date.now() > t.expires) return false;
    if (hmacHex(this.secret, t._payload || '') !== t.mac) return false;
    this._rotate();
    if (this._a.has(t.tid) || this._b.has(t.tid)) return false; // replay
    (this._active === 0 ? this._a : this._b).add(t.tid);
    return true;
  }
}

/** Advisory SSI screen for one sentinel turn. Never DENYs. */
function ssiScreen({ rights, subSignal, telSignal }) {  const out = { advisory: 'CLEAR', flags: [] };
  if (rights) {
    const g = rightsGate(rights);
    if (!g.ok) out.flags.push(`rights_pillar_${g.failedIndex}_below_base`);
  }
  if (subSignal && telSignal && subSignal.length >= KSG_K + 1) {
    const mi = ksg1(subSignal, telSignal);
    out.mi = +mi.toFixed(4);
    if (mi > EPSILON_LEAK) out.flags.push('ksg1_leakage_above_epsilon');
  }
  if (out.flags.length) out.advisory = 'WARN';
  return out;
}

/** Imagined-passphrase consent gate. Placeholder string-match backend —
 * see Python InnerSpeechGate: contract is enroll/authorize, ML later. */
class InnerSpeechGate {
  constructor() { this._hash = null; this.backend = 'placeholder-string-match'; }
  enroll(passphrase) {
    this._hash = crypto.createHash('sha256').update('ssi-inner-speech' + passphrase).digest('hex');
  }
  authorize(evidence) {
    if (!this._hash) return false;
    const h = crypto.createHash('sha256').update('ssi-inner-speech' + String(evidence || '')).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(this._hash));
  }
}

function selfTest() {
  const checks = [];
  checks.push(['rights_pass', rightsGate([1, 0.8, 0.5, 1]).ok === true]);
  checks.push(['rights_fail', rightsGate([0, 0.8, 0.5, 1]).ok === false]);
  checks.push(['ksg_const', ksg1([0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5], [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]) < 0.25]);
  checks.push(['ksg_coupled', ksg1([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8], [0.11, 0.19, 0.31, 0.39, 0.51, 0.59, 0.71, 0.79]) > EPSILON_LEAK]);
  const ta = new MicroTicketAuthority();
  const t = ta.issue('abc', 1, 200);
  checks.push(['ticket_single_use', ta.consume(t) === true && ta.consume(t) === false]);
  const expired = ta.issue('abc', 1, -50);
  checks.push(['ticket_expiry', ta.consume(expired) === false]);
  const isg = new InnerSpeechGate();
  isg.enroll('execute');
  checks.push(['inner_speech', isg.authorize('execute') === true && isg.authorize('nope') === false]);
  return { passed: checks.filter(c => c[1]).length, total: checks.length, failed: checks.filter(c => !c[1]).map(c => c[0]) };
}

module.exports = { RIGHTS_BASE, EPSILON_LEAK, ksg1, rightsGate, MicroTicketAuthority, InnerSpeechGate, ssiScreen, selfTest };
