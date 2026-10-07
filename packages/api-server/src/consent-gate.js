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
let _dataDir = null;
const fs = require('fs');
const nodePath = require('path');

function init({ dataDir } = {}) {
  _dataDir = dataDir || null;
  if (_dataDir) { try { fs.mkdirSync(_dataDir, { recursive: true, mode: 0o700 }); } catch (_) {} }
}

function _auditLog(entry) {
  const row = { ts: new Date().toISOString(), ...entry };
  _audit.push(row);
  if (_audit.length > 500) _audit.splice(0, _audit.length - 500);
  if (_dataDir) {
    try { fs.appendFileSync(nodePath.join(_dataDir, 'consent-audit.jsonl'), JSON.stringify(row) + '\n', { mode: 0o600 }); } catch (_) {}
  }
  return row;
}

// ---- Consequence tiers: selective ignition (anti prompt-fatigue) ----
// READ: auto-allow, Stone stays dark. WRITE: tap required. DESTRUCTIVE /
// EXFIL: tap required + flagged high-consequence. Patterns, not ML.
const TIER_DESTRUCTIVE = [
  /\brm\s+-rf?\b/i, /\bsudo\b/i, /\bdd\b.*of=/i, /\bmkfs\b/i,
  /\bdrop\s+(table|database)\b/i, /\bdelete\s+from\b/i, /\btruncate\b/i,
  /\bformat\s+[a-z]:/i, /\bshutdown\b|\breboot\b|\bhalt\b/i,
  /git\s+push.*--force/i, /git\s+push.*\bmain\b/i, /\bterraform\s+(apply|destroy)\b/i,
];
const TIER_SENSITIVE_PATH = [
  /\.ssh\//i, /\.env\b/i, /\.aws\//i, /\.gnupg\//i, /id_rsa/i,
  /credential/i, /secret/i, /wallet/i, /\.key\b/i, /keychain/i, /\.p12\b/i,
];
const TIER_EXFIL_TOOL = new Set(['network_post', 'webhook', 'send_email', 'upload', 'transmit', 'publish', 'http_post', 'http_put', 'http_delete']);
const TIER_WRITE_TOOL = new Set(['file_write', 'shell_execute', 'shell', 'exec', 'bash', 'zsh', 'sh', 'write_file', 'delete_file', 'move_file', 'rm', 'rmdir', 'chmod', 'chown', 'db_mutate', 'db_write', 'git_push', 'deploy', 'send_email', 'pip_install', 'npm_install', 'cargo_run']);

function assess({ action = '', tool = '', args = {} } = {}) {
  const text = [action, tool, JSON.stringify(args || {})].join(' ');
  const reasons = [];
  for (const re of TIER_DESTRUCTIVE) {
    if (re.test(text)) { reasons.push('destructive pattern'); break; }
  }
  for (const re of TIER_SENSITIVE_PATH) {
    if (re.test(text)) { reasons.push('sensitive path'); break; }
  }
  const t = String(tool || '').toLowerCase();
  if (TIER_EXFIL_TOOL.has(t)) reasons.push('exfil-capable tool ' + t);
  if (reasons.length) return { tier: reasons[0] === 'destructive pattern' ? 'DESTRUCTIVE' : 'EXFIL', tapRequired: true, highConsequence: true, reasons };
  if (TIER_WRITE_TOOL.has(t)) return { tier: 'WRITE', tapRequired: true, highConsequence: false, reasons: ['write-capable tool ' + t] };
  return { tier: 'READ', tapRequired: false, highConsequence: false, reasons: ['read-only: Stone stays dark'] };
}

// Software Stone keypair: persistent per dataDir (or STONE_SEED), so
// signatures verify across restarts. Ephemeral only if neither exists.
// Hardware Stone replaces sign() with a BLE round-trip; verify() already
// dispatches on signer. Per-user isolation: stone key = HKDF(master, agentId).
const _softKeys = new Map(); // agentId -> KeyObject pair
function _masterKey() {
  if (process.env.STONE_SEED) {
    return crypto.createHash('sha256').update('kasbah-stone-seed:' + process.env.STONE_SEED).digest();
  }
  if (_dataDir) {
    const kf = nodePath.join(_dataDir, 'stone-master.key');
    try {
      if (fs.existsSync(kf)) return fs.readFileSync(kf);
    } catch (_) {}
    try {
      const raw = crypto.randomBytes(32);
      fs.writeFileSync(kf, raw, { mode: 0o600 });
      return raw;
    } catch (_) {}
  }
  return crypto.randomBytes(32); // ephemeral fallback
}
let _master = null;
function _agentKeys(agentId = 'anonymous') {
  const id = String(agentId || 'anonymous');
  if (_softKeys.has(id)) return _softKeys.get(id);
  // 1) disk-persisted per-agent key (survives restarts; 0600)
  if (_dataDir) {
    try {
      const kf = nodePath.join(_dataDir, 'stone-' + id.replace(/[^a-zA-Z0-9_-]/g, '_') + '.key.json');
      if (fs.existsSync(kf)) {
        const j = JSON.parse(fs.readFileSync(kf, 'utf8'));
        const rec = {
          publicKey: crypto.createPublicKey({ key: Buffer.from(j.public, 'base64'), format: 'der', type: 'spki' }),
          privateKey: crypto.createPrivateKey({ key: Buffer.from(j.private, 'base64'), format: 'der', type: 'pkcs8' }),
        };
        _softKeys.set(id, rec);
        return rec;
      }
    } catch (_) {}
  }
  if (!_master) _master = _masterKey();
  const seed = crypto.hkdfSync('sha256', _master, Buffer.from('kasbah-stone-v1:' + id), Buffer.from('ed25519'), 32);
  let pair;
  try {
    pair = crypto.generateKeyPairSync('ed25519', { seed });
    // Verify the seed was honored (Node may ignore it): re-derive check
    const pair2 = crypto.generateKeyPairSync('ed25519', { seed });
    const same = pair.publicKey.export({ format: 'der', type: 'spki' }).equals(
      pair2.publicKey.export({ format: 'der', type: 'spki' }));
    if (!same) throw new Error('seed ignored');
  } catch (_) {
    pair = crypto.generateKeyPairSync('ed25519'); // random; persist below
  }
  const rec = { publicKey: pair.publicKey, privateKey: pair.privateKey };
  if (_dataDir) {
    try {
      const kf = nodePath.join(_dataDir, 'stone-' + id.replace(/[^a-zA-Z0-9_-]/g, '_') + '.key.json');
      if (!fs.existsSync(kf)) {
        fs.writeFileSync(kf, JSON.stringify({
          public: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
          private: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
        }), { mode: 0o600 });
      }
    } catch (_) {}
  }
  _softKeys.set(id, rec);
  return rec;
}
function stoneIdFor(agentId = 'anonymous') {
  return crypto.createHash('sha256').update('kasbah-stone-v1:' + String(agentId || 'anonymous')).digest('hex').slice(0, 16);
}
function stoneSign(canonical, agentId = 'anonymous') {
  const k = _agentKeys(agentId);
  const sig = crypto.sign(null, Buffer.from(canonical), k.privateKey);
  return { signer: 'soft-stone', alg: 'ed25519', signature: sig.toString('base64url'), hardware: false, stoneId: stoneIdFor(agentId), agentId: String(agentId || 'anonymous') };
}
function stoneVerify(canonical, att, agentId = 'anonymous') {
  if (!att || att.signer === 'soft-stone') {
    try {
      // Cross-agent use rejected: signature must belong to the acting agent.
      if (att.agentId && att.agentId !== String(agentId || 'anonymous')) return false;
      const k = _agentKeys(att.agentId || agentId);
      return crypto.verify(null, Buffer.from(canonical), k.publicKey, Buffer.from(att.signature, 'base64url'));
    } catch (_) { return false; }
  }
  if (att.signer === 'hw-stone') return { pendingHardware: true, reason: 'no secure element attached' };
  return false;
}
// Kill-switch guard: a tap for agent A NEVER authorizes agent B or a
// global kill. Remote kill-switch commands are denied cross-agent.
const KILL_RE = /\b(kill\s+-9|pkill|killall|taskkill|deny[_\s-]?all|shutdown|reboot|halt|agent[_\s-]?kill|remote[_\s-]?kill|emergency[_\s-]?stop)\b/i;
function killSwitchGuard({ requestingAgent, targetAgent, action = '', tool = '' } = {}) {
  const text = [action, tool].join(' ');
  if (!KILL_RE.test(text)) return { ok: true };
  if (String(requestingAgent || '') !== String(targetAgent || '')) {
    return { ok: false, reason: 'cross-agent kill denied: tap is per-agent, remote kill-switch blocked' };
  }
  return { ok: true, needsLocalTap: true };
}

function auditHead() {
  if (!_audit.length) return 'GENESIS';
  return crypto.createHash('sha256').update(JSON.stringify(_audit[_audit.length - 1])).digest('hex').slice(0, 32);
}

function canonicalGate(payload) {
  const ordered = {};
  for (const k of Object.keys(payload).sort()) ordered[k] = payload[k];
  return JSON.stringify(ordered);
}

function startTap({ action, tool, args = {}, scalars = [], n = 0, agree = 0, ignition = false, coherence = false, delegationThreshold = 0.5, epsilon = 1e-6, agentId = 'anonymous', targetAgent = null } = {}) {
  const id = 'tap_' + crypto.randomBytes(8).toString('hex');
  const { S, veto, vetoBy } = fuse(scalars, [], epsilon);
  const cert = certify(n, agree);
  // Kill-switch guard at request time: cross-agent kill requests are
  // rejected before a tap is even minted — no tap, no replay surface.
  const ks = killSwitchGuard({ requestingAgent: agentId, targetAgent: targetAgent || agentId, action, tool });
  const tierInfo = assess({ action, tool, args });
  const gate = {
    id, action, tool: tool || null, agentId: String(agentId || 'anonymous'),
    targetAgent: String(targetAgent || agentId || 'anonymous'),
    stoneId: stoneIdFor(agentId),
    S: +S.toFixed(6), veto: !!veto, vetoBy: vetoBy ? { tier: vetoBy.tier, value: vetoBy.value } : null,
    certified: cert.certified, n: cert.n, agree: cert.a, dissent: cert.d, faultBound: cert.f,
    ignition: !!ignition, coherence: !!coherence, delegationThreshold,
    gateReady: !!ignition && !!coherence && S > delegationThreshold && cert.certified && ks.ok,
    killSwitch: !ks.ok || !!ks.needsLocalTap,
    tier: tierInfo.tier, tierReasons: tierInfo.reasons, tapRequired: tierInfo.tapRequired,
    createdAt: Date.now(), status: ks.ok ? 'awaiting-tap' : 'denied-killswitch',
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

function tap(id, { approve = true, agentId = null } = {}) {
  const p = _pending.get(id);
  if (!p) return { error: 'unknown or expired tap request' };
  const g = p.gate;
  // Agent binding: only the owning agent's tap counts. A tap presented
  // for another agent is rejected — this is the remote kill-switch block.
  const actor = String(agentId || g.agentId || 'anonymous');
  if (actor !== String(g.agentId || 'anonymous')) {
    _auditLog({ event: 'TAP_CROSS_AGENT_DENIED', id, action: g.action, actor, owner: g.agentId });
    return { ...g, A: 0, reason: 'cross-agent tap denied: remote kill-switch blocked' };
  }
  clearTimeout(p.timer);
  _pending.delete(id);
  if (!approve) {
    g.status = 'denied-human';
    _auditLog({ event: 'TAP_DENIED', id, action: g.action });
    p.resolve({ ...g, A: 0, reason: 'human denied' });
    return { ...g, A: 0 };
  }
  const ah = auditHead();
  const canonical = canonicalGate({ id, action: g.action, tool: g.tool, S: g.S, n: g.n, agree: g.agree, ah, ts: Date.now(), agentId: g.agentId, stoneId: g.stoneId });
  const att = stoneSign(canonical, g.agentId);
  const ok = stoneVerify(canonical, att, g.agentId);
  const A = g.gateReady && ok === true ? 1 : 0;
  g.status = A ? 'authorized' : 'denied-gate';
  // Tap elevates epistemic tier: MODEL (statistical guess) -> RULE (human warrant).
  g.tierElevation = A ? 'MODEL → RULE' : null;
  _auditLog({ event: A ? 'TAP_AUTHORIZED' : 'TAP_GATE_FAIL', id, action: g.action, A, signer: att.signer, ah, tierElevation: g.tierElevation });
  p.resolve({ ...g, A, attestation: att, canonical });
  return { ...g, A, attestation: att, canonical };
}

function deny(id, opts = {}) { return tap(id, { approve: false, ...opts }); }
// Revocation: drop an agent's in-memory keys + pending taps. Disk keys
// remain but are orphaned — a new session mints a new agentId/stoneId.
// Old signatures stay verifiable for audit; new taps require the new stone.
function revokeStone(agentId = 'anonymous') {
  const id = String(agentId || 'anonymous');
  let dropped = 0;
  for (const [tid, p] of _pending.entries()) {
    if (String(p.gate.agentId) === id) {
      clearTimeout(p.timer);
      _pending.delete(tid);
      dropped++;
      p.resolve({ ...p.gate, A: 0, status: 'denied-revoked', reason: 'stone revoked' });
    }
  }
  _softKeys.delete(id);
  _auditLog({ event: 'STONE_REVOKED', agentId: id, stoneId: stoneIdFor(id), droppedTaps: dropped });
  return { ok: true, agentId: id, stoneId: stoneIdFor(id), droppedTaps: dropped };
}
function stoneStatus(agentId = 'anonymous') {
  const id = String(agentId || 'anonymous');
  const aura = _aura.get(id) || { glow: 'idle', color: 'soft-white', since: Date.now() };
  return { agentId: id, stoneId: stoneIdFor(id), signer: 'soft-stone', hardware: false, pendingTaps: [..._pending.values()].filter((p) => String(p.gate.agentId) === id).length, aura, capabilities: STONE_FUNCTIONS };
}
// ---- Aurora: ambient functions beyond tap ----
// The Stone is an ambient presence device, not a button. Aura states drive
// the LED/haptic language on hardware; on software they are API-visible
// state the desktop renders. No aura function ever weakens the tap
// requirement for PHYSICAL_TOUCH — gestures only ever approve READ/SOFT,
// never destructive/exfil/kill.
const STONE_FUNCTIONS = [
  'tap', 'double-tap', 'hold-to-deny', 'presence', 'aura-glow',
  'find-my-stone', 'duress', 'snooze-soft', 'tap-history',
];
const _aura = new Map(); // agentId -> { glow, color, since }
const _presence = new Map(); // agentId -> { near, rssi, updatedAt }
const _snooze = new Map(); // agentId -> untilMs (SOFT-tier batch approve)
function setAura(agentId, glow, color) {
  const id = String(agentId || 'anonymous');
  const valid = ['idle', 'awaiting-tap', 'authorized', 'denied', 'duress-silent', 'finding', 'low-batt'];
  const g = valid.includes(glow) ? glow : 'idle';
  _aura.set(id, { glow: g, color: color || _auraColor(g), since: Date.now() });
  _auditLog({ event: 'AURA', agentId: id, glow: g });
  return _aura.get(id);
}
function _auraColor(glow) {
  return { idle: 'soft-white', 'awaiting-tap': 'pulse-amber', authorized: 'flash-green', denied: 'red', 'duress-silent': 'dark', finding: 'pulse-blue', 'low-batt': 'slow-amber' }[glow] || 'soft-white';
}
function auraFor(agentId) {
  // Derived aura: pending tap overrides everything except duress.
  const id = String(agentId || 'anonymous');
  const cur = _aura.get(id);
  if (cur && (cur.glow === 'duress-silent' || cur.glow === 'finding') && Date.now() - cur.since < 60000) return cur;
  const pend = [..._pending.values()].some((p) => String(p.gate.agentId) === id);
  if (pend) return { glow: 'awaiting-tap', color: 'pulse-amber', since: Date.now() };
  return cur || { glow: 'idle', color: 'soft-white', since: Date.now() };
}
// Gestures. double-tap: approve oldest pending READ/SOFT tap only (never
// destructive/exfil/kill). hold: deny all pending. duress (tap-hold-tap):
// silently deny + raise silent alarm. find: buzz aura for 60 s.
function gesture(agentId = 'anonymous', name = '', opts = {}) {
  const id = String(agentId || 'anonymous');
  const mine = [..._pending.entries()].filter(([, p]) => String(p.gate.agentId) === id);
  if (name === 'double-tap') {
    const soft = mine.find(([, p]) => !p.gate.killSwitch && !p.gate.highConsequence && (p.gate.tier !== 'DESTRUCTIVE' && p.gate.tier !== 'EXFIL' && !/destructive|exfil/i.test((p.gate.tierReasons || []).join(' '))));
    if (!soft) return { ok: false, reason: 'no soft tap pending (gestures never approve destructive/exfil/kill)' };
    return { ok: true, approved: tap(soft[0], { agentId: id, approve: true }) };
  }
  if (name === 'hold-to-deny') {
    let n = 0;
    for (const [tid] of mine) { tap(tid, { agentId: id, approve: false }); n++; }
    setAura(id, 'denied', 'red');
    return { ok: true, denied: n };
  }
  if (name === 'duress') {
    for (const [tid] of mine) { tap(tid, { agentId: id, approve: false }); }
    setAura(id, 'duress-silent', 'dark');
    _auditLog({ event: 'DURESS', agentId: id, stoneId: stoneIdFor(id), note: 'silent alarm: all pending denied' });
    return { ok: true, silent: true };
  }
  if (name === 'find-my-stone') {
    setAura(id, 'finding', 'pulse-blue');
    return { ok: true, aura: _aura.get(id) };
  }
  if (name === 'snooze-soft') {
    // Batch-quiet SOFT-tier requests for 10 min. READ unaffected (already dark).
    // Never applies to PHYSICAL_TOUCH/dead destructive/kill.
    _snooze.set(id, Date.now() + 10 * 60 * 1000);
    _auditLog({ event: 'SNOOZE_SOFT', agentId: id, until: new Date(Date.now() + 10 * 60 * 1000).toISOString() });
    return { ok: true, untilMs: _snooze.get(id) };
  }
  return { ok: false, reason: 'unknown gesture' };
}
function snoozed(agentId) {
  const until = _snooze.get(String(agentId || 'anonymous')) || 0;
  if (Date.now() > until) { _snooze.delete(String(agentId || 'anonymous')); return false; }
  return true;
}
function presence(agentId = 'anonymous', body = {}) {
  const id = String(agentId || 'anonymous');
  _presence.set(id, { near: !!body.near, rssi: Number(body.rssi) || null, updatedAt: Date.now() });
  return _presence.get(id);
}
function presenceFor(agentId) { return _presence.get(String(agentId || 'anonymous')) || { near: false, rssi: null, updatedAt: 0 }; }
function tapHistory(agentId = 'anonymous', limit = 20) {
  const id = String(agentId || 'anonymous');
  return _audit.filter((e) => e.agentId === id || e.actor === id).slice(-limit).reverse();
}
function pending() {
  return [..._pending.entries()].map(([id, p]) => ({ id, action: p.gate.action, tool: p.gate.tool, S: p.gate.S, ageMs: Date.now() - p.gate.createdAt, graceMs: GRACE_MS }));
}
function auditLog(limit = 100) { return _audit.slice(-limit).reverse(); }

module.exports = {
  TIER_ORDER, TIER_TAU, GRACE_MS,
  tierTau, fuse, certify, salience, assess, init,
  stoneSign, stoneVerify, canonicalGate, stoneIdFor, killSwitchGuard,
  startTap, requestTap, tap, deny, pending, auditLog, revokeStone, stoneStatus,
  setAura, auraFor, gesture, snoozed, presence, presenceFor, tapHistory, STONE_FUNCTIONS,
};
