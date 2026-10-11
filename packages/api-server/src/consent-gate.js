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
  _approvers.clear(); _approversLoaded = false; _registryCorrupt = false; // reload the registry from the new location
  _lockdownLoaded = false; _lockdown = false;
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
  /:\(\)\s*\{\s*:\|:&\s*\};:/, /\bchmod\s+777\b/i, /\bkubectl\s+delete\b/i,
  /\baws\s+s3\s+(rm|rb)\b/i,
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
function _keyFileName(id) {
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, '_');
  // Distinct ids must never collapse onto one file. Ids that needed no
  // rewriting keep their original name so existing keys still load.
  return 'stone-' + (safe === id ? safe : safe.slice(0, 40) + '-' + crypto.createHash('sha256').update(id).digest('hex').slice(0, 16)) + '.key.json';
}
function _agentKeys(agentId = 'anonymous') {
  const id = String(agentId || 'anonymous');
  if (_softKeys.has(id)) return _softKeys.get(id);
  // 1) disk-persisted per-agent key (survives restarts; 0600)
  if (_dataDir) {
    try {
      const kf = nodePath.join(_dataDir, _keyFileName(id));
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
      const kf = nodePath.join(_dataDir, _keyFileName(id));
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
// ═════════════════════════════════════════════════════════════════════════════
// Approver registry — binds approval to a key the requesting agent cannot use.
//
// Before this existed, tap() signed with the software Stone key inside this
// process, so ANY caller of the tap route (including the agent that asked)
// could approve its own request, and a 'hw-stone' attestation was accepted
// without its signature being checked. Now:
//
//   • An approver is a provisioned Ed25519 public key: kind 'hw-stone' (a
//     device with a secure element) or 'desktop' (the desktop app's main
//     process, which signs only after a native OS confirmation dialog).
//   • Once an approver exists for an agent (or for '*', every agent), an
//     approval REQUIRES an attestation: a signature over the request's exact
//     challenge string plus a strictly increasing counter.
//   • Provisioning is trust-on-first-use. Adding or replacing a key afterwards
//     requires a signature from a key that is already registered.
//   • With KASBAH_REQUIRE_ATTESTED_TAP=1 and no approver, approvals fail closed.
//
// The legacy in-process signature remains only while no approver is
// provisioned, and is reported as selfSigned so nothing mistakes it for a
// human-bound approval.
// ═════════════════════════════════════════════════════════════════════════════
const APPROVER_KINDS = new Set(['hw-stone', 'desktop']);
const MAX_BAD_ATTESTATIONS = 5;
const DESKTOP_GRACE_MS = Math.min(Math.max(Number(process.env.KASBAH_TAP_GRACE_MS) || 60000, GRACE_MS), 300000);
const _approvers = new Map(); // scope ('*' | agentId) -> [{ keyId, kind, pubkey (b64 spki der), counter, addedAt }]
let _approversLoaded = false;

function _approverFile() { return _dataDir ? nodePath.join(_dataDir, 'consent-approvers.json') : null; }
function _loadApprovers() {
  if (_approversLoaded) return;
  _approversLoaded = true;
  const f = _approverFile();
  if (!f) return;
  try {
    const j = JSON.parse(fs.readFileSync(f, 'utf8'));
    for (const [scope, list] of Object.entries(j.approvers || {})) {
      if (Array.isArray(list)) _approvers.set(scope, list.filter((a) => a && a.keyId && a.pubkey && APPROVER_KINDS.has(a.kind)));
    }
  } catch (e) {
    // A registry that exists but cannot be read must not silently reopen the
    // legacy self-signed path: fail closed until it is repaired.
    if (e.code !== 'ENOENT') { _registryCorrupt = true; _auditLog({ event: 'APPROVER_REGISTRY_UNREADABLE', error: e.message }); }
  }
}
let _registryCorrupt = false;
function _saveApprovers() {
  const f = _approverFile();
  if (!f) return;
  const body = JSON.stringify({ v: 1, approvers: Object.fromEntries(_approvers) }, null, 2);
  const tmp = f + '.tmp';
  fs.writeFileSync(tmp, body, { mode: 0o600 });
  fs.renameSync(tmp, f);
}
function _pubFromB64(b64) {
  const key = crypto.createPublicKey({ key: Buffer.from(String(b64), 'base64'), format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('approver key must be Ed25519');
  return key;
}
function _keyIdFor(b64) { return crypto.createHash('sha256').update(Buffer.from(String(b64), 'base64')).digest('hex').slice(0, 16); }
function _approversFor(agentId) {
  _loadApprovers();
  const id = String(agentId || 'anonymous');
  return [...(_approvers.get(id) || []), ...(_approvers.get('*') || [])];
}
function approverRequired(agentId) {
  _loadApprovers();
  return _registryCorrupt || process.env.KASBAH_REQUIRE_ATTESTED_TAP === '1' || _approversFor(agentId).length > 0;
}
function approverStatus(agentId) {
  const list = _approversFor(agentId);
  return {
    required: approverRequired(agentId),
    registryUnreadable: _registryCorrupt,
    approvers: list.map((a) => ({ keyId: a.keyId, kind: a.kind, addedAt: a.addedAt })),
    graceMs: graceFor(agentId),
  };
}
function graceFor(agentId) {
  return _approversFor(agentId).some((a) => a.kind === 'desktop') ? DESKTOP_GRACE_MS : GRACE_MS;
}
/** Canonical string a current approver signs to authorise adding a key. */
function provisionCanonical({ scope, pubkey, kind, ts }) {
  return canonicalGate({ op: 'provision-approver', scope: String(scope), pubkey: String(pubkey), kind: String(kind), ts: Number(ts) });
}
function provisionApprover({ agentId = '*', pubkey, kind, proof } = {}) {
  _loadApprovers();
  if (_registryCorrupt) return { ok: false, reason: 'approver registry unreadable; repair or remove it first' };
  const scope = String(agentId || '*');
  if (!APPROVER_KINDS.has(kind)) return { ok: false, reason: 'kind must be hw-stone or desktop' };
  if (!pubkey || typeof pubkey !== 'string' || pubkey.length > 512) return { ok: false, reason: 'pubkey (base64 SPKI DER) required' };
  try { _pubFromB64(pubkey); } catch (e) { return { ok: false, reason: 'invalid pubkey: ' + e.message }; }
  const keyId = _keyIdFor(pubkey);
  const existing = [...(_approvers.get(scope) || []), ...(scope === '*' ? [] : (_approvers.get('*') || []))];
  if ((_approvers.get(scope) || []).some((a) => a.keyId === keyId)) return { ok: true, keyId, scope, kind, alreadyRegistered: true };
  // Anything already trusted for this scope (or globally) must authorise the
  // addition. When scope is '*', every existing approver anywhere counts, so a
  // global key cannot be slipped in over per-agent ones.
  const mustAuthorise = scope === '*' ? [..._approvers.values()].flat() : existing;
  if (mustAuthorise.length) {
    if (!proof || !proof.signature || !proof.keyId || typeof proof.ts !== 'number') {
      _auditLog({ event: 'APPROVER_PROVISION_REFUSED', scope, kind, keyId, why: 'no proof from an existing approver' });
      return { ok: false, reason: 'an approver already exists: adding a key needs a signature from a registered approver' };
    }
    if (Math.abs(Date.now() - proof.ts) > 120000) return { ok: false, reason: 'provisioning proof expired' };
    const signer = mustAuthorise.find((a) => a.keyId === proof.keyId);
    let good = false;
    if (signer) {
      try { good = crypto.verify(null, Buffer.from(provisionCanonical({ scope, pubkey, kind, ts: proof.ts })), _pubFromB64(signer.pubkey), Buffer.from(String(proof.signature), 'base64url')); } catch (_) { good = false; }
    }
    if (!good) {
      _auditLog({ event: 'APPROVER_PROVISION_REFUSED', scope, kind, keyId, why: 'bad proof' });
      return { ok: false, reason: 'provisioning proof does not verify against a registered approver' };
    }
  }
  const list = _approvers.get(scope) || [];
  list.push({ keyId, kind, pubkey, counter: -1, addedAt: new Date().toISOString() });
  _approvers.set(scope, list);
  try { _saveApprovers(); } catch (e) {
    list.pop(); if (!list.length) _approvers.delete(scope);
    return { ok: false, reason: 'could not persist approver registry: ' + e.message };
  }
  _auditLog({ event: 'APPROVER_PROVISIONED', scope, kind, keyId, firstUse: mustAuthorise.length === 0 });
  return { ok: true, keyId, scope, kind, firstUse: mustAuthorise.length === 0 };
}
/** What an approver signs: the exact challenge, then the counter. */
function attestationMessage(challenge, counter) { return String(challenge) + '|' + String(counter); }
/**
 * Verify an external attestation for a pending request. Returns
 * { ok, reason?, approver? }. Never throws. On success the approver's counter
 * is advanced and persisted BEFORE returning, so a crash cannot reopen a replay.
 */
function verifyAttestation(gate, challenge, att) {
  if (!att || typeof att !== 'object') return { ok: false, reason: 'ATTESTATION_REQUIRED' };
  if (!APPROVER_KINDS.has(att.signer)) return { ok: false, reason: 'UNKNOWN_SIGNER' };
  if (typeof att.signature !== 'string' || att.signature.length > 256) return { ok: false, reason: 'BAD_SIGNATURE_FORMAT' };
  if (!Number.isSafeInteger(att.counter) || att.counter < 0) return { ok: false, reason: 'COUNTER_REQUIRED' };
  if (att.agentId != null && String(att.agentId) !== String(gate.agentId)) return { ok: false, reason: 'CROSS_AGENT' };
  const candidates = _approversFor(gate.agentId).filter((a) => a.kind === att.signer && (!att.keyId || a.keyId === att.keyId));
  if (!candidates.length) return { ok: false, reason: 'NO_MATCHING_APPROVER' };
  const msg = Buffer.from(attestationMessage(challenge, att.counter));
  let sig;
  try { sig = Buffer.from(att.signature, 'base64url'); } catch (_) { return { ok: false, reason: 'BAD_SIGNATURE_FORMAT' }; }
  if (sig.length !== 64) return { ok: false, reason: 'BAD_SIGNATURE_FORMAT' };
  for (const a of candidates) {
    let good = false;
    try { good = crypto.verify(null, msg, _pubFromB64(a.pubkey), sig); } catch (_) { good = false; }
    if (!good) continue;
    if (att.counter <= a.counter) return { ok: false, reason: 'STALE_COUNTER' };
    const prev = a.counter;
    a.counter = att.counter;
    try { _saveApprovers(); } catch (e) { a.counter = prev; return { ok: false, reason: 'COUNTER_NOT_PERSISTED' }; }
    return { ok: true, approver: { keyId: a.keyId, kind: a.kind } };
  }
  return { ok: false, reason: 'SIGNATURE_MISMATCH' };
}
/** Test hook: forget in-memory registry state so the next call reloads from disk. */
function _resetApproversForTest() { _approvers.clear(); _approversLoaded = false; _registryCorrupt = false; }

function stoneVerify(canonical, att, agentId = 'anonymous') {
  if (!att || att.signer === 'soft-stone') {
    try {
      // Cross-agent use rejected: signature must belong to the acting agent.
      if (att.agentId && att.agentId !== String(agentId || 'anonymous')) return false;
      const k = _agentKeys(att.agentId || agentId);
      return crypto.verify(null, Buffer.from(canonical), k.publicKey, Buffer.from(att.signature, 'base64url'));
    } catch (_) { return false; }
  }
  // External signers are verified against the provisioned registry by
  // verifyAttestation() inside tap(); they are never accepted here, so no
  // caller can treat a bare { signer: 'hw-stone' } object as proof.
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

function startTap({ action, tool, args = {}, scalars = [], n = 0, agree = 0, ignition = false, coherence = false, delegationThreshold = 0.5, epsilon = 1e-6, agentId = 'anonymous', targetAgent = null, mode = 'evidence', advice = '' } = {}) {
  const id = 'tap_' + crypto.randomBytes(8).toString('hex');
  const { S, veto, vetoBy } = fuse(scalars, [], epsilon);
  const cert = certify(n, agree);
  // Kill-switch guard at request time: cross-agent kill requests are
  // rejected before a tap is even minted — no tap, no replay surface.
  const ks = killSwitchGuard({ requestingAgent: agentId, targetAgent: targetAgent || agentId, action, tool });
  const tierInfo = assess({ action, tool, args });
  // Two ways a request can become approvable:
  //   'evidence' — the original conjunctive gate: ignition ∧ coherence ∧ S > θ ∧ certified.
  //   'human'    — a plain "ask the person" request with no machine evidence. The
  //                human is the authority, so it is only approvable when a
  //                registered approver exists; it can never fall back to the
  //                in-process signature. Kill-switch and lockdown still veto.
  const humanMode = mode === 'human';
  const needsApprover = approverRequired(agentId);
  const gate = {
    id, action, tool: tool || null, agentId: String(agentId || 'anonymous'),
    targetAgent: String(targetAgent || agentId || 'anonymous'),
    stoneId: stoneIdFor(agentId),
    S: +S.toFixed(6), veto: !!veto, vetoBy: vetoBy ? { tier: vetoBy.tier, value: vetoBy.value } : null,
    certified: cert.certified, n: cert.n, agree: cert.a, dissent: cert.d, faultBound: cert.f,
    ignition: !!ignition, coherence: !!coherence, delegationThreshold,
    mode: humanMode ? 'human' : 'evidence',
    gateReady: humanMode
      ? (ks.ok && needsApprover && !_registryCorrupt)
      : (!!ignition && !!coherence && S > delegationThreshold && cert.certified && ks.ok),
    notReadyReason: humanMode && ks.ok && !needsApprover ? 'no approver is registered; open Kasbah or pair a device' : null,
    advice: String(advice || '').slice(0, 160),
    killSwitch: !ks.ok || !!ks.needsLocalTap,
    tier: tierInfo.tier, tierReasons: tierInfo.reasons, tapRequired: tierInfo.tapRequired,
    createdAt: Date.now(), status: ks.ok ? 'awaiting-tap' : 'denied-killswitch',
  };
  const graceMs = graceFor(gate.agentId);
  gate.expiresAt = gate.createdAt + graceMs;
  gate.graceMs = graceMs;
  gate.approverRequired = needsApprover;
  // The challenge is fixed now, at request time, and is the ONLY thing an
  // approver signs. It carries a fresh nonce and a hash of the arguments, so a
  // signature for one request can never approve another, and what the human
  // is shown is what gets signed.
  const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
  gate.argsHash = crypto.createHash('sha256').update(argsStr).digest('hex');
  const challenge = canonicalGate({
    v: 2, id, nonce: crypto.randomBytes(16).toString('hex'), action: String(action || ''), tool: gate.tool,
    argsHash: gate.argsHash, agentId: gate.agentId, targetAgent: gate.targetAgent, stoneId: gate.stoneId,
    tier: gate.tier, S: gate.S, n: gate.n, agree: gate.agree, createdAt: gate.createdAt, expiresAt: gate.expiresAt,
    mode: gate.mode, advice: gate.advice,
  });
  let resolve;
  const done = new Promise((res) => { resolve = res; });
  const timer = setTimeout(() => {
    _pending.delete(id);
    gate.status = 'denied-timeout';
    _auditLog({ event: 'DISCONNECT_TIMEOUT', id, action, tool, agentId: gate.agentId, stoneId: gate.stoneId });
    resolve({ ...gate, A: 0, reason: 'grace window elapsed without tap' });
  }, graceMs);
  if (timer.unref) timer.unref();
  _pending.set(id, { gate, timer, resolve, challenge, badAttestations: 0, argsPreview: argsStr.slice(0, 400) });
  _auditLog({ event: 'TAP_REQUESTED', id, action, tool, S: gate.S, agentId: gate.agentId, stoneId: gate.stoneId, tier: gate.tier, approverRequired: gate.approverRequired });
  return { gate: { ...gate, challenge }, done };
}

function requestTap(opts = {}) {
  const { gate, done } = startTap(opts);
  done.then(() => {});
  return gate;
}

function tap(id, { approve = true, agentId = null, attestation = null } = {}) {
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
  // Belt and braces: the timer normally removes an expired request, but never
  // rely on a timer alone for a security deadline.
  if (g.expiresAt && Date.now() > g.expiresAt) {
    clearTimeout(p.timer); _pending.delete(id);
    g.status = 'denied-timeout';
    _auditLog({ event: 'DISCONNECT_TIMEOUT', id, action: g.action, tool: g.tool, agentId: g.agentId, stoneId: g.stoneId });
    p.resolve({ ...g, A: 0, reason: 'grace window elapsed without tap' });
    return { error: 'unknown or expired tap request' };
  }
  if (!approve) {
    // Denying never needs a signature: it can only make things safer.
    clearTimeout(p.timer);
    _pending.delete(id);
    g.status = 'denied-human';
    _auditLog({ event: 'TAP_DENIED', id, action: g.action, agentId: g.agentId, stoneId: g.stoneId });
    p.resolve({ ...g, A: 0, reason: 'human denied' });
    return { ...g, A: 0 };
  }
  const ah = auditHead();
  let att, ok, approver = null, canonical;
  if (approverRequired(g.agentId)) {
    // Human-bound path: an external key must have signed this exact challenge.
    const v = verifyAttestation(g, p.challenge, attestation);
    if (!v.ok) {
      p.badAttestations += 1;
      _auditLog({ event: 'TAP_ATTESTATION_REJECTED', id, action: g.action, agentId: g.agentId, why: v.reason, attempt: p.badAttestations });
      if (p.badAttestations >= MAX_BAD_ATTESTATIONS) {
        clearTimeout(p.timer); _pending.delete(id);
        g.status = 'denied-attestation';
        p.resolve({ ...g, A: 0, reason: 'too many invalid attestations' });
        return { ...g, A: 0, reason: 'too many invalid attestations' };
      }
      // The request stays pending so the real approver can still answer.
      return { ...g, A: 0, status: 'awaiting-tap', reason: 'attestation rejected: ' + v.reason, attestationRequired: true };
    }
    canonical = p.challenge;
    approver = v.approver;
    att = { signer: attestation.signer, alg: 'ed25519', signature: attestation.signature, counter: attestation.counter, keyId: approver.keyId, hardware: attestation.signer === 'hw-stone', stoneId: g.stoneId, agentId: g.agentId };
    ok = true;
  } else {
    // Legacy path, only while no approver is provisioned: signed in-process,
    // so it proves the gate ran, NOT that a human approved. Labelled as such.
    canonical = canonicalGate({ id, action: g.action, tool: g.tool, S: g.S, n: g.n, agree: g.agree, ah, ts: Date.now(), agentId: g.agentId, stoneId: g.stoneId });
    att = { ...stoneSign(canonical, g.agentId), selfSigned: true };
    ok = stoneVerify(canonical, att, g.agentId);
  }
  clearTimeout(p.timer);
  _pending.delete(id);
  const A = g.gateReady && ok === true ? 1 : 0;
  g.status = A ? 'authorized' : 'denied-gate';
  g.humanBound = !!approver;
  // Tap elevates epistemic tier: MODEL (statistical guess) -> RULE (human warrant).
  g.tierElevation = A && approver ? 'MODEL → RULE' : null;
  // On authorize, mint the micro-TTL execution ticket bound to this action.
  const ticket = A ? issueTicket(g.agentId, g.tool || g.action, { action: g.action }) : null;
  _auditLog({ event: A ? 'TAP_AUTHORIZED' : 'TAP_GATE_FAIL', id, action: g.action, A, signer: att.signer, humanBound: g.humanBound, approverKeyId: approver ? approver.keyId : null, ah, tierElevation: g.tierElevation, ticket: ticket ? ticket.tid.slice(0, 12) : null, agentId: g.agentId, stoneId: g.stoneId });
  p.resolve({ ...g, A, attestation: att, canonical, ticket });
  return { ...g, A, attestation: att, canonical, ticket };
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
  const ap = approverStatus(id);
  return { agentId: id, stoneId: stoneIdFor(id), signer: ap.approvers.length ? ap.approvers.map((a) => a.kind).join('+') : 'soft-stone', hardware: ap.approvers.some((a) => a.kind === 'hw-stone'), approver: ap, pendingTaps: [..._pending.values()].filter((p) => String(p.gate.agentId) === id).length, aura, capabilities: STONE_FUNCTIONS };
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
  'wearable-pair', 'away-mode', 'surrounding-sense', 'private-relay',
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
    // A gesture carries no signature, so it can never stand in for a signed
    // approval once an approver is provisioned.
    if (approverRequired(id)) return { ok: false, reason: 'a signed approval is required; gestures can only deny' };
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
// ---- Lockdown (default-deny): enterprise kill-switch mode ----
// When on, every ESCALATE-tier request denies without minting a tap.
// READ/ZERO_TOUCH unaffected. Toggle is audit-logged with actor.
let _lockdown = false;
let _lockdownLoaded = false;
function _lockdownFile() { return _dataDir ? nodePath.join(_dataDir, 'consent-lockdown.json') : null; }
function _loadLockdown() {
  if (_lockdownLoaded) return;
  _lockdownLoaded = true;
  const f = _lockdownFile();
  if (!f) return;
  try { _lockdown = JSON.parse(fs.readFileSync(f, 'utf8')).lockdown === true; }
  catch (e) { if (e.code !== 'ENOENT') _lockdown = true; } // unreadable state fails closed
}
/** Canonical string an approver signs for a sensitive operation. */
function opCanonical(op, ts, counter) { return canonicalGate({ op: String(op), ts: Number(ts), counter: Number(counter) }); }
/** Verify a signed operation against ANY registered approver. Advances its counter. */
function verifyOpProof(op, proof) {
  _loadApprovers();
  if (!proof || typeof proof.signature !== 'string' || typeof proof.ts !== 'number' || !Number.isSafeInteger(proof.counter)) return { ok: false, reason: 'PROOF_REQUIRED' };
  if (Math.abs(Date.now() - proof.ts) > 120000) return { ok: false, reason: 'PROOF_EXPIRED' };
  let sig; try { sig = Buffer.from(proof.signature, 'base64url'); } catch (_) { return { ok: false, reason: 'BAD_SIGNATURE_FORMAT' }; }
  if (sig.length !== 64) return { ok: false, reason: 'BAD_SIGNATURE_FORMAT' };
  const msg = Buffer.from(opCanonical(op, proof.ts, proof.counter));
  for (const a of [..._approvers.values()].flat()) {
    if (proof.keyId && a.keyId !== proof.keyId) continue;
    let good = false;
    try { good = crypto.verify(null, msg, _pubFromB64(a.pubkey), sig); } catch (_) { good = false; }
    if (!good) continue;
    if (proof.counter <= a.counter) return { ok: false, reason: 'STALE_COUNTER' };
    const prev = a.counter; a.counter = proof.counter;
    try { _saveApprovers(); } catch (_) { a.counter = prev; return { ok: false, reason: 'COUNTER_NOT_PERSISTED' }; }
    return { ok: true, approver: { keyId: a.keyId, kind: a.kind } };
  }
  return { ok: false, reason: 'SIGNATURE_MISMATCH' };
}
/**
 * Turning lockdown ON is always allowed (it only makes things safer). Turning
 * it OFF is a privileged act: with approvers provisioned it needs a signed
 * proof; without any, the caller must pass { trusted: true } (the route sets
 * that only for an authenticated admin key). State survives restarts.
 */
function setLockdown(on, actor = 'unknown', { proof = null, trusted = false } = {}) {
  _loadLockdown(); _loadApprovers();
  const want = !!on;
  if (!want && _lockdown) {
    const anyApprover = [..._approvers.values()].flat().length > 0 || _registryCorrupt;
    if (anyApprover) {
      const v = verifyOpProof('lockdown-off', proof);
      if (!v.ok) { _auditLog({ event: 'LOCKDOWN_OFF_REFUSED', actor, why: v.reason }); return { ok: false, lockdown: true, reason: 'lifting lockdown needs a signed approval: ' + v.reason }; }
    } else if (!trusted) {
      _auditLog({ event: 'LOCKDOWN_OFF_REFUSED', actor, why: 'untrusted caller' });
      return { ok: false, lockdown: true, reason: 'lifting lockdown needs an authenticated admin key' };
    }
  }
  _lockdown = want;
  const f = _lockdownFile();
  if (f) {
    try { const tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify({ lockdown: _lockdown, at: new Date().toISOString(), actor: String(actor) }), { mode: 0o600 }); fs.renameSync(tmp, f); }
    catch (e) { if (!want) { _lockdown = true; return { ok: false, lockdown: true, reason: 'could not persist lockdown state: ' + e.message }; } }
  }
  _auditLog({ event: _lockdown ? 'LOCKDOWN_ON' : 'LOCKDOWN_OFF', actor });
  return { ok: true, lockdown: _lockdown };
}
function lockdown() { _loadLockdown(); return _lockdown; }
// Recent-tap check: was there a TAP_AUTHORIZED for this agent within windowMs?
function recentTap(agentId = 'anonymous', windowMs = 5000) {
  const id = String(agentId || 'anonymous');
  const now = Date.now();
  for (let i = _audit.length - 1; i >= 0; i--) {
    const e = _audit[i];
    if (e.event === 'TAP_AUTHORIZED' && (e.agentId === id || e.actor === id)) {
      const ts = new Date(e.ts).getTime();
      if (now - ts <= windowMs) return { ok: true, at: e.ts };
      return { ok: false };
    }
  }
  return { ok: false };
}
// Independent attestation verify: any third party posts { canonical,
// signature, pubkey } and learns valid/invalid without trusting the host.
function verifyIndependent({ canonical, signature, pubkey } = {}) {
  if (!canonical || !signature || !pubkey) return { valid: false, reason: 'canonical+signature+pubkey required' };
  try {
    const pub = crypto.createPublicKey({ key: Buffer.from(String(pubkey), 'base64'), format: 'der', type: 'spki' });
    const ok = crypto.verify(null, Buffer.from(String(canonical)), pub, Buffer.from(String(signature), 'base64url'));
    return { valid: !!ok, signatureOk: !!ok, counterOk: null, detail: ok ? 'signature verifies against supplied pubkey' : 'signature does not verify' };
  } catch (e) { return { valid: false, reason: e.message }; }
}
// ---- Micro-TTL single-use execution tickets (wow-plane semantics) ----
// A tap authorizes intent; the ticket authorizes one execution. Tickets are
// HMAC-bound to tool+args+timestamps, 300 ms TTL, single-use. Verify fails
// closed: REPLAY / EXPIRED / TOOL_MISMATCH / MAC_FAIL all deny.
const TICKET_TTL_MS = 300;
const _ticketKeys = new Map(); // agentId -> key
const _usedTickets = new Set();
function _ticketKey(agentId) {
  const id = String(agentId || 'anonymous');
  if (!_ticketKeys.has(id)) {
    if (!_master) _master = _masterKey();
    _ticketKeys.set(id, crypto.hkdfSync('sha256', _master, Buffer.from('kasbah-ticket-v1:' + id), Buffer.from('ticket'), 32));
  }
  return _ticketKeys.get(id);
}
function issueTicket(agentId = 'anonymous', tool = '', args = {}) {
  const id = String(agentId || 'anonymous');
  const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
  const tid = crypto.randomBytes(16);
  const now = Date.now();
  const exp = now + TICKET_TTL_MS;
  const th = crypto.createHash('sha256').update(String(tool) + '|' + argsStr).digest();
  const pre = Buffer.concat([tid, th, Buffer.from(String(now) + '|' + String(exp))]);
  const mac = crypto.createHmac('sha256', _ticketKey(id)).update(pre).digest();
  return { tid: tid.toString('hex'), toolHash: th.toString('hex'), issuedMs: now, expiresMs: exp, ttlMs: TICKET_TTL_MS, mac: mac.toString('hex'), agentId: id };
}
function verifyTicket(agentId = 'anonymous', ticket = {}, tool = '', args = {}) {
  const id = String(agentId || 'anonymous');
  if (!ticket || !ticket.tid || !ticket.mac) return { ok: false, reason: 'TICKET_MISSING' };
  if (_usedTickets.has(ticket.tid)) return { ok: false, reason: 'REPLAY' };
  if (Number(ticket.expiresMs) < Date.now()) return { ok: false, reason: 'EXPIRED' };
  const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
  const th = crypto.createHash('sha256').update(String(tool) + '|' + argsStr).digest('hex');
  if (th !== ticket.toolHash) return { ok: false, reason: 'TOOL_MISMATCH' };
  const pre = Buffer.concat([Buffer.from(ticket.tid, 'hex'), Buffer.from(ticket.toolHash, 'hex'), Buffer.from(String(ticket.issuedMs) + '|' + String(ticket.expiresMs))]);
  const mac = crypto.createHmac('sha256', _ticketKey(ticket.agentId || id)).update(pre).digest('hex');
  if (mac.length !== String(ticket.mac).length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(String(ticket.mac)))) return { ok: false, reason: 'MAC_FAIL' };
  if (String(ticket.agentId || id) !== id) return { ok: false, reason: 'CROSS_AGENT' };
  _usedTickets.add(ticket.tid);
  if (_usedTickets.size > 5000) { const it = _usedTickets.values(); for (let i = 0; i < 4000; i++) _usedTickets.delete(it.next().value); }
  return { ok: true };
}
// ---- Wearable (ring / band): away-from-computer Kasbah ----
// Design contract:
//  1) Aware of surroundings: the wearable pairs to the Stone and carries
//     the same sentinel-alert feed (mic/camera/silent-speech/voice-clone/
//     rppg) as haptic + glow, delivered over BLE — no phone screen needed.
//  2) Very private: all classification happens on-device (wearable MCU or
//     paired phone enclave). The relay is a dumb encrypted pipe: phone
//     forwards opaque sealed boxes, never sees content. No cloud, ever.
//     Away mode degrades gracefully: urgent alerts queue as sealed boxes
//     and deliver on reconnect; NOTHING is sent in cleartext.
// Away = computer BLE lost, wearable still near user. In away mode the
// wearable becomes the primary surface: it can deny (hold) and duress,
// but can NEVER approve destructive/exfil/kill — same rule as gestures.
const _wearables = new Map(); // agentId -> { wearableId, kind, pubkey, pairedAt, lastSeen }
const _awayQueue = new Map(); // agentId -> [ sealed alert boxes ]
function pairWearable(agentId = 'anonymous', body = {}) {
  const id = String(agentId || 'anonymous');
  const rec = {
    wearableId: String(body.wearableId || 'wear-' + crypto.randomBytes(4).toString('hex')),
    kind: /ring|band|fit|watch/i.test(String(body.kind || '')) ? String(body.kind) : 'ring',
    pubkey: body.pubkey || null, // wearable's public key for sealed boxes
    pairedAt: Date.now(), lastSeen: Date.now(),
  };
  _wearables.set(id, rec);
  _auditLog({ event: 'WEARABLE_PAIRED', agentId: id, stoneId: stoneIdFor(id), wearableId: rec.wearableId, kind: rec.kind });
  return { ok: true, ...rec, stoneId: stoneIdFor(id) };
}
function wearableFor(agentId) { return _wearables.get(String(agentId || 'anonymous')) || null; }
function awayMode(agentId = 'anonymous') {
  // Away = computer presence stale (>60 s) AND wearable recently seen.
  const id = String(agentId || 'anonymous');
  const comp = presenceFor(id);
  const w = _wearables.get(id);
  const compGone = Date.now() - (comp.updatedAt || 0) > 60000;
  const wearNear = w && Date.now() - w.lastSeen < 120000;
  const away = !!(compGone && wearNear);
  return { away, computerNear: !compGone, wearableNear: !!wearNear, wearable: w || null };
}
function wearableHeartbeat(agentId = 'anonymous', body = {}) {
  const id = String(agentId || 'anonymous');
  const w = _wearables.get(id);
  if (!w) return { ok: false, reason: 'no wearable paired' };
  w.lastSeen = Date.now();
  if (body.rssi !== undefined) w.rssi = Number(body.rssi);
  // Flush queued sealed boxes on reconnect.
  const q = _awayQueue.get(id) || [];
  _awayQueue.delete(id);
  return { ok: true, away: awayMode(id).away, flushed: q.length, boxes: q };
}
// Queue a sealed alert box for away delivery. The server never sees
// content: `sealed` is opaque bytes encrypted to the wearable pubkey
// by the detector. Server stores + forwards only.
function queueAwayAlert(agentId = 'anonymous', sealed = '', source = '') {
  const id = String(agentId || 'anonymous');
  if (!sealed) return { ok: false, reason: 'sealed box required (server never sees content)' };
  const q = _awayQueue.get(id) || [];
  if (q.length >= 50) q.shift();
  q.push({ sealed, source, queuedAt: Date.now() });
  _awayQueue.set(id, q);
  _auditLog({ event: 'AWAY_QUEUED', agentId: id, source, bytes: String(sealed).length });
  return { ok: true, queued: q.length };
}
// Sentinel alert → aura. Detection modules (mic/camera sentinels,
// biometric detectors, voice-privacy) push events here; the Stone
// surfaces them as ambient glow + haptic. Alert never auto-approves
// anything — it only lights the Stone and logs.
const ALERT_AURA = {
  'mic-unapproved': ['denied', 'red'],
  'mic-recording': ['awaiting-tap', 'pulse-amber'],
  'camera-unapproved': ['denied', 'red'],
  'camera-capture': ['awaiting-tap', 'pulse-amber'],
  'silent-speech-suspected': ['awaiting-tap', 'pulse-amber'],
  'voice-clone-suspected': ['denied', 'red'],
  'rppg-suspected': ['awaiting-tap', 'pulse-amber'],
  'neural-codec-suspected': ['awaiting-tap', 'pulse-amber'],
  'steganography-suspected': ['awaiting-tap', 'pulse-amber'],
  'all-clear': ['idle', 'soft-white'],
};
function sentinelAlert(agentId = 'anonymous', source = '', detail = {}) {
  const id = String(agentId || 'anonymous');
  const [glow, color] = ALERT_AURA[source] || ['awaiting-tap', 'pulse-amber'];
  setAura(id, glow, color);
  const row = _auditLog({ event: 'SENTINEL_ALERT', agentId: id, stoneId: stoneIdFor(id), source, glow, detail: detail && typeof detail === 'object' ? detail : { note: String(detail || '') } });
  return { ok: true, aura: _aura.get(id), audit: row };
}
function tapHistory(agentId = 'anonymous', limit = 20) {
  const id = String(agentId || 'anonymous');
  return _audit.filter((e) => e.agentId === id || e.actor === id).slice(-limit).reverse();
}
function pending() {
  return [..._pending.entries()].map(([id, p]) => ({
    id, action: p.gate.action, tool: p.gate.tool, S: p.gate.S, agentId: p.gate.agentId, stoneId: p.gate.stoneId,
    tier: p.gate.tier, tierReasons: p.gate.tierReasons, killSwitch: p.gate.killSwitch, gateReady: p.gate.gateReady,
    approverRequired: approverRequired(p.gate.agentId), challenge: p.challenge, argsPreview: p.argsPreview,
    ageMs: Date.now() - p.gate.createdAt, graceMs: p.gate.graceMs, expiresAt: p.gate.expiresAt,
  }));
}
function auditLog(limit = 100) { return _audit.slice(-limit).reverse(); }

module.exports = {
  TIER_ORDER, TIER_TAU, GRACE_MS,
  tierTau, fuse, certify, salience, assess, init,
  stoneSign, stoneVerify, canonicalGate, stoneIdFor, killSwitchGuard,
  startTap, requestTap, tap, deny, pending, auditLog, revokeStone, stoneStatus,
  setAura, auraFor, gesture, snoozed, presence, presenceFor, tapHistory, STONE_FUNCTIONS, sentinelAlert, ALERT_AURA,
  pairWearable, wearableFor, awayMode, wearableHeartbeat, queueAwayAlert,
  issueTicket, verifyTicket, TICKET_TTL_MS,
  setLockdown, lockdown, recentTap, verifyIndependent,
  provisionApprover, provisionCanonical, approverRequired, approverStatus, attestationMessage, graceFor,
  APPROVER_KINDS, DESKTOP_GRACE_MS, MAX_BAD_ATTESTATIONS, _resetApproversForTest,
  opCanonical, verifyOpProof,
};
