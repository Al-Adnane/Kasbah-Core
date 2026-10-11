'use strict';

/**
 * consent-approver.js — the desktop app as a human-bound approver.
 *
 * The engine's consent gate only approves a request when a registered approver
 * key has signed that request's exact challenge. This module is that approver
 * for people without a hardware Stone:
 *
 *   • An Ed25519 key is created on first run and kept in the main process
 *     (OS keychain via safeStorage when available, else a 0600 file). The
 *     renderer never sees it and there is no IPC call that signs.
 *   • The module polls the engine for pending requests and shows a NATIVE
 *     confirmation dialog. Only a click on "Allow" in that dialog produces a
 *     signature. A compromised page, or the agent itself, cannot click it.
 *   • What the dialog shows is parsed from the challenge that gets signed, not
 *     from separate fields, so what you see is what you sign.
 *   • The default and Escape/Enter action is Deny. Timeouts and errors deny.
 *   • Each signature carries a counter that is persisted BEFORE the signature
 *     leaves the process, so a crash can never lead to a counter being reused.
 *
 * All Electron and network access is injected, so the logic is unit-testable.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KIND = 'desktop';

function createApprover({ dir, safeStorage = null, request, showDialog, log = console, pollMs = 1500, now = () => Date.now() }) {
  if (!dir || typeof request !== 'function' || typeof showDialog !== 'function') throw new Error('consent-approver: dir, request and showDialog are required');
  const keyFile = path.join(dir, 'consent-approver-key.json');
  const counterFile = path.join(dir, 'consent-approver-counter.json');
  const state = { registered: false, keyId: null, error: null, decisions: [], pending: 0, lastPollOk: null };
  const seen = new Set();   // request ids already shown or skipped
  const queue = [];         // requests waiting for the dialog
  let busy = false, timer = null, keys = null;

  const ss = safeStorage && typeof safeStorage.isEncryptionAvailable === 'function' && safeStorage.isEncryptionAvailable() ? safeStorage : null;

  function writePrivate(file, body) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, body, { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  function loadKeys() {
    if (keys) return keys;
    let pkcs8 = null;
    try {
      const raw = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      if (raw.enc) { if (!ss) throw new Error('approver key is keychain-protected but the keychain is unavailable'); pkcs8 = Buffer.from(ss.decryptString(Buffer.from(raw.enc, 'base64')), 'base64'); }
      else if (raw.pkcs8) pkcs8 = Buffer.from(raw.pkcs8, 'base64');
    } catch (e) {
      if (e.code !== 'ENOENT') throw new Error('could not read the approver key: ' + e.message); // never silently mint a second identity
    }
    let privateKey;
    if (pkcs8) {
      privateKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    } else {
      privateKey = crypto.generateKeyPairSync('ed25519').privateKey;
      const b64 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
      writePrivate(keyFile, JSON.stringify(ss ? { enc: ss.encryptString(b64).toString('base64') } : { pkcs8: b64 }));
    }
    const pubkey = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64');
    const keyId = crypto.createHash('sha256').update(Buffer.from(pubkey, 'base64')).digest('hex').slice(0, 16);
    keys = { privateKey, pubkey, keyId };
    state.keyId = keyId;
    return keys;
  }

  /** Reserve the next counter value, durably, before it is used. */
  function nextCounter() {
    let last = 0;
    try { last = Number(JSON.parse(fs.readFileSync(counterFile, 'utf8')).counter) || 0; }
    catch (e) { if (e.code !== 'ENOENT') throw new Error('approver counter unreadable: ' + e.message); }
    // Time-based floor: even if the counter file is lost or restored from a
    // backup, the next value is still higher than anything used before.
    const next = Math.max(last + 1, now());
    writePrivate(counterFile, JSON.stringify({ counter: next }));
    return next;
  }

  async function register() {
    try {
      const k = loadKeys();
      const r = await request('POST', '/v1/consent/approver', { agentId: '*', kind: KIND, pubkey: k.pubkey });
      if (r && r.ok) { state.registered = true; state.error = null; return true; }
      state.registered = false;
      state.error = (r && (r.reason || r.error)) || 'engine did not accept the approver key';
      return false;
    } catch (e) { state.registered = false; state.error = e.message; return false; }
  }

  /** Parse and sanity-check a pending entry. Returns null when it must not be shown. */
  function describe(p) {
    if (!p || typeof p.challenge !== 'string' || !p.id) return null;
    let c;
    try { c = JSON.parse(p.challenge); } catch (_) { return null; }
    // The challenge is the source of truth. If the loose fields disagree with
    // it, something is wrong: do not show a dialog that could mislead.
    if (c.id !== p.id || c.v !== 2 || typeof c.nonce !== 'string' || typeof c.action !== 'string') return null;
    if (typeof c.expiresAt !== 'number' || c.expiresAt <= now()) return null;
    let args = null;
    if (typeof p.argsPreview === 'string' && crypto.createHash('sha256').update(p.argsPreview).digest('hex') === c.argsHash) args = p.argsPreview;
    return { id: c.id, action: c.action, tool: c.tool || '', agentId: String(c.agentId), tier: String(c.tier || ''), expiresAt: c.expiresAt, args, argsHash: String(c.argsHash || ''), advice: typeof c.advice === 'string' ? c.advice : '', reasons: Array.isArray(p.tierReasons) ? p.tierReasons : [] };
  }

  const clip = (s, n) => { const t = String(s).replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, ' '); return t.length > n ? t.slice(0, n) + '…' : t; };

  async function decide(p) {
    const d = describe(p);
    if (!d) return;
    const secs = Math.max(1, Math.round((d.expiresAt - now()) / 1000));
    const lines = [
      'What: ' + clip(d.action, 300),
      d.tool ? 'Tool: ' + clip(d.tool, 80) : null,
      'Asked by: ' + clip(d.agentId, 80),
      'Risk: ' + clip(d.tier || 'unknown', 40) + (d.reasons.length ? ' (' + clip(d.reasons.join(', '), 120) + ')' : ''),
      d.args != null ? 'Details: ' + clip(d.args, 400) : 'Details: too long to show in full (fingerprint ' + d.argsHash.slice(0, 16) + ')',
      d.advice ? clip(d.advice, 160) : null,
      '',
      'Expires in about ' + secs + ' seconds. If you did not expect this, choose Deny.',
    ].filter((x) => x !== null);
    let allow = false;
    try {
      const choice = await showDialog({
        title: 'Kasbah — approval needed',
        message: 'An AI helper is asking to do something that needs your approval.',
        detail: lines.join('\n'),
        buttons: ['Deny', 'Allow'], defaultId: 0, cancelId: 0,
      });
      allow = choice === 1;
    } catch (e) { log.warn('[approver] dialog failed, denying: ' + e.message); allow = false; }

    const record = (outcome, why) => {
      state.decisions.unshift({ at: new Date(now()).toISOString(), action: clip(d.action, 80), tool: d.tool, agentId: d.agentId, tier: d.tier, outcome, why: why || null });
      if (state.decisions.length > 20) state.decisions.length = 20;
    };

    if (!allow) {
      try { await request('POST', '/v1/consent/deny/' + encodeURIComponent(d.id), { agentId: d.agentId }); } catch (_) { /* expiry denies anyway */ }
      record('denied');
      return;
    }
    if (d.expiresAt <= now()) { record('expired'); return; }
    try {
      const k = loadKeys();
      const counter = nextCounter();
      const signature = crypto.sign(null, Buffer.from(p.challenge + '|' + String(counter)), k.privateKey).toString('base64url');
      const r = await request('POST', '/v1/consent/tap/' + encodeURIComponent(d.id), { approve: true, agentId: d.agentId, attestation: { signer: KIND, keyId: k.keyId, counter, signature } });
      if (r && r.A === 1) record('allowed');
      else record('not approved', (r && (r.reason || r.error || r.status)) || 'the engine refused');
    } catch (e) { record('not approved', e.message); }
  }

  async function drain() {
    if (busy) return;
    busy = true;
    try { while (queue.length) await decide(queue.shift()); }
    finally { busy = false; }
  }

  async function poll() {
    try {
      if (!state.registered && !(await register())) { state.lastPollOk = false; return; }
      const r = await request('GET', '/v1/consent/pending');
      const list = (r && Array.isArray(r.pending)) ? r.pending : [];
      state.lastPollOk = !!(r && Array.isArray(r.pending));
      state.pending = list.length;
      for (const p of list) {
        if (!p || seen.has(p.id)) continue;
        seen.add(p.id);
        if (p.approverRequired && p.gateReady !== false) queue.push(p);
      }
      if (seen.size > 2000) { const keep = new Set(list.map((p) => p.id)); for (const id of seen) if (!keep.has(id)) seen.delete(id); }
      drain();
    } catch (e) { state.lastPollOk = false; state.error = e.message; }
  }

  return {
    start() { if (!timer) { poll(); timer = setInterval(poll, pollMs); if (timer.unref) timer.unref(); } },
    stop() { if (timer) { clearInterval(timer); timer = null; } },
    poll, register, describe,
    status() { return { registered: state.registered, keyId: state.keyId, keychain: !!ss, error: state.error, pending: state.pending, engineReachable: state.lastPollOk, decisions: state.decisions.slice(0, 10) }; },
    /** Sign a privileged gate operation (for example lifting lockdown) after its own native confirmation. */
    async signOp(op, confirm) {
      const choice = await showDialog({ title: 'Kasbah — confirm', message: confirm.message, detail: confirm.detail, buttons: ['Cancel', confirm.button || 'Confirm'], defaultId: 0, cancelId: 0 });
      if (choice !== 1) return null;
      const k = loadKeys(); const ts = now(); const counter = nextCounter();
      const canon = JSON.stringify({ counter, op: String(op), ts }); // sorted keys, matches the gate's canonical form
      return { keyId: k.keyId, ts, counter, signature: crypto.sign(null, Buffer.from(canon), k.privateKey).toString('base64url') };
    },
    _keys: loadKeys, _nextCounter: nextCounter,
  };
}

module.exports = { createApprover, KIND };
