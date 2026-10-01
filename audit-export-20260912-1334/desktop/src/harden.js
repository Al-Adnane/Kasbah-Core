'use strict';

/**
 * 7-day harden path + commitment receipt.
 * Pattern from Pharma5 SDG workshop: signed commitment with a date.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const STATE = path.join(DIR, 'harden.json');
const KEY_FILE = path.join(DIR, 'harden-key.bin');

// Per-install random HMAC key, generated once and kept on disk (0600) — a
// hardcoded key baked into shipped source would make the "signed"
// commitment forgeable by anyone who read this file, proving nothing.
function hmacKey() {
  try { return fs.readFileSync(KEY_FILE); } catch (_) {}
  const key = crypto.randomBytes(32);
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(KEY_FILE, key, { mode: 0o600 });
  } catch (_) {}
  return key;
}

const STEPS = [
  { id: 'vpn', title: 'Connect VPN (Singapore)', hint: 'VPN → Connect' },
  { id: 'helper', title: 'Install passwordless helper', hint: 'VPN → Install helper' },
  { id: 'vault', title: 'Unlock vault + add 1 password', hint: 'Vault' },
  { id: 'clip', title: 'Enable clipboard watch', hint: 'Home → Safe mode' },
  { id: 'honey', title: 'Deploy 1 honeytoken', hint: 'Honeytokens → Deploy AWS' },
  { id: 'agent', title: 'Require VPN for agents', hint: 'Agent Guard' },
  { id: 'proof', title: 'Mint a protection proof', hint: 'Protection Proof' },
];

function load() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); }
  catch {
    return { startedAt: null, done: [], commitment: null };
  }
}

function save(s) {
  try {
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(STATE, JSON.stringify(s, null, 2), { mode: 0o600 });
  } catch (_) {}
  return s;
}

function status() {
  const s = load();
  const done = new Set(s.done || []);
  const items = STEPS.map((st) => ({ ...st, done: done.has(st.id) }));
  const complete = items.every((i) => i.done);
  return {
    startedAt: s.startedAt,
    items,
    doneCount: items.filter((i) => i.done).length,
    total: items.length,
    complete,
    commitment: s.commitment,
    deadline: s.startedAt
      ? new Date(new Date(s.startedAt).getTime() + 7 * 24 * 3600 * 1000).toISOString()
      : null,
  };
}

function start() {
  const s = load();
  if (!s.startedAt) s.startedAt = new Date().toISOString();
  save(s);
  return status();
}

function completeStep(id) {
  const s = load();
  if (!STEPS.some((x) => x.id === id)) throw new Error('unknown step');
  if (!s.done) s.done = [];
  if (!s.done.includes(id)) s.done.push(id);
  save(s);
  return status();
}

function commit(note = 'I will finish hardening this Mac within 7 days.') {
  const s = load();
  const st = status();
  const payload = {
    kind: 'harden-commitment',
    note,
    startedAt: s.startedAt || new Date().toISOString(),
    deadline: st.deadline,
    stepsTotal: STEPS.length,
    ts: Date.now(),
  };
  const sig = crypto.createHmac('sha256', hmacKey())
    .update(JSON.stringify(payload))
    .digest('hex');
  s.commitment = { ...payload, sig };
  save(s);
  return { ok: true, commitment: s.commitment };
}

function reset() {
  save({ startedAt: null, done: [], commitment: null });
  return status();
}

module.exports = { status, start, completeStep, commit, reset, STEPS };
