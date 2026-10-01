'use strict';

/**
 * Honeytokens — plant fake credentials. If they ever appear in clipboard
 * or scanned text, that's exfiltration / leak. Local only.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const DIR = path.join(os.homedir(), '.kasbah-privacy');
const FILE = path.join(DIR, 'honeytokens.json');

function ensure() { fs.mkdirSync(DIR, { recursive: true, mode: 0o700 }); }

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { return { tokens: [] }; }
}

function save(s) {
  ensure();
  fs.writeFileSync(FILE, JSON.stringify(s, null, 2), { mode: 0o600 });
  return s;
}

function _rand(n = 16) { return crypto.randomBytes(n).toString('hex'); }

function deploy(service = 'custom') {
  const templates = {
    aws: () => 'AKIA' + _rand(8).toUpperCase().slice(0, 16),
    github: () => 'ghp_' + _rand(20),
    slack: () => 'xoxb-' + _rand(12) + '-' + _rand(12),
    openai: () => 'sk-' + _rand(24),
    stripe: () => 'sk_live_' + _rand(16),
    custom: () => 'kasbah_ht_' + _rand(12),
  };
  const fn = templates[service] || templates.custom;
  const token = fn();
  const id = 'ht_' + _rand(6);
  const s = load();
  s.tokens.push({ id, token, service, deployedAt: new Date().toISOString(), hits: 0 });
  save(s);
  return { id, token, service };
}

function list() {
  return load().tokens
    .filter((t) => t.token && t.id)
    .map((t) => ({ ...t, tokenPreview: String(t.token).slice(0, 8) + '…' }));
}

function check(text) {
  const s = load();
  const hits = [];
  for (const t of s.tokens) {
    if (t.token && String(text || '').includes(t.token)) {
      t.hits = (t.hits || 0) + 1;
      hits.push({ id: t.id, service: t.service, tokenPreview: t.token.slice(0, 10) + '…' });
    }
  }
  if (hits.length) save(s);
  return { found: hits.length > 0, hits };
}

function remove(id) {
  const s = load();
  s.tokens = s.tokens.filter((t) => t.id !== id);
  save(s);
  return { ok: true };
}

module.exports = { deploy, list, check, remove };
